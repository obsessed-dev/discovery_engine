use log::{debug, info, warn};
use mac_vendor_lookup::lookup_mac_vendor;
use pnet::{
    datalink::{self, DataLinkSender, NetworkInterface},
    ipnetwork::IpNetwork,
    packet::{
        MutablePacket, Packet,
        arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
        ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
        icmp::{IcmpCode, IcmpPacket, IcmpTypes, checksum, echo_request::MutableEchoRequestPacket},
        ip::IpNextHeaderProtocols,
        ipv4::{Ipv4Packet, MutableIpv4Packet, checksum as ipv4_checksum},
    },
    util::MacAddr,
};
use std::{
    collections::HashMap,
    error::Error,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
    thread::{self, sleep},
    time::{Duration, Instant},
};

#[derive(Debug, PartialEq)]
pub enum DiscoveryMethod {
    Arp,
    Icmp,
    Both,
}

#[derive(Debug, PartialEq)]
pub struct HostRecord {
    pub ip: Ipv4Addr,
    pub mac: Option<MacAddr>,
    pub vendor: Option<&'static str>,
    pub latency: Option<Duration>,
    pub method: DiscoveryMethod,
}

pub struct InterfaceNetwork {
    pub network: IpNetwork,
    pub host_count: u64,
}

impl InterfaceNetwork {
    pub fn hosts(&self) -> impl Iterator<Item = std::net::IpAddr> + '_ {
        let skip = if self.network.prefix() < 31 { 1 } else { 0 };
        self.network
            .iter()
            .skip(skip)
            .take(self.host_count as usize)
    }
}

pub struct ScannedInterface {
    pub name: String,
    pub networks: Vec<InterfaceNetwork>,
    pub mac: MacAddr,
    iface: NetworkInterface,
}

fn send_arp_request(
    tx: &mut dyn DataLinkSender,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Result<(), Box<dyn Error>> {
    let mut buf = [0u8; 42];

    {
        let mut eth =
            MutableEthernetPacket::new(&mut buf).ok_or("failed to create ethernet packet")?;
        eth.set_destination(MacAddr::broadcast());
        eth.set_source(src_mac);
        eth.set_ethertype(EtherTypes::Arp);

        let mut arp =
            MutableArpPacket::new(eth.payload_mut()).ok_or("failed to create arp packet")?;
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(src_mac);
        arp.set_sender_proto_addr(src_ip);
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(target_ip);
    }
    tx.send_to(&buf, None).ok_or("send_to returned None")??;

    Ok(())
}

fn parse_arp_reply(frame: &[u8], src_ip: Ipv4Addr) -> Option<HostRecord> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(eth.payload())?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }
    if arp.get_target_proto_addr() != src_ip {
        return None;
    }
    let ip = arp.get_sender_proto_addr();
    let mac = arp.get_sender_hw_addr();
    let vendor = lookup_mac_vendor(&mac.to_string());
    Some(HostRecord {
        ip,
        mac: Some(mac),
        vendor,
        latency: None,
        method: DiscoveryMethod::Arp,
    })
}

pub fn sweep(
    scanned: &ScannedInterface,
    src_ip: Ipv4Addr,
    net: &InterfaceNetwork,
) -> Result<Vec<HostRecord>, Box<dyn Error>> {
    let config = datalink::Config {
        read_timeout: Some(Duration::from_millis(200)),
        ..Default::default()
    };
    let (mut tx, mut rx) = match datalink::channel(&scanned.iface, config) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err("unexpected channel type".into()),
        Err(e) => return Err(e.into()),
    };

    let hosts: Vec<Ipv4Addr> = net
        .hosts()
        .filter_map(|ip| {
            if let IpAddr::V4(ip) = ip {
                Some(ip)
            } else {
                None
            }
        })
        .collect();

    let results: Arc<Mutex<Vec<HostRecord>>> = Arc::new(Mutex::new(Vec::new()));

    let src_mac = scanned.mac;

    let tx_handle = thread::spawn(move || {
        for target_ip in hosts {
            let _ = send_arp_request(&mut *tx, src_mac, src_ip, target_ip);
            debug!("ARP -> {}", target_ip);
            sleep(Duration::from_millis(1));
        }
    });

    let results_rx = Arc::clone(&results);
    let deadline = Instant::now() + Duration::from_secs(3);

    let rx_handle =
        thread::spawn(move || {
            while Instant::now() < deadline {
                match rx.next() {
                    Ok(frame) => {
                        if let Some(record) = parse_arp_reply(frame, src_ip) {
                            debug!("ARP <- {} MAC {}", record.ip, record.mac.unwrap());
                            results_rx.lock().unwrap_or_else(|e| {
                            warn!("ARP results mutex was poisoned - recovering partial results");
                            e.into_inner()
                        }).push(record);
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::TimedOut => continue,
                    Err(_) => break,
                }
            }
        });

    let _ = tx_handle.join();
    let _ = rx_handle.join();

    Ok(Arc::try_unwrap(results)
        .expect("results Arc still has multiple owners after threads joined - this is a bug")
        .into_inner()
        .expect("results Mutex poisoned after threads joined - this is a bug"))
}

fn send_icmp_request(
    tx: &mut dyn DataLinkSender,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    seq: u16,
) -> Result<(), Box<dyn Error>> {
    let mut buf = [0u8; 42];

    {
        let mut eth =
            MutableEthernetPacket::new(&mut buf).ok_or("failed to create ethernet packet")?;
        eth.set_destination(MacAddr::broadcast());
        eth.set_source(src_mac);
        eth.set_ethertype(EtherTypes::Ipv4);
    }

    {
        let mut ipv4 =
            MutableIpv4Packet::new(&mut buf[14..]).ok_or("failed to create ipv4 packet")?;
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(28);
        ipv4.set_ttl(64);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ipv4.set_source(src_ip);
        ipv4.set_destination(target_ip);
    }

    {
        let mut echo =
            MutableEchoRequestPacket::new(&mut buf[34..]).ok_or("failed to create icmp packet")?;
        echo.set_icmp_type(IcmpTypes::EchoRequest);
        echo.set_icmp_code(IcmpCode(0));
        echo.set_identifier(0);
        echo.set_sequence_number(seq);
        let ck = checksum(
            &IcmpPacket::new(echo.packet()).ok_or("failed to view icmp packet for checksum")?,
        );
        echo.set_checksum(ck);
    }

    {
        let mut ipv4 = MutableIpv4Packet::new(&mut buf[14..])
            .ok_or("failed to re-open ipv4 packet for checksum")?;
        let ck = ipv4_checksum(&ipv4.to_immutable());
        ipv4.set_checksum(ck);
    }

    tx.send_to(&buf, None).ok_or("send_to returned None")??;

    Ok(())
}

fn parse_icmp_reply(frame: &[u8], src_ip: Ipv4Addr) -> Option<Ipv4Addr> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }
    let ipv4 = Ipv4Packet::new(eth.payload())?;
    if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
        return None;
    }
    if ipv4.get_destination() != src_ip {
        return None;
    }
    let icmp = IcmpPacket::new(ipv4.payload())?;
    if icmp.get_icmp_type() != IcmpTypes::EchoReply {
        return None;
    }
    Some(ipv4.get_source())
}

pub fn icmp_sweep(
    scanned: &ScannedInterface,
    src_ip: Ipv4Addr,
    net: &InterfaceNetwork,
) -> Result<Vec<HostRecord>, Box<dyn Error>> {
    let config = datalink::Config {
        read_timeout: Some(Duration::from_millis(200)),
        ..Default::default()
    };
    let (mut tx, mut rx) = match datalink::channel(&scanned.iface, config) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err("unexpected channel type".into()),
        Err(e) => return Err(e.into()),
    };

    let hosts: Vec<Ipv4Addr> = net
        .hosts()
        .filter_map(|ip| {
            if let IpAddr::V4(v4) = ip {
                Some(v4)
            } else {
                None
            }
        })
        .collect();

    let send_times: Arc<Mutex<HashMap<Ipv4Addr, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let send_times_tx = Arc::clone(&send_times);
    let src_mac = scanned.mac;

    let tx_handle = thread::spawn(move || {
        for (seq, target_ip) in hosts.iter().enumerate() {
            send_times_tx
                .lock()
                .unwrap_or_else(|e| {
                    warn!("ICMP send_times mutex was poisoned in tx thread");
                    e.into_inner()
                })
                .insert(*target_ip, Instant::now());
            let _ = send_icmp_request(&mut *tx, src_mac, src_ip, *target_ip, seq as u16);
            debug!("ICMP -> {} seq {}", target_ip, seq);
            sleep(Duration::from_millis(1));
        }
    });

    let results: Arc<Mutex<Vec<HostRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let results_rx = Arc::clone(&results);
    let send_times_rx = Arc::clone(&send_times);
    let deadline = Instant::now() + Duration::from_secs(3);

    let rx_handle =
        thread::spawn(move || {
            while Instant::now() < deadline {
                match rx.next() {
                    Ok(frame) => {
                        if let Some(ip) = parse_icmp_reply(frame, src_ip) {
                            let latency = send_times_rx
                                .lock()
                                .unwrap_or_else(|e| {
                                    warn!("ICMP send_times mutex was poisoned in rx thread");
                                    e.into_inner()
                                })
                                .get(&ip)
                                .map(|t| t.elapsed());
                            debug!("ICMP <- {} latency {:?}", ip, latency);
                            results_rx.lock().unwrap_or_else(|e| {
                            warn!("ICMP results mutex was poisoned - recovering partial results");
                            e.into_inner()
                        }).push(HostRecord {
                            ip,
                            mac: None,
                            vendor: None,
                            latency,
                            method: DiscoveryMethod::Icmp,
                        });
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::TimedOut => continue,
                    Err(_) => break,
                }
            }
        });

    let _ = tx_handle.join();
    let _ = rx_handle.join();

    Ok(Arc::try_unwrap(results)
        .expect("results Arc still has multiple owners after threads joined - this is a bug")
        .into_inner()
        .expect("results Mutex poisoned after threads joined - this is a bug"))
}

pub fn merge_results(arp: Vec<HostRecord>, icmp: Vec<HostRecord>) -> Vec<HostRecord> {
    let arp_count = arp.len();
    let icmp_count = icmp.len();

    let mut map: HashMap<Ipv4Addr, HostRecord> = HashMap::new();

    for record in icmp {
        map.insert(record.ip, record);
    }

    for record in arp {
        map.entry(record.ip)
            .and_modify(|existing| {
                existing.mac = record.mac;
                existing.vendor = record.vendor;
                existing.method = DiscoveryMethod::Both;
            })
            .or_insert(record);
    }
    let mut results: Vec<HostRecord> = map.into_values().collect();
    results.sort_by_key(|r| r.ip);
    debug!(
        "{} ARP + {} ICMP -> {} unique hosts",
        arp_count,
        icmp_count,
        results.len()
    );
    results
}

pub fn scan_interface(name: &str) -> Result<ScannedInterface, Box<dyn Error>> {
    let all_ifaces = datalink::interfaces();

    let iface = all_ifaces.iter().find(|i| i.name == name).ok_or_else(|| {
        let names: Vec<_> = all_ifaces.iter().map(|i| i.name.as_str()).collect();
        format!(
            "interface '{}' not found. Available: {}",
            name,
            names.join(", ")
        )
    })?;

    let networks: Vec<InterfaceNetwork> = iface
        .ips
        .iter()
        .filter_map(|ip| match ip {
            IpNetwork::V4(_) => {
                let cidr = ip.prefix();
                let host_count = match cidr {
                    32 => 1,
                    31 => 2,
                    _ => 2u64.pow(32 - cidr as u32) - 2,
                };
                Some(InterfaceNetwork {
                    network: *ip,
                    host_count,
                })
            }
            _ => None,
        })
        .collect();

    if networks.is_empty() {
        return Err(format!("interface '{}' has no IPv4 addresses", name).into());
    }

    let mac = iface
        .mac
        .ok_or_else(|| format!("interface '{}' has no mac address", iface.name))?;

    info!(
        "Interface '{}' (MAC: {}) - {} network(s)",
        name,
        mac,
        networks.len()
    );
    for net in &networks {
        debug!(
            "    {}/{} - {} hosts",
            net.network.ip(),
            net.network.prefix(),
            net.host_count
        );
    }

    Ok(ScannedInterface {
        name: name.to_string(),
        networks,
        mac,
        iface: iface.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::ipnetwork::IpNetwork;
    use std::{net::Ipv4Addr, str::FromStr, time::Duration};

    fn arp_record(ip: Ipv4Addr) -> HostRecord {
        HostRecord {
            ip,
            mac: Some(MacAddr::new(0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33)),
            vendor: Some("TestVendor"),
            latency: None,
            method: DiscoveryMethod::Arp,
        }
    }

    fn icmp_record(ip: Ipv4Addr) -> HostRecord {
        HostRecord {
            ip,
            mac: None,
            vendor: None,
            latency: Some(Duration::from_millis(5)),
            method: DiscoveryMethod::Icmp,
        }
    }

    #[test]
    fn icmp_only_has_no_mac() {
        let result = merge_results(vec![], vec![icmp_record(Ipv4Addr::new(192, 168, 1, 1))]);
        assert_eq!(result.len(), 1);
        assert!(result[0].mac.is_none());
        assert_eq!(result[0].method, DiscoveryMethod::Icmp);
    }

    #[test]
    fn arp_only_has_mac() {
        let result = merge_results(vec![arp_record(Ipv4Addr::new(192, 168, 1, 1))], vec![]);
        assert_eq!(result.len(), 1);
        assert!(result[0].mac.is_some());
        assert_eq!(result[0].method, DiscoveryMethod::Arp);
    }

    #[test]
    fn same_ip_merges_to_both() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let result = merge_results(vec![arp_record(ip)], vec![icmp_record(ip)]);
        assert_eq!(result.len(), 1);
        assert!(result[0].mac.is_some());
        assert_eq!(result[0].method, DiscoveryMethod::Both);
    }

    #[test]
    fn merged_host_preserves_icmp_latency() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let result = merge_results(vec![arp_record(ip)], vec![icmp_record(ip)]);
        assert_eq!(result[0].latency, Some(Duration::from_millis(5)));
    }

    #[test]
    fn no_duplicates_ips_in_output() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let result = merge_results(vec![arp_record(ip)], vec![icmp_record(ip)]);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn output_is_sorted_by_ip() {
        let arp = vec![
            arp_record(Ipv4Addr::new(192, 168, 1, 3)),
            arp_record(Ipv4Addr::new(192, 168, 1, 1)),
        ];
        let result = merge_results(arp, vec![]);
        assert_eq!(result[0].ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(result[1].ip, Ipv4Addr::new(192, 168, 1, 3));
    }

    fn make_net(cidr: &str) -> InterfaceNetwork {
        let network = IpNetwork::from_str(cidr).unwrap();
        let prefix = network.prefix();
        let host_count = match prefix {
            32 => 1,
            31 => 2,
            _ => 2u64.pow(32 - prefix as u32) - 2,
        };
        InterfaceNetwork {
            network,
            host_count,
        }
    }

    #[test]
    fn slash24_skips_network_address() {
        let net = make_net("192.168.1.0/24");
        let hosts: Vec<_> = net.hosts().collect();
        assert!(!hosts.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0))));
        assert_eq!(hosts[0], IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn slash31_has_2_hosts() {
        let net = make_net("10.0.0.0/31");
        assert_eq!(net.host_count, 2);
        let hosts: Vec<_> = net.hosts().collect();
        assert_eq!(hosts.len(), 2);
    }

    #[test]
    fn slash32_has_1_host() {
        let net = make_net("10.0.0.1/32");
        assert_eq!(net.host_count, 1);
        let hosts: Vec<_> = net.hosts().collect();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0], IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
    }
}
