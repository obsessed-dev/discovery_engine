use mac_vendor_lookup::lookup_mac_vendor;
use pnet::{
    datalink::{self, DataLinkSender, NetworkInterface},
    ipnetwork::IpNetwork,
    packet::{
        MutablePacket, Packet,
        arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
        ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    },
    util::MacAddr,
};
use std::{
    error::Error,
    io::{self, ErrorKind},
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
    thread::{self, sleep},
    time::{Duration, Instant},
};

#[derive(Debug)]
pub enum DiscoveryMethod {
    Arp,
}

#[derive(Debug)]
pub struct HostRecord {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
    pub vendor: Option<&'static str>,
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
        mac,
        vendor,
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
            sleep(Duration::from_millis(1));
        }
    });

    let results_rx = Arc::clone(&results);
    let deadline = Instant::now() + Duration::from_secs(3);

    let rx_handle = thread::spawn(move || {
        while Instant::now() < deadline {
            match rx.next() {
                Ok(frame) => {
                    if let Some(record) = parse_arp_reply(frame, src_ip) {
                        results_rx.lock().unwrap().push(record);
                    }
                }
                Err(e) if e.kind() == ErrorKind::TimedOut => continue,
                Err(_) => break,
            }
        }
    });

    let _ = tx_handle.join();
    let _ = rx_handle.join();

    Ok(Arc::try_unwrap(results).unwrap().into_inner().unwrap())
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

    Ok(ScannedInterface {
        name: name.to_string(),
        networks,
        mac,
        iface: iface.clone(),
    })
}
