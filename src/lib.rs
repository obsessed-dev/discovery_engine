use pnet::{
    datalink::{self, NetworkInterface},
    ipnetwork::IpNetwork,
    packet::{
        MutablePacket, Packet,
        arp::{ArpHardwareTypes, ArpOperation, ArpOperations, ArpPacket, MutableArpPacket},
        ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    },
    util::MacAddr,
};
use std::{error::Error, io, net::Ipv4Addr, time::Duration};

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

pub fn arp_probe(
    scanned: &ScannedInterface,
    src_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Result<(Ipv4Addr, MacAddr), Box<dyn Error>> {
    let mut buf = [0u8; 42];

    {
        let mut eth =
            MutableEthernetPacket::new(&mut buf).ok_or("failed to create ethernet packet")?;
        eth.set_destination(MacAddr::broadcast());
        eth.set_source(scanned.mac);
        eth.set_ethertype(EtherTypes::Arp);

        let mut arp =
            MutableArpPacket::new(eth.payload_mut()).ok_or("failed to create arp packet")?;
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(scanned.mac);
        arp.set_sender_proto_addr(src_ip);
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(target_ip);
    }

    let config = datalink::Config {
        read_timeout: Some(Duration::from_secs(3)),
        ..Default::default()
    };

    let (mut tx, mut rx) = match datalink::channel(&scanned.iface, config) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err("unexpected channel type".into()),
        Err(e) => return Err(e.into()),
    };

    tx.send_to(&buf, None).ok_or("send_to returned None")??;

    loop {
        let frame = match rx.next() {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                return Err(format!("no ARP reply from {} within 3s", target_ip).into());
            }
            Err(e) => return Err(e.into()),
        };

        let eth = match EthernetPacket::new(frame) {
            Some(p) => p,
            None => continue,
        };
        if eth.get_ethertype() != EtherTypes::Arp {
            continue;
        }

        let arp = match ArpPacket::new(eth.payload()) {
            Some(p) => p,
            None => continue,
        };
        if arp.get_target_proto_addr() != src_ip {
            continue;
        }
        return Ok((arp.get_sender_proto_addr(), arp.get_sender_hw_addr()));
    }
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
