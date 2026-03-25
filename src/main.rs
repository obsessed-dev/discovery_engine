use discovery::{arp_probe, scan_interface};
use std::{env, error::Error, net::IpAddr};
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args().skip(1).collect();

    if args.is_empty() {
        return Err("Usage: sudo ./discovery <INTERFACE> [INTERFACE...] (e.g. eth0)".into());
    }

    for name in &args {
        match scan_interface(name) {
            Ok(iface) => {
                println!("[*] Interface: {}", iface.name);
                'networks: for net in &iface.networks {
                    let IpAddr::V4(src_ip) = net.network.ip() else {
                        unreachable!()
                    };
                    for host in net.hosts() {
                        let IpAddr::V4(target_ip) = host else {
                            unreachable!()
                        };
                        match arp_probe(&iface, src_ip, target_ip) {
                            Ok((ip, mac)) => println!("[*] {} is at {}", ip, mac),
                            Err(e) => eprintln!("[-] {}", e),
                        }
                        break 'networks;
                    }
                }
            }
            Err(e) => eprintln!("Error on '{}': {}", name, e),
        }
    }
    Ok(())
}
