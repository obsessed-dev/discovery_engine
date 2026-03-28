use comfy_table::{Cell, Color, Table};
use discovery::{DiscoveryMethod, icmp_sweep, merge_results, scan_interface, sweep};
use std::{env, error::Error, net::IpAddr};

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let args: Vec<_> = env::args().skip(1).collect();

    if args.is_empty() {
        return Err("Usage: sudo ./discovery <INTERFACE> [INTERFACE...] (e.g. eth0)".into());
    }

    for name in &args {
        match scan_interface(name) {
            Ok(iface) => {
                println!("[*] Interface: {}", iface.name);
                for net in &iface.networks {
                    println!(
                        "[*] Network: {}/{}, Hosts: {}",
                        net.network.ip(),
                        net.network.prefix(),
                        net.host_count
                    );
                    let IpAddr::V4(src_ip) = net.network.ip() else {
                        unreachable!()
                    };

                    let arp_records = match sweep(&iface, src_ip, net) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("[-] ARP sweep failed: {}", e);
                            vec![]
                        }
                    };

                    let icmp_records = match icmp_sweep(&iface, src_ip, net) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("[-] ICMP sweep failed: {}", e);
                            vec![]
                        }
                    };

                    let records = merge_results(arp_records, icmp_records);

                    println!("[*] Sweep complete - {} hosts discovered", records.len());

                    let mut table = Table::new();
                    table.set_header(vec![
                        Cell::new("IP").fg(Color::Cyan),
                        Cell::new("MAC").fg(Color::Cyan),
                        Cell::new("Vendor").fg(Color::Cyan),
                        Cell::new("Latency").fg(Color::Cyan),
                        Cell::new("Method").fg(Color::Cyan),
                    ]);

                    for r in &records {
                        let mac_str = r.mac.map_or("\u{2014}".to_string(), |m| m.to_string());
                        let vendor_str = r.vendor.unwrap_or("\u{2014}");
                        let latency_str = r.latency.map_or("\u{2014}".to_string(), |d| {
                            format!("{:.1}ms", d.as_secs_f64() * 1000.0)
                        });
                        let (method_str, method_color) = match r.method {
                            DiscoveryMethod::Arp => ("ARP", Color::Green),
                            DiscoveryMethod::Icmp => ("ICMP", Color::Magenta),
                            DiscoveryMethod::Both => ("Both", Color::Yellow),
                        };
                        table.add_row(vec![
                            Cell::new(r.ip),
                            Cell::new(mac_str),
                            Cell::new(vendor_str).fg(Color::Yellow),
                            Cell::new(latency_str),
                            Cell::new(method_str).fg(method_color),
                        ]);
                    }
                    println!("{}", table);
                }
            }
            Err(e) => eprintln!("Error on '{}': {}", name, e),
        }
    }
    Ok(())
}
