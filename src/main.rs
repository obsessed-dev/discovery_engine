use comfy_table::{Cell, Color, Table};
use discovery::{scan_interface, sweep};
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
                    match sweep(&iface, src_ip, net) {
                        Ok(records) => {
                            println!("[*] Sweep complete - {} hosts discovered", records.len());
                            let mut table = Table::new();
                            table.set_header(vec![
                                Cell::new("IP").fg(Color::Cyan),
                                Cell::new("MAC").fg(Color::Cyan),
                                Cell::new("Vendor").fg(Color::Cyan),
                                Cell::new("Method").fg(Color::Cyan),
                            ]);
                            for r in &records {
                                table.add_row(vec![
                                    Cell::new(r.ip),
                                    Cell::new(r.mac),
                                    Cell::new(r.vendor.unwrap_or("Unknown")).fg(Color::Yellow),
                                    Cell::new("ARP").fg(Color::Green),
                                ]);
                            }
                            println!("{}", table);
                        }
                        Err(e) => eprintln!("[-] Sweep failed: {}", e),
                    }
                }
            }
            Err(e) => eprintln!("Error on '{}': {}", name, e),
        }
    }
    Ok(())
}
