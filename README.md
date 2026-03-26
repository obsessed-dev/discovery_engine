# Discovery Engine

A network discovery tool written in Rust. Performs ARP subnet sweeps to identify live hosts on a network, reporting their IP address, MAC address, and hardware vendor.

## How It Works

Given a network interface, the tool:

1. Scans the interface for IPv4 networks
2. Opens a raw datalink channel on the interface
3. Spawns a TX thread that fires ARP requests at every host in the subnet (1ms between sends)
4. Spawns an RX thread that listens for ARP replies within a 3 second window
5. Looks up the MAC vendor OUI for each discovered host
6. Prints results in a formatted table

TX and RX run concurrently across two threads. Results are collected into a shared `Arc<Mutex<Vec<HostRecord>>>` and printed after both threads complete.

## Usage

Requires root privileges to open a raw datalink channel.

```
sudo ./discovery <INTERFACE> [INTERFACE...]
```

Example:

```
sudo ./discovery eth0
```

Output:

```
[*] Interface: eth0
[*] Network: 192.168.1.1/24, Hosts: 254
[*] Sweep complete - 3 hosts discovered
+--------------+-------------------+---------------+--------+
| IP           | MAC               | Vendor        | Method |
+=====================================================+
| 192.168.1.1  | e4:55:a8:92:44:eb | Cisco Meraki  | ARP    |
| 192.168.1.10 | dc:a6:32:4f:1a:bc | Raspberry Pi  | ARP    |
| 192.168.1.42 | a4:c3:f0:88:21:dd | Apple         | ARP    |
+--------------+-------------------+---------------+--------+
```

## Building

```
cargo build --release
```

Binary will be at `target/release/discovery`.

## Dependencies

- [pnet](https://github.com/libpnet/libpnet) — raw packet construction and datalink channel
- [mac-vendor-lookup](../vendor) — OUI to vendor name lookup (local crate)
- [comfy-table](https://github.com/nukesor/comfy-table) — terminal table output

## Testing

A Docker-based test environment is provided for local testing without access to a physical LAN.

**Setup** — creates a `192.168.99.0/24` bridge network with two Alpine containers as targets:

```
./tests/docker_setup.sh
```

**Teardown:**

```
./tests/docker_teardown.sh
```

The setup script prints the bridge interface name to pass directly to `discovery`.

## Scope

ARP sweeps are effective and low-noise on /24 networks. Sweeping /16 or larger is not recommended — it generates excessive traffic and takes impractical amounts of time. The tool is intended for use on networks you own or have explicit authorization to scan.
