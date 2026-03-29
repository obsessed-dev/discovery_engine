# Discovery Engine

A network discovery tool written in Rust. Performs ARP and ICMP sweeps to identify live hosts on a network, reporting their IP address, MAC address, hardware vendor, round-trip latency, and discovery method.

## System Dependencies

Requires `libpcap-dev` for raw packet I/O:

```bash
sudo apt install libpcap-dev
```

## How It Works

Given a network interface, the tool:

1. Scans the interface for IPv4 networks
2. **ARP sweep** — opens a raw datalink channel, spawns concurrent TX/RX threads, fires ARP requests at every host in the subnet and collects replies within a 3 second window
3. **ICMP sweep** — fires ICMP echo requests at every host, records round-trip latency per reply
4. **Merge** — deduplicates results by IP, marks hosts seen by both methods, preserves ICMP latency
5. Looks up the MAC vendor OUI for each discovered host
6. Prints results in a formatted table

## Usage

Requires root privileges to open a raw datalink channel.

```bash
sudo ./discovery <INTERFACE> [INTERFACE...]
```

Example:

```bash
sudo ./discovery eth0
```

Output:

```
[*] Interface: eth0
[*] Network: 192.168.1.0/24, Hosts: 254
[*] Sweep complete - 3 hosts discovered
+--------------+-------------------+--------------+---------+--------+
| IP           | MAC               | Vendor       | Latency | Method |
+==================================================================+
| 192.168.1.1  | e4:55:a8:92:44:eb | Cisco Meraki | 1.2ms   | Both   |
| 192.168.1.10 | dc:a6:32:4f:1a:bc | Raspberry Pi | 0.8ms   | Both   |
| 192.168.1.42 | a4:c3:f0:88:21:dd | Apple        | —       | ARP    |
+--------------+-------------------+--------------+---------+--------+
```

## Building

```bash
cargo build --release
```

Binary will be at `target/release/discovery`.

## Logging

Runtime verbosity is controlled via `RUST_LOG`. The variable must be set after `sudo` so it reaches the process:

```bash
# Interface and network summary only
sudo RUST_LOG=info ./discovery eth0

# Every packet sent and received
sudo RUST_LOG=debug ./discovery eth0

# Silence everything except mutex fault warnings
sudo RUST_LOG=warn ./discovery eth0
```

## Testing

### Unit Tests

Pure logic tests — no root required, no network access:

```bash
cargo test --lib
```

Covers merge/dedup logic (6 tests), CIDR parsing and subnet iteration (4 tests), and vendor lookup (7 tests).

### Integration Tests

Requires Docker and root. Uses `assert_cmd` to run the binary as a subprocess against a live Docker test network.

Enter a root shell with the Rust toolchain available:

```bash
sudo -s
export RUSTUP_HOME="/home/<user>/.rustup"
export CARGO_HOME="/home/<user>/.cargo"
export PATH="/home/<user>/.cargo/bin:$PATH"
```

Run the integration suite:

```bash
cargo test --test integration -- --ignored --test-threads=1
```

`--test-threads=1` is required — Docker tests share a single `testnet` network and must run serially to avoid conflicts.

**Tests:**
- `integration_discovers_docker_network` — full sweep, asserts 2 hosts, correct IPs, no duplicate rows, table headers present
- `no_args_prints_usage` — asserts non-zero exit and usage message
- `invalid_interface_returns_error` — asserts non-zero exit and error message for unknown interface
- `results_are_consistent_across_runs` — runs binary twice, asserts same IPs both times

### Docker Fixtures

The test infrastructure can also be used manually:

```bash
# Spin up a 192.168.99.0/24 bridge network with two Alpine containers
./tests/docker_setup.sh

# Run against the printed bridge interface
sudo ./discovery br-<id>

# Tear down
./tests/docker_teardown.sh
```

Note: Docker's default iptables rules block ICMP forwarding on the bridge. To enable ICMP replies from containers:

```bash
sudo iptables -I DOCKER-USER -p icmp -j ACCEPT
```

## Dependencies

- [pnet](https://github.com/libpnet/libpnet) — raw packet construction and datalink channel
- [mac-vendor-lookup](../vendor) — OUI to vendor name lookup (local crate, future crates.io publish)
- [comfy-table](https://github.com/nukesor/comfy-table) — terminal table output
- [log](https://github.com/rust-lang/log) + [env_logger](https://github.com/rust-cli/env_logger) — structured runtime logging

## Scope

ARP and ICMP sweeps are effective and low-noise on /24 networks. Sweeping /16 or larger is not recommended — it generates excessive traffic and takes impractical amounts of time. This tool is intended for use on networks you own or have explicit authorization to scan.
