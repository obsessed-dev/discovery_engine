Milestone 3: Full ARP Subnet Sweep

With single ARP request/reply proven in Milestone 2, the objective now is to scale that to the entire subnet. You'll split TX and RX across two threads — one fires ARP requests at every host in the range, the other listens for replies within a time-bounded window and collects them into a structured Vec<HostRecord>. This is the scanner's core loop and where mac_vendor_lookup gets wired in for the first time.


- Define HostRecord struct and DiscoveryMethod enum, derive Debug
- Set pnet channel config with read_timeout: Some(Duration::from_millis(200))
- Open datalink channel, destructure into tx and rx
- Wrap results in Arc<Mutex<Vec<HostRecord>>>
- Spawn TX thread — iterate subnet IPs, skip network/broadcast, call send_arp_request() per IP with 1ms sleep between sends
- Spawn RX thread — loop until Instant::now() < deadline (3 sec), call rx.next(), pass frames to parse_arp_reply()
- parse_arp_reply() — filter for ARP Reply targeting your source IP, extract sender IP and MAC, call mac_vendor_lookup::lookup(), return Some(HostRecord)
- Push valid records into Arc<Mutex<Vec<HostRecord>>> from RX thread
- Join both thread handles
- Print results with comfy-table — columns: IP, MAC, Vendor, Method