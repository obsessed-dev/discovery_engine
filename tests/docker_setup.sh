#!/usr/bin/env bash
set -e

docker network create --subnet 192.168.99.0/24 testnet
docker run -d --name target1 --network testnet --cap-add NET_ADMIN alpine sleep 3600
docker run -d --name target2 --network testnet --cap-add NET_ADMIN alpine sleep 3600

BRIDGE_ID=$(docker network inspect testnet --format '{{ .Id }}' | head -c 12)
echo "[*] Test network ready"
echo "[*] Bridge interface: br-${BRIDGE_ID}"
echo "[*] Run: sudo ./discovery br-${BRIDGE_ID}"

# You can implement this iptables command via CLI to allow the host
# bridge interface to ICMP forward, otherwise Docker's iptables rules 
# will eat the packets before they reach the bridge.

# sudo iptables -I DOCKER-USER -p icmp -j ACCEPT