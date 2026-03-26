#!/usr/bin/env bash
set -e

docker stop target1 target2
docker rm target1 target2
docker network rm testnet

echo "[*] Test network torn down"
