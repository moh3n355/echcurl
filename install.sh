#!/bin/bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Checking dependencies..."
missing=0
for tool in docker dig python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "  - '$tool' not found."
    missing=1
  fi
done

if [ "$missing" -eq 1 ]; then
  echo "[!] Missing dependencies. Install them first:"
  echo "    docker : https://docs.docker.com/engine/install/"
  echo "    dig    : sudo apt install dnsutils   (or: yum install bind-utils)"
  echo "    python3: sudo apt install python3"
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "[!] Docker daemon is not reachable (not running, or you lack permission)."
  echo "    Try: sudo systemctl start docker   or add your user to the 'docker' group."
  exit 1
fi

echo "[*] Building openssl-ech image (this takes ~5-10 min)..."
docker build -t openssl-ech "$DIR"

echo "[*] Installing echcurl to /usr/local/bin ..."
sudo install -m 755 "$DIR/echcurl.py" /usr/local/bin/echcurl

echo "[*] Done. Try: echcurl example.com"
