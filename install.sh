#!/bin/bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "[*] Building openssl-ech image (this takes ~5-10 min)..."
docker build -t openssl-ech "$DIR"
echo "[*] Installing echcurl to /usr/local/bin ..."
sudo install -m 755 "$DIR/echcurl.py" /usr/local/bin/echcurl
echo "[*] Done. Try: echcurl example.com"
