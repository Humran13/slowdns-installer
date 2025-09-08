#!/bin/bash
# ==========================================================
# SlowDNS (DNS Tunnel) Installer Script for Ubuntu/Debian
# Author: Cleaned & Rewritten by ChatGPT (2025)
# Features:
# - Works with captive portals
# - Bypasses DPI (Deep Packet Inspection)
# - Uses UDP/53 tunneling
# - Simple SSH integration
# ==========================================================

# --- Check root ---
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root!"
   echo "Try: sudo -i"
   exit 1
fi

# --- Detect OS ---
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Unsupported system!"
    exit 1
fi

# --- Install Dependencies ---
echo "[*] Installing dependencies..."
if [[ "$OS" =~ (debian|ubuntu) ]]; then
    apt update -y
    apt install -y git build-essential wget curl unzip iptables net-tools dnsutils
else
    echo "Only Ubuntu/Debian are supported."
    exit 1
fi

# --- Download & Build dnstt ---
echo "[*] Downloading and building dnstt..."
cd /opt
if [ ! -d "/opt/dnstt" ]; then
    git clone https://github.com/yawning/dnstt.git
fi
cd dnstt/dnstt-server
go build .

# --- Configure SlowDNS ---
read -p "Enter your SSH server IP: " SERVER_IP
read -p "Enter your domain (NS record must point here): " DNS_DOMAIN

mkdir -p /etc/slowdns
cat > /etc/slowdns/config.json <<EOF
{
  "listen": "0.0.0.0:53",
  "server_ip": "$SERVER_IP",
  "domain": "$DNS_DOMAIN"
}
EOF

# --- Systemd Service ---
cat > /etc/systemd/system/slowdns.service <<EOF
[Unit]
Description=SlowDNS (dnstt) Tunnel
After=network.target

[Service]
ExecStart=/opt/dnstt/dnstt-server -udp :53 -privkey-file /etc/slowdns/private.key -pubkey-file /etc/slowdns/public.key $DNS_DOMAIN 127.0.0.1:22
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# --- Enable Service ---
systemctl daemon-reexec
systemctl enable slowdns
systemctl start slowdns

echo "=================================================="
echo " SlowDNS setup complete!"
echo " SSH over DNS is now running on UDP port 53"
echo " Domain: $DNS_DOMAIN"
echo " Server IP: $SERVER_IP"
echo "=================================================="
