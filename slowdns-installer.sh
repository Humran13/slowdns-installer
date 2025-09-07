#!/bin/bash
# SSH over DNS (SlowDNS) Setup Script using DNSTT
# Works with HTTP Injector / HTTP Custom (Android)
# Features: Captive portal bypass, DPI evasion, Port 53 tunneling, Compression, Adaptive routing, Protocol switching

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Run as root (sudo).${NC}" 
   exit 1
fi

echo -e "${GREEN}SSH over DNS (DNSTT / SlowDNS) Setup Starting...${NC}"

# --- User inputs ---
read -p "Hostname (e.g. uk.sshmax.site): " HOSTNAME
[[ -z "$HOSTNAME" ]] && { echo -e "${RED}Empty hostname!${NC}"; exit 1; }

read -p "Nameserver (e.g. uk-ns.sshmax.site): " NAMESERVER
[[ -z "$NAMESERVER" ]] && { echo -e "${RED}Empty nameserver!${NC}"; exit 1; }

read -p "SSH username: " USERNAME
[[ -z "$USERNAME" ]] && { echo -e "${RED}Empty username!${NC}"; exit 1; }

read -s -p "SSH password: " PASSWORD
echo ""
[[ -z "$PASSWORD" ]] && { echo -e "${RED}Empty password!${NC}"; exit 1; }

read -p "SSH port [default 2222]: " SSH_PORT
SSH_PORT=${SSH_PORT:-2222}

# Tunnel IP (used by client SSH)
TUN_IP="127.0.0.1"

# Dates
CREATED_DATE=$(date '+%d %b %Y')
EXPIRED_DATE=$(date -d "+7 days" '+%d %b %Y')

# --- Install dependencies ---
echo -e "${YELLOW}Installing dependencies...${NC}"
apt update -y
apt install -y git golang-go build-essential ufw

# --- Build DNSTT ---
if ! command -v dnstt-server &>/dev/null; then
    cd /opt
    git clone https://github.com/yarrick/dnstt.git
    cd dnstt/dnstt-server
    go build .
    cp dnstt-server /usr/local/bin/
fi

# --- Generate keys ---
mkdir -p /etc/dnstt
cd /etc/dnstt
if [ ! -f server.key ]; then
    dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub
fi
PUBKEY=$(cat /etc/dnstt/server.pub)

# --- Firewall ---
ufw allow 53/udp
ufw allow $SSH_PORT/tcp
ufw --force enable

# --- SSH config ---
if ! grep -q "Port $SSH_PORT" /etc/ssh/sshd_config; then
    echo "Port $SSH_PORT" >> /etc/ssh/sshd_config
fi
systemctl restart ssh

# --- Create SSH user ---
id -u "$USERNAME" &>/dev/null || adduser --disabled-password --gecos "" "$USERNAME"
echo "$USERNAME:$PASSWORD" | chpasswd
chage -E $(date -d "+7 days" +%Y-%m-%d) "$USERNAME"

# --- systemd service for DNSTT ---
cat << EOF > /etc/systemd/system/dnstt.service
[Unit]
Description=DNSTT (SlowDNS) Server
After=network.target

[Service]
ExecStart=/usr/local/bin/dnstt-server -udp :53 -privkey-file /etc/dnstt/server.key ${NAMESERVER} 127.0.0.1:${SSH_PORT}
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable dnstt
systemctl restart dnstt

# --- Output block ---
echo -e "${GREEN}Setup Complete!${NC}"
cat << EOF
Hostname: $HOSTNAME
Nameserver: $NAMESERVER
Username: $USERNAME
Password: $PASSWORD
SSH Port: $SSH_PORT
Created: $CREATED_DATE
Expired: $EXPIRED_DATE

DNS Public Key:
$PUBKEY

Client Usage (HTTP Injector / HTTP Custom):
1. Go to "SlowDNS" settings.
2. Host: $HOSTNAME
3. Nameserver: $NAMESERVER
4. SSH Username/Password: as above
5. SSH Port: $SSH_PORT
6. Public Key: paste the key above
EOF
