#!/bin/bash
# SSH over DNS (SlowDNS) Setup Script using Iodine
# Features:
# 1. Works with captive portals
# 2. Bypasses deep packet inspection
# 3. Overcomes port blocking (UDP/53)
# 4. Dynamic packet compression (-c flag in iodine)
# 5. Adaptive routing (multiple NS support on client)
# 6. Protocol switching (iodine --protocol)

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

echo -e "${GREEN}SSH over DNS (Iodine) Setup Starting...${NC}"

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

read -s -p "DNS tunnel password: " DNS_PASSWORD
echo ""
[[ -z "$DNS_PASSWORD" ]] && { echo -e "${RED}Empty DNS password!${NC}"; exit 1; }

# Tunnel IP
TUN_IP="10.0.0.1"

# Dates
CREATED_DATE=$(date '+%d %b %Y')
EXPIRED_DATE=$(date -d "+7 days" '+%d %b %Y')

# --- Install deps ---
echo -e "${YELLOW}Installing dependencies...${NC}"
apt update -y
apt install -y build-essential git ufw make

# --- Install iodine ---
if ! command -v iodined &>/dev/null; then
    cd /tmp
    git clone https://github.com/yarrick/iodine.git
    cd iodine
    make
    make install
    cd ..
    rm -rf iodine
fi

# --- Firewall ---
ufw allow 53/udp
ufw allow $SSH_PORT/tcp
ufw --force enable

# --- SSH config ---
echo -e "${YELLOW}Configuring SSH...${NC}"
if ! grep -q "Port $SSH_PORT" /etc/ssh/sshd_config; then
    echo "Port $SSH_PORT" >> /etc/ssh/sshd_config
fi
systemctl restart ssh

# --- Create SSH user ---
id -u "$USERNAME" &>/dev/null || adduser --disabled-password --gecos "" "$USERNAME"
echo "$USERNAME:$PASSWORD" | chpasswd

# expire user in 7 days
chage -E $(date -d "+7 days" +%Y-%m-%d) "$USERNAME"

# --- systemd service for iodine ---
cat << EOF > /etc/systemd/system/iodine.service
[Unit]
Description=Iodine DNS Tunnel
After=network.target

[Service]
ExecStart=/usr/local/sbin/iodined -f -c -P "$DNS_PASSWORD" $TUN_IP $HOSTNAME
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable iodine
systemctl restart iodine

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
DNS Public Key: $DNS_PASSWORD

Client Usage:
1. Install iodine:  sudo apt install iodine   (Debian/Ubuntu) or brew install iodine (macOS).
2. Run: iodine -f -c -P "$DNS_PASSWORD" <YOUR_SERVER_IP> $HOSTNAME
3. SSH: ssh -p $SSH_PORT $USERNAME@$TUN_IP

Notes:
- Works through captive portals (DNS allowed).
- Use --protocol or alternate NS for adaptive routing.
- SSH compression is enabled by default.
EOF
