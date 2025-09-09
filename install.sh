#!/bin/bash
# Auto SlowDNS (DNSTT) Installer for Ubuntu
# Author: Humran13
# Features: One-click install with auto config

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}=== SlowDNS Auto Installer by Humran13 ===${NC}"

# --- Variables (edit before uploading to GitHub) ---
NAMESERVER="your-ns.domain.com"
SSH_PORT="2222"
USERNAME="slowdns-user"
PASSWORD="123456"

# Dates
CREATED_DATE=$(date '+%d %b %Y')
EXPIRED_DATE=$(date -d "+7 days" '+%d %b %Y')

# --- Update system ---
echo -e "${GREEN}[1/6] Updating system...${NC}"
apt update -y && apt upgrade -y

# --- Install dependencies ---
echo -e "${GREEN}[2/6] Installing dependencies...${NC}"
apt install -y git make build-essential screen cron iptables wget curl

# --- Download and build DNSTT ---
echo -e "${GREEN}[3/6] Installing DNSTT...${NC}"
if ! command -v dnstt-server &>/dev/null; then
    cd /tmp
    git clone https://github.com/yarrick/dnstt.git
    cd dnstt/dnstt-server
    make
    cp dnstt-server /usr/local/bin/
fi

# --- Create keys if not exist ---
mkdir -p /etc/slowdns
cd /etc/slowdns
if [[ ! -f /etc/slowdns/server.key || ! -f /etc/slowdns/server.pub ]]; then
    echo -e "${GREEN}Generating new DNS keys...${NC}"
    /usr/local/bin/dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub
fi

# --- Configure SSH ---
echo -e "${GREEN}[4/6] Configuring SSH...${NC}"
if ! grep -q "Port $SSH_PORT" /etc/ssh/sshd_config; then
    echo "Port $SSH_PORT" >> /etc/ssh/sshd_config
    systemctl restart ssh
fi

id -u "$USERNAME" &>/dev/null || adduser --disabled-password --gecos "" "$USERNAME"
echo "$USERNAME:$PASSWORD" | chpasswd
chage -E $(date -d "+7 days" +%Y-%m-%d) "$USERNAME"

# --- IPTables rules ---
echo -e "${GREEN}[5/6] Configuring firewall...${NC}"
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
ufw allow "$SSH_PORT"/tcp
ufw allow 53/udp
ufw --force enable

# --- Create systemd service ---
echo -e "${GREEN}[6/6] Setting up systemd service...${NC}"
cat << EOF > /etc/systemd/system/slowdns.service
[Unit]
Description=SlowDNS (DNSTT) Tunnel
After=network.target

[Service]
ExecStart=/usr/local/bin/dnstt-server -udp :5300 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSH_PORT
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable slowdns
systemctl restart slowdns

# --- Output details ---
echo -e "${YELLOW}=========================================${NC}"
echo -e "${GREEN} Installation Complete! ${NC}"
echo -e "${YELLOW}=========================================${NC}"
echo "Hostname: $HOSTNAME"
echo "Nameserver: $NAMESERVER"
echo "Username: $USERNAME"
echo "Password: $PASSWORD"
echo "SSH Port: $SSH_PORT"
echo "Created: $CREATED_DATE"
echo "Expired: $EXPIRED_DATE"
echo "DNS Public Key: $(cat /etc/slowdns/server.pub)"
echo -e "${YELLOW}=========================================${NC}"
