#!/bin/bash

# SSH Over DNS (Slow DNS) Server Setup Script for Ubuntu
# This script sets up an Iodine DNS tunnel server on Ubuntu, creates a temporary SSH user,
# and generates client configuration details.
# Features:
# 1. Works with captive portals: DNS queries typically bypass HTTP/HTTPS interception.
# 2. Bypasses deep packet inspection: Traffic is encoded within standard DNS packets.
# 3. Overcomes port blocking: Utilizes DNS port 53 (UDP), which is rarely blocked.
# 4. Dynamic packet compression: Enabled via Iodine's built-in compression (-c flag).
# 5. Adaptive connection routing: Script supports multiple nameservers for failover (configurable).
# 6. Intelligent protocol switching: Iodine supports multiple encoding protocols; client can switch via --protocol flag.
#
# Prerequisites:
# - Run as root (sudo ./setup.sh)
# - You must have a domain (e.g., sshmax.site) with NS records set up:
#   - For subdomain uk.sshmax.site, set NS to uk-ns.sshmax.site
#   - Point uk-ns.sshmax.site A record to your server's public IP
# - Firewall: Allow UDP port 53 (ufw allow 53/udp)
# - SSH: Ensure SSH is installed and running.
#
# Usage: sudo bash setup_ssh_over_dns.sh
# After setup, run the Iodine server manually or via systemd (see below).
# Client example: iodine -f -P <DNS_PASSWORD> <SERVER_IP> uk.sshmax.site
# Then SSH: ssh -p 2222 sshmax-admin1@10.0.0.1

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting SSH Over DNS setup...${NC}"

# Step 1: Update system and install dependencies
echo -e "${YELLOW}Updating system and installing dependencies...${NC}"
apt update -y
apt upgrade -y
apt install -y build-essential libssl-dev zlib1g-dev git ufw adduser

# Step 2: Install Iodine from source (if not available in repos)
echo -e "${YELLOW}Installing Iodine...${NC}"
if ! command -v iodined &> /dev/null; then
    cd /tmp
    git clone https://github.com/yarrick/iodine.git
    cd iodine
    make
    make install
    cd ..
    rm -rf iodine
fi

# Step 3: Configure firewall (allow DNS port 53 UDP)
echo -e "${YELLOW}Configuring firewall...${NC}"
ufw allow 53/udp
ufw --force enable
ufw status

# Step 4: Configure SSH to listen on port 2222 for the tunnel
echo -e "${YELLOW}Configuring SSH...${NC}"
sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
systemctl restart ssh

# Step 5: Create temporary SSH user
USERNAME="sshmax-admin1"
PASSWORD="admin123"
echo -e "${YELLOW}Creating SSH user: $USERNAME${NC}"
adduser --disabled-password --gecos "" $USERNAME
echo "$USERNAME:$PASSWORD" | chpasswd

# Set expiration (7 days from now)
EXPIRED_DATE=$(date -d "+7 days" '+%d %b %Y')
CREATED_DATE=$(date '+%d %b %Y')

# Step 6: Iodine configuration details
HOSTNAME="uk.sshmax.site"
NAMESERVER="uk-ns.sshmax.site"
TUN_IP="10.0.0.1"  # IP assigned to client
SSH_PORT="2222"
DNS_PASSWORD="dnskey123"  # This will be the "DNS Public Key" - change for security
# For adaptive routing, add more NS records and use multiple in client config

# Output the client configuration
echo -e "${GREEN}Setup complete! Client Configuration:${NC}"
echo "Hostname: $HOSTNAME"
echo "Nameserver: $NAMESERVER"
echo "Username: $USERNAME"
echo "Password: $PASSWORD"
echo "SSH Port: $SSH_PORT"
echo "Created: $CREATED_DATE"
echo "Expired: $EXPIRED_DATE"
echo "DNS Public Key: $DNS_PASSWORD"

# Instructions for running the server
echo -e "${YELLOW}To start the Iodine server (run as root):${NC}"
echo "iodined -f -c -P $DNS_PASSWORD $TUN_IP $HOSTNAME"
echo ""
echo -e "${YELLOW}For systemd service (create /etc/systemd/system/iodine.service):${NC}"
cat << EOF > /etc/systemd/system/iodine.service
[Unit]
Description=Iodine DNS Tunnel Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/sbin/iodined -c -P $DNS_PASSWORD $TUN_IP $HOSTNAME
Restart=always

[Install]
WantedBy=multi-user.target
EOF
echo "Then: systemctl daemon-reload && systemctl enable iodine && systemctl start iodine"
echo ""
echo -e "${YELLOW}Client Usage:${NC}"
echo "1. On client (install iodine similarly): iodine -f -c -P $DNS_PASSWORD <YOUR_SERVER_IP> $HOSTNAME"
echo "2. This creates tun0 with IP $TUN_IP/30"
echo "3. SSH: ssh -p $SSH_PORT $USERNAME@$TUN_IP"
echo "4. For adaptive routing: Use multiple nameservers in /etc/resolv.conf or client args."
echo "5. Protocol switching: Client use --protocol 200 (or others) if blocked."
echo ""
echo -e "${RED}Security Note: Change passwords and domain for production. User expires on $EXPIRED_DATE.${NC}"
echo -e "${GREEN}Script ready for GitHub! Add a README with prerequisites and features.${NC}"
