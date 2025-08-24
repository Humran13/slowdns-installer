#!/bin/bash

# SlowDNS (dnstt) Installer Script for Ubuntu - Undetectable DNS Tunneling
# GitHub: Humran13
# Run as root: sudo ./slowdns-installer.sh

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Directories and files
DNSTT_DIR="/opt/dnstt"
CONFIG_DIR="/etc/dnstt"
SERVICE_FILE="/etc/systemd/system/dnstt-server.service"

# Check if root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root (sudo).${NC}"
  exit 1
fi

# Function to check if a package is installed
check_package() {
  dpkg -l "$1" &> /dev/null && return 0 || return 1
}

# Function to install dependencies
install_deps() {
  echo -e "${GREEN}Installing dependencies...${NC}"
  apt update && apt upgrade -y
  apt install -y golang-go git iptables-persistent netcat-openbsd dropbear || {
    echo -e "${RED}Failed to install dependencies.${NC}"
    exit 1
  }
}

# Function to install dnstt
install_dnstt() {
  if [ -d "$DNSTT_DIR" ]; then
    echo -e "${YELLOW}dnstt already installed at $DNSTT_DIR. Skipping clone.${NC}"
  else
    echo -e "${GREEN}Cloning dnstt repository...${NC}"
    git clone https://www.bamsoftware.com/git/dnstt.git "$DNSTT_DIR" || {
      echo -e "${RED}Failed to clone repo.${NC}"
      exit 1
    }
  fi

  # Build dnstt-server
  cd "$DNSTT_DIR/dnstt-server"
  go build || { echo -e "${RED}Build failed. Ensure Go is installed.${NC}"; exit 1; }

  # Generate keys
  echo -e "${GREEN}Generating encryption keys...${NC}"
  ./dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub
  PUBKEY=$(cat server.pub)
  echo -e "${GREEN}Public key: ${PUBKEY}${NC}"

  # Prompt for tunnel domain
  read -p "Enter your tunnel subdomain (e.g., t.example.com): " TUNNEL_DOMAIN
  echo "TUNNEL_DOMAIN=${TUNNEL_DOMAIN}" > "$CONFIG_DIR/dnstt.conf"

  # Set up Dropbear on port 2222
  echo -e "${GREEN}Configuring Dropbear SSH on port 2222...${NC}"
  sed -i 's/NO_START=1/NO_START=0/' /etc/default/dropbear
  sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=2222/' /etc/default/dropbear
  systemctl restart dropbear

  # Set up iptables
  echo -e "${GREEN}Setting up port forwarding (UDP 53 -> 5300)...${NC}"
  iptables -I INPUT -p udp --dport 5300 -j ACCEPT
  iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
  ip6tables -I INPUT -p udp --dport 5300 -j ACCEPT
  ip6tables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
  netfilter-persistent save

  # Create systemd service
  echo -e "${GREEN}Creating systemd service...${NC}"
  cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=dnstt-server DNS Tunnel
After=network.target

[Service]
ExecStart=$DNSTT_DIR/dnstt-server/dnstt-server -udp :5300 -privkey-file $DNSTT_DIR/dnstt-server/server.key ${TUNNEL_DOMAIN} 127.0.0.1:2222
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable dnstt-server
  systemctl start dnstt-server

  # Verify
  if systemctl is-active --quiet dnstt-server; then
    echo -e "${GREEN}Installation complete! dnstt-server is running.${NC}"
    echo -e "${YELLOW}Save this public key for HTTP Injector:${NC} ${PUBKEY}"
    echo -e "${YELLOW}DNS Setup:${NC}"
    echo "  - A/AAAA: tns.${TUNNEL_DOMAIN#*.} -> Your server's IPv4/IPv6"
    echo "  - NS: ${TUNNEL_DOMAIN} -> tns.${TUNNEL_DOMAIN#*.}"
  else
    echo -e "${RED}Installation failed. Check logs with 'journalctl -u dnstt-server'.${NC}"
    exit 1
  fi
}

# Function to add a user
add_user() {
  read -p "Enter new username: " USERNAME
  read -s -p "Enter password: " PASSWORD
  echo
  echo "${USERNAME}:${PASSWORD}" | chpasswd
  echo -e "${GREEN}User ${USERNAME} added for Dropbear SSH.${NC}"
}

# Function to remove a user
remove_user() {
  echo -e "${GREEN}Existing users:${NC}"
  cat /etc/passwd | grep '/home' | cut -d: -f1
  read -p "Enter username to remove: " USERNAME
  if id "$USERNAME" &>/dev/null; then
    userdel -r "$USERNAME"
    echo -e "${GREEN}User ${USERNAME} removed.${NC}"
  else
    echo -e "${RED}User ${USERNAME} does not exist.${NC}"
  fi
}

# Function to uninstall
uninstall_dnstt() {
  echo -e "${GREEN}Uninstalling dnstt and cleaning up...${NC}"
  systemctl stop dnstt-server
  systemctl disable dnstt-server
  rm -f "$SERVICE_FILE"
  systemctl daemon-reload
  rm -rf "$DNSTT_DIR" "$CONFIG_DIR"
  iptables -D INPUT -p udp --dport 5300 -j ACCEPT
  iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
  ip6tables -D INPUT -p udp --dport 5300 -j ACCEPT
  ip6tables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
  netfilter-persistent save
  apt purge -y dropbear
  echo -e "${GREEN}Uninstallation complete.${NC}"
}

# Function to check status
check_status() {
  echo -e "${GREEN}Checking dnstt status...${NC}"
  if systemctl is-active --quiet dnstt-server; then
    echo -e "${GREEN}dnstt-server is running.${NC}"
  else
    echo -e "${RED}dnstt-server is stopped.${NC}"
  fi
  echo -e "${GREEN}Active SSH users:${NC}"
  netstat -tuln | grep :2222
  ps aux | grep dropbear | grep -v grep
}

# Main menu
mkdir -p "$CONFIG_DIR"
while true; do
  echo -e "${YELLOW}=== SlowDNS Installer (Humran13) ===${NC}"
  echo "1. Install SlowDNS (dnstt)"
  echo "2. Add SSH User"
  echo "3. Uninstall SlowDNS"
  echo "4. Remove SSH User"
  echo "5. Check Status"
  echo "6. Exit"
  read -p "Choose an option [1-6]: " OPTION

  case $OPTION in
    1) install_deps && install_dnstt ;;
    2) add_user ;;
    3) uninstall_dnstt ;;
    4) remove_user ;;
    5) check_status ;;
    6) echo -e "${GREEN}Exiting...${NC}"; exit 0 ;;
    *) echo -e "${RED}Invalid option.${NC}" ;;
  esac
done
