#!/bin/bash

# SlowDNS (dnstt) Installer for Ubuntu
# - Binds to UDP 53 or falls back to 5300 with iptables redirect
# - Dropbear SSH on port 2222
# - User management for SSH access
# - Optimized for testmyvps.site (194.238.24.199) and HTTP Injector
# Author: Humran13
# GitHub: https://github.com/Humran13/slowdns-installer

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Paths
DNSTT_DIR="/opt/dnstt"
CONFIG_DIR="/etc/dnstt"
SERVICE_FILE="/etc/systemd/system/dnstt-server.service"

# Ensure root
if [ "${EUID}" -ne 0 ]; then
  echo -e "${RED}Please run as root (sudo).${NC}"
  exit 1
fi

# -------- Input Validation --------
validate_domain() {
  local domain="$1"
  if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    echo -e "${RED}Invalid domain: $domain${NC}"
    exit 1
  fi
}

validate_ip() {
  local ip="$1"
  if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo -e "${RED}Invalid IPv4: $ip${NC}"
    exit 1
  fi
}

# -------- Inputs --------
echo -e "${YELLOW}=== SlowDNS (DNSTT) Installer ===${NC}"
read -rp "Enter tunnel NS domain [t.testmyvps.site]: " NS_DOMAIN
NS_DOMAIN="${NS_DOMAIN:-t.testmyvps.site}"
validate_domain "$NS_DOMAIN"

read -rp "Enter VPS public IP [194.238.24.199]: " VPS_IP
VPS_IP="${VPS_IP:-194.238.24.199}"
validate_ip "$VPS_IP"

SSH_PORT=2222  # Fixed to match working setup

# -------- Install Dependencies --------
echo -e "${GREEN}Installing dependencies...${NC}"
apt update -y
apt install -y golang-go git curl ca-certificates socat netcat-openbsd iptables-persistent dropbear fail2ban
systemctl enable --now fail2ban

# -------- Configure Dropbear --------
echo -e "${GREEN}Configuring Dropbear on port ${SSH_PORT}...${NC}"
sed -i 's/NO_START=1/NO_START=0/' /etc/default/dropbear 2>/dev/null || true
if grep -q "^DROPBEAR_PORT=" /etc/default/dropbear; then
  sed -i "s/^DROPBEAR_PORT=.*/DROPBEAR_PORT=${SSH_PORT}/" /etc/default/dropbear
else
  echo "DROPBEAR_PORT=${SSH_PORT}" >> /etc/default/dropbear
fi
systemctl enable --now dropbear

# -------- Install dnstt --------
echo -e "${GREEN}Installing dnstt...${NC}"
mkdir -p "${DNSTT_DIR}"
if [ ! -d "${DNSTT_DIR}/.git" ]; then
  git clone https://www.bamsoftware.com/git/dnstt.git "${DNSTT_DIR}"
fi
cd "${DNSTT_DIR}/dnstt-server"
go build

# Generate keys
mkdir -p "${CONFIG_DIR}"
if [ ! -f "${CONFIG_DIR}/server.key" ] || [ ! -f "${CONFIG_DIR}/server.pub" ]; then
  ./dnstt-server -gen-key -privkey-file "${CONFIG_DIR}/server.key" -pubkey-file "${CONFIG_DIR}/server.pub"
fi
PUBKEY=$(cat "${CONFIG_DIR}/server.pub")
echo -e "${YELLOW}Public key: ${GREEN}${PUBKEY}${NC}"

# Save config
cat > "${CONFIG_DIR}/dnstt.conf" <<EOF
NS_DOMAIN=${NS_DOMAIN}
VPS_IP=${VPS_IP}
SSH_PORT=${SSH_PORT}
PUBKEY=${PUBKEY}
EOF

# -------- Disable systemd-resolved --------
echo -e "${GREEN}Disabling systemd-resolved stub listener...${NC}"
if systemctl is-active --quiet systemd-resolved; then
  mkdir -p /etc/systemd/resolved.conf.d
  echo -e "[Resolve]\nDNSStubListener=no" > /etc/systemd/resolved.conf.d/no-stub.conf
  systemctl restart systemd-resolved
  echo "nameserver 8.8.8.8" > /etc/resolv.conf
fi

# -------- Port Binding Test --------
echo -e "${YELLOW}Checking UDP :53 availability...${NC}"
CAN_BIND_53="no"
BIND_PORT="5300"
NEED_REDIRECT="yes"

socat -T1 -u UDP4-RECVFROM:53,ip-add-membership=224.0.0.1:0.0.0.0,fork - &>/dev/null &
SOCAT_PID=$!
sleep 0.5
if ss -lun | grep -q ":53 "; then
  CAN_BIND_53="yes"
  BIND_PORT="53"
  NEED_REDIRECT="no"
fi
kill "${SOCAT_PID}" &>/dev/null || true

# Fallback to 5301-5303 if 5300 is taken
if [ "$NEED_REDIRECT" = "yes" ] && ss -lun | grep -q ":5300 "; then
  for alt_port in 5301 5302 5303; do
    socat -T1 -u UDP4-RECVFROM:${alt_port},ip-add-membership=224.0.0.1:0.0.0.0,fork - &>/dev/null &
    SOCAT_PID=$!
    sleep 0.5
    if ! ss -lun | grep -q ":${alt_port} "; then
      BIND_PORT="${alt_port}"
      echo -e "${YELLOW}Port 5300 occupied, using ${BIND_PORT}.${NC}"
      break
    fi
    kill "${SOCAT_PID}" &>/dev/null || true
  done
fi

# -------- Create dnstt Service --------
echo -e "${GREEN}Creating dnstt service on UDP :${BIND_PORT}...${NC}"
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=dnstt-server - ${NS_DOMAIN}
After=network.target

[Service]
ExecStart=${DNSTT_DIR}/dnstt-server/dnstt-server -udp :${BIND_PORT} -privkey-file ${CONFIG_DIR}/server.key ${NS_DOMAIN} 127.0.0.1:${SSH_PORT}
Restart=always
User=root
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now dnstt-server

# -------- iptables Redirect --------
if [ "${NEED_REDIRECT}" = "yes" ]; then
  echo -e "${GREEN}Setting iptables: UDP 53 -> ${BIND_PORT}${NC}"
  iptables -I INPUT -p udp --dport "${BIND_PORT}" -j ACCEPT
  iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports "${BIND_PORT}"
  ip6tables -I INPUT -p udp --dport "${BIND_PORT}" -j ACCEPT 2>/dev/null || true
  ip6tables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports "${BIND_PORT}" 2>/dev/null || true
  netfilter-persistent save
fi

# -------- User Management --------
add_user() {
  read -rp "Enter new username: " USERNAME
  if id "$USERNAME" &>/dev/null; then
    echo -e "${RED}User ${USERNAME} already exists.${NC}"
    return 1
  fi
  read -rs -p "Enter password: " PASSWORD
  echo
  useradd -m -s /bin/bash "$USERNAME"
  echo "${USERNAME}:${PASSWORD}" | chpasswd
  echo -e "${GREEN}User ${USERNAME} added.${NC}"
}

remove_user() {
  echo -e "${GREEN}Existing users:${NC}"
  getent passwd | grep '/home' | cut -d: -f1
  read -rp "Enter username to remove: " USERNAME
  if id "$USERNAME" &>/dev/null; then
    userdel -r "$USERNAME"
    echo -e "${GREEN}User ${USERNAME} removed.${NC}"
  else
    echo -e "${RED}User ${USERNAME} does not exist.${NC}"
  fi
}

# -------- Status Check --------
check_status() {
  echo -e "${GREEN}Checking status...${NC}"
  if systemctl is-active --quiet dnstt-server; then
    echo -e "${GREEN}dnstt-server (${NS_DOMAIN}, :${BIND_PORT}) is running.${NC}"
  else
    echo -e "${RED}dnstt-server is stopped.${NC}"
  fi
  echo -e "${GREEN}Active SSH connections:${NC}"
  ss -tnp | grep ":${SSH_PORT}" || echo "No active connections."
}

# -------- Uninstall --------
uninstall() {
  echo -e "${GREEN}Uninstalling dnstt...${NC}"
  systemctl stop dnstt-server
  systemctl disable dnstt-server
  rm -f "${SERVICE_FILE}"
  systemctl daemon-reload
  rm -rf "${DNSTT_DIR}" "${CONFIG_DIR}"
  iptables -D INPUT -p udp --dport "${BIND_PORT}" -j ACCEPT 2>/dev/null || true
  iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports "${BIND_PORT}" 2>/dev/null || true
  ip6tables -D INPUT -p udp --dport "${BIND_PORT}" -j ACCEPT 2>/dev/null || true
  ip6tables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports "${BIND_PORT}" 2>/dev/null || true
  netfilter-persistent save
  apt purge -y dropbear
  echo -e "${GREEN}Uninstallation complete.${NC}"
}

# -------- Main Menu --------
while true; do
  echo -e "${YELLOW}=== SlowDNS Installer (Humran13) ===${NC}"
  echo "1. Install SlowDNS (dnstt)"
  echo "2. Add SSH User"
  echo "3. Remove SSH User"
  echo "4. Check Status"
  echo "5. Uninstall"
  echo "6. Exit"
  read -rp "Choose an option [1-6]: " OPTION
  case $OPTION in
    1) break ;;  # Installation handled above
    2) add_user ;;
    3) remove_user ;;
    4) check_status ;;
    5) uninstall ;;
    6) echo -e "${GREEN}Exiting...${NC}"; exit 0 ;;
    *) echo -e "${RED}Invalid option.${NC}" ;;
  esac
done

# -------- Installation Summary --------
echo -e "\n${YELLOW}=== Installation Summary ===${NC}"
echo -e "NS Domain: ${NS_DOMAIN}"
echo -e "VPS IP: ${VPS_IP}"
echo -e "SSH Port: ${SSH_PORT} (Dropbear)"
echo -e "Public Key: ${GREEN}${PUBKEY}${NC}"
echo -e "Listening Port: UDP ${BIND_PORT} ${NEED_REDIRECT:+(with iptables 53->${BIND_PORT})}"

echo -e "\n${YELLOW}DNS Records:${NC}"
echo "  - A: tns.${NS_DOMAIN#*.} -> ${VPS_IP}"
echo "  - NS: ${NS_DOMAIN} -> tns.${NS_DOMAIN#*.}"

echo -e "\n${YELLOW}HTTP Injector Setup:${NC}"
echo "  DNSTT Nameserver: ${NS_DOMAIN}"
echo "  DNSTT Public Key: ${PUBKEY}"
echo "  DNSTT Port: 53 ${NEED_REDIRECT:+(server redirects to ${BIND_PORT})}"
echo "  SSH Host: ${VPS_IP}"
echo "  SSH Port: ${SSH_PORT}"
echo "  SSH Username/Password: Use credentials from 'Add SSH User'"
echo "  DNS Resolver: Cloudflare DoH (https://dns.cloudflare.com/dns-query)"

echo -e "\n${GREEN}Done!${NC} Check logs: ${YELLOW}journalctl -u dnstt-server -f${NC}"
