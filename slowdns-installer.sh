#!/bin/bash

# SlowDNS (dnstt) Smart Installer for Ubuntu
# - Auto bind to :53 or fallback to :5300 with iptables redirect
# - Supports multiple NS domains with unique keys
# - Optional OpenSSH with compression or Dropbear
# - Optional DoH/DoT stubs via dnsproxy
# - User management for SSH access
# - Author: Humran13 (improved interactive version)
# - GitHub: https://github.com/Humran13/slowdns-installer

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Paths
DNSTT_DIR="/opt/dnstt"
CONFIG_DIR="/etc/dnstt"
SERVICE_DIR="/etc/systemd/system"
PRIMARY_SERVICE="${SERVICE_DIR}/dnstt-server.service"

# Ensure root
if [ "${EUID}" -ne 0 ]; then
  echo -e "${RED}Please run as root (sudo).${NC}"
  exit 1
fi

echo -e "${YELLOW}=== SlowDNS (DNSTT) Smart Installer ===${NC}"

# -------- Input Validation --------
validate_domain() {
  local domain="$1"
  if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    echo -e "${RED}Invalid domain format: $domain${NC}"
    exit 1
  fi
}

validate_ip() {
  local ip="$1"
  if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo -e "${RED}Invalid IPv4 address: $ip${NC}"
    exit 1
  fi
}

validate_port() {
  local port="$1"
  if [[ ! "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    echo -e "${RED}Invalid port: $port (must be 1-65535)${NC}"
    exit 1
  fi
}

# -------- Inputs --------
read -rp "Enter tunnel NS domain(s), comma-separated (e.g., t.testmyvps.site or t1.testmyvps.site,t2.testmyvps.site): " NS_DOMAINS_RAW
IFS=',' read -r -a NS_DOMAINS <<< "${NS_DOMAINS_RAW// /}"
if [ "${#NS_DOMAINS[@]}" -lt 1 ]; then
  echo -e "${RED}At least one NS domain is required.${NC}"
  exit 1
fi
for domain in "${NS_DOMAINS[@]}"; do
  validate_domain "$domain"
done

read -rp "Enter your VPS public IP (e.g., 194.238.24.199): " VPS_IP
validate_ip "$VPS_IP"

read -rp "SSH backend port (Dropbear default 2222, OpenSSH 22) [2222]: " SSH_PORT
SSH_PORT="${SSH_PORT:-2222}"
validate_port "$SSH_PORT"

read -rp "Install Dropbear (y/n) [y]: " WANT_DROPBEAR
WANT_DROPBEAR="${WANT_DROPBEAR:-y}"

read -rp "Install OpenSSH server with compression (y/n) [n]: " WANT_OPENSSH
WANT_OPENSSH="${WANT_OPENSSH:-n}"

read -rp "Install local DoH/DoT stubs via dnsproxy (y/n) [n]: " WANT_DNSPROXY
WANT_DNSPROXY="${WANT_DNSPROXY:-n}"

read -rp "Install fail2ban for SSH security (y/n) [y]: " WANT_FAIL2BAN
WANT_FAIL2BAN="${WANT_FAIL2BAN:-y}"

# -------- Install Dependencies --------
echo -e "${GREEN}Installing dependencies...${NC}"
apt update -y
apt install -y golang-go git curl ca-certificates socat netcat-openbsd iptables-persistent
if [[ "${WANT_FAIL2BAN}" =~ ^[Yy]$ ]]; then
  apt install -y fail2ban
  systemctl enable --now fail2ban
fi

# -------- Configure Dropbear --------
if [[ "${WANT_DROPBEAR}" =~ ^[Yy]$ ]]; then
  echo -e "${GREEN}Installing Dropbear...${NC}"
  apt install -y dropbear
  sed -i 's/NO_START=1/NO_START=0/' /etc/default/dropbear 2>/dev/null || true
  if grep -q "^DROPBEAR_PORT=" /etc/default/dropbear; then
    sed -i "s/^DROPBEAR_PORT=.*/DROPBEAR_PORT=${SSH_PORT}/" /etc/default/dropbear
  else
    echo "DROPBEAR_PORT=${SSH_PORT}" >> /etc/default/dropbear
  fi
  systemctl enable --now dropbear
fi

# -------- Configure OpenSSH --------
if [[ "${WANT_OPENSSH}" =~ ^[Yy]$ ]]; then
  echo -e "${GREEN}Installing OpenSSH with compression...${NC}"
  apt install -y openssh-server
  if ! grep -q "^Compression " /etc/ssh/sshd_config; then
    echo "Compression yes" >> /etc/ssh/sshd_config
  else
    sed -i 's/^Compression .*/Compression yes/' /etc/ssh/sshd_config
  fi
  systemctl enable --now ssh
  SSH_PORT=22  # Override to 22 for OpenSSH unless user specified otherwise
fi

# -------- Install dnstt --------
echo -e "${GREEN}Fetching and building dnstt...${NC}"
mkdir -p "${DNSTT_DIR}"
if [ ! -d "${DNSTT_DIR}/.git" ]; then
  git clone https://www.bamsoftware.com/git/dnstt.git "${DNSTT_DIR}"
fi
cd "${DNSTT_DIR}"
go build ./dnstt-server ./dnstt-client

mkdir -p "${CONFIG_DIR}"

# -------- Generate Unique Keys per NS Domain --------
echo -e "${GREEN}Generating encryption keys...${NC}"
declare -A PUBKEYS
for domain in "${NS_DOMAINS[@]}"; do
  key_dir="${CONFIG_DIR}/keys/${domain}"
  mkdir -p "$key_dir"
  "${DNSTT_DIR}/dnstt-server" -gen-key -privkey-file "${key_dir}/server.key" -pubkey-file "${key_dir}/server.pub"
  PUBKEYS["$domain"]=$(cat "${key_dir}/server.pub")
  echo -e "${YELLOW}Public key for ${domain}: ${GREEN}${PUBKEYS[$domain]}${NC}"
done

# Save config
cat > "${CONFIG_DIR}/dnstt.conf" <<EOF
NS_DOMAINS=${NS_DOMAINS_RAW}
VPS_IP=${VPS_IP}
SSH_PORT=${SSH_PORT}
EOF

# -------- Disable systemd-resolved Stub Listener --------
echo -e "${GREEN}Disabling systemd-resolved stub listener...${NC}"
if systemctl is-active --quiet systemd-resolved; then
  echo -e "${YELLOW}Configuring DNSStubListener=no...${NC}"
  mkdir -p /etc/systemd/resolved.conf.d
  echo -e "[Resolve]\nDNSStubListener=no" > /etc/systemd/resolved.conf.d/no-stub.conf
  systemctl restart systemd-resolved
fi

# -------- Port Binding Test --------
echo -e "${YELLOW}Checking if UDP :53 can be bound...${NC}"
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

# Fallback to alternative ports if 5300 is taken
if [ "$NEED_REDIRECT" = "yes" ] && ss -lun | grep -q ":5300 "; then
  for alt_port in 5301 5302 5303; do
    socat -T1 -u UDP4-RECVFROM:${alt_port},ip-add-membership=224.0.0.1:0.0.0.0,fork - &>/dev/null &
    SOCAT_PID=$!
    sleep 0.5
    if ! ss -lun | grep -q ":${alt_port} "; then
      BIND_PORT="${alt_port}"
      echo -e "${YELLOW}Port 5300 occupied, using fallback port ${BIND_PORT}.${NC}"
      break
    fi
    kill "${SOCAT_PID}" &>/dev/null || true
  done
fi

# -------- Create Primary dnstt Service --------
PRIMARY_NS="${NS_DOMAINS[0]}"
echo -e "${GREEN}Creating primary DNSTT service for NS: ${PRIMARY_NS} on UDP :${BIND_PORT}...${NC}"
cat > "${PRIMARY_SERVICE}" <<EOF
[Unit]
Description=dnstt-server (primary) - ${PRIMARY_NS}
After=network.target

[Service]
ExecStart=${DNSTT_DIR}/dnstt-server -udp :${BIND_PORT} -privkey-file ${CONFIG_DIR}/keys/${PRIMARY_NS}/server.key ${PRIMARY_NS} 127.0.0.1:${SSH_PORT}
Restart=always
User=root
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

# -------- Create Standby Services --------
ALT_PORTS=(5353 5454 5553)
i=0
for ns in "${NS_DOMAINS[@]:1}"; do
  port="${ALT_PORTS[$i]:-0}"
  [ "$port" = "0" ] && break
  svc="${SERVICE_DIR}/dnstt-server-${port}.service"
  echo -e "${GREEN}Creating standby DNSTT service for NS: ${ns} on UDP :${port}...${NC}"
  cat > "${svc}" <<EOF
[Unit]
Description=dnstt-server (standby) - ${ns}
After=network.target

[Service]
ExecStart=${DNSTT_DIR}/dnstt-server -udp :${port} -privkey-file ${CONFIG_DIR}/keys/${ns}/server.key ${ns} 127.0.0.1:${SSH_PORT}
Restart=always
User=root
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
  i=$((i+1))
done

# -------- Start Services --------
systemctl daemon-reload
systemctl enable --now dnstt-server.service
for p in "${ALT_PORTS[@]}"; do
  if [ -f "${SERVICE_DIR}/dnstt-server-${p}.service" ]; then
    systemctl enable --now "dnstt-server-${p}.service"
  fi
done

# -------- iptables Redirect --------
if [ "${NEED_REDIRECT}" = "yes" ]; then
  echo -e "${GREEN}Setting up iptables redirect: UDP 53 -> ${BIND_PORT}${NC}"
  iptables -I INPUT -p udp --dport "${BIND_PORT}" -j ACCEPT
  iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports "${BIND_PORT}"
  ip6tables -I INPUT -p udp --dport "${BIND_PORT}" -j ACCEPT 2>/dev/null || true
  ip6tables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports "${BIND_PORT}" 2>/dev/null || true
  netfilter-persistent save
fi

# -------- Install dnsproxy --------
if [[ "${WANT_DNSPROXY}" =~ ^[Yy]$ ]]; then
  echo -e "${GREEN}Installing dnsproxy for DoH/DoT...${NC}"
  DNSPROXY_URL="https://github.com/AdguardTeam/dnsproxy/releases/latest/download/dnsproxy-linux-amd64.tar.gz"
  mkdir -p /opt/dnsproxy
  if curl -fsSL -o /tmp/dnsproxy.tar.gz "${DNSPROXY_URL}" && tar -xzf /tmp/dnsproxy.tar.gz -C /opt/dnsproxy; then
    cat > /etc/systemd/system/dnsproxy.service <<EOF
[Unit]
Description=Local DoH/DoT stub (dnsproxy)
After=network.target

[Service]
ExecStart=/opt/dnsproxy/dnsproxy --listen=127.0.0.1:5053 --upstream=https://dns.cloudflare.com/dns-query
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now dnsproxy.service
    echo -e "${YELLOW}dnsproxy running on 127.0.0.1:5053 (DoH to Cloudflare).${NC}"
  else
    echo -e "${YELLOW}dnsproxy installation failed; skipping DoH/DoT stub.${NC}"
  fi
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
  echo -e "${GREEN}User ${USERNAME} added for SSH.${NC}"
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
  echo -e "${GREEN}Checking dnstt status...${NC}"
  if systemctl is-active --quiet dnstt-server; then
    echo -e "${GREEN}Primary dnstt-server (${PRIMARY_NS}, :${BIND_PORT}) is running.${NC}"
  else
    echo -e "${RED}Primary dnstt-server is stopped.${NC}"
  fi
  for p in "${ALT_PORTS[@]}"; do
    if [ -f "${SERVICE_DIR}/dnstt-server-${p}.service" ] && systemctl is-active --quiet "dnstt-server-${p}"; then
      echo -e "${GREEN}Standby dnstt-server (:${p}) is running.${NC}"
    fi
  done
  if [[ "${WANT_DNSPROXY}" =~ ^[Yy]$ ]] && systemctl is-active --quiet dnsproxy; then
    echo -e "${GREEN}dnsproxy (DoH/DoT) is running on 127.0.0.1:5053.${NC}"
  fi
  echo -e "${GREEN}Active SSH connections:${NC}"
  ss -tnp | grep ":${SSH_PORT}" || echo "No active connections."
}

# -------- Main Menu --------
while true; do
  echo -e "${YELLOW}=== SlowDNS Installer (Humran13) ===${NC}"
  echo "1. Install SlowDNS (dnstt)"
  echo "2. Add SSH User"
  echo "3. Remove SSH User"
  echo "4. Check Status"
  echo "5. Exit"
  read -rp "Choose an option [1-5]: " OPTION
  case $OPTION in
    1) break ;;  # Installation already handled above
    2) add_user ;;
    3) remove_user ;;
    4) check_status ;;
    5) echo -e "${GREEN}Exiting...${NC}"; exit 0 ;;
    *) echo -e "${RED}Invalid option.${NC}" ;;
  esac
done

# -------- Installation Summary --------
echo -e "\n${YELLOW}=== Installation Summary ===${NC}"
echo -e "Primary NS: ${PRIMARY_NS}"
echo -e "Listening port: UDP ${BIND_PORT} ${NEED_REDIRECT:+(with iptables 53->${BIND_PORT})}"
echo -e "SSH backend: 127.0.0.1:${SSH_PORT} ${WANT_OPENSSH:+(OpenSSH Compression yes)} ${WANT_DROPBEAR:+(Dropbear)}"
for domain in "${NS_DOMAINS[@]}"; do
  echo -e "DNSTT public key for ${domain}:\n${GREEN}${PUBKEYS[$domain]}${NC}"
done

echo -e "\n${YELLOW}DNS Records (set at your DNS provider):${NC}"
echo "  - A: tns.${PRIMARY_NS#*.} -> ${VPS_IP}"
echo "  - NS: ${PRIMARY_NS} -> tns.${PRIMARY_NS#*.}"
for ns in "${NS_DOMAINS[@]:1}"; do
  echo "  - NS (standby): ${ns} -> tns.${ns#*.}"
done

echo -e "\n${YELLOW}Android Client (HTTP Injector):${NC}"
echo "  DNSTT Nameserver: ${PRIMARY_NS}"
echo "  DNSTT Public Key: ${PUBKEYS[$PRIMARY_NS]}"
echo "  DNSTT Port: 53 ${NEED_REDIRECT:+(server redirects to ${BIND_PORT})}"
echo "  SSH Host/IP: ${VPS_IP}"
echo "  SSH Port: ${SSH_PORT}"
echo "  DNS Resolver: Cloudflare DoH (https://dns.cloudflare.com/dns-query) or Google (https://dns.google/dns-query)"
if [ -f /etc/systemd/system/dnstt-server-5353.service ]; then
  echo "  Standby routes: UDP 5353, 5454, 5553 (use matching NS)."
fi

echo -e "\n${GREEN}Done!${NC} Check logs: ${YELLOW}journalctl -u dnstt-server -f${NC}"
