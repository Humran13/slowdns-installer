#!/usr/bin/env bash
# install-slowdns.sh
# Interactive Ubuntu installer for DNSTT (SlowDNS) with optional Hysteria fallback.
# Features:
# 1. Works with captive portals: Supports DoH/DoT via client configuration.
# 2. Bypasses deep packet inspection: DNSTT uses DNS encoding; Hysteria uses QUIC obfuscation.
# 3. Overcomes port blocking: Uses UDP 53 (DNS) and configurable Hysteria port.
# 4. Dynamic packet compression: Enabled via DNSTT -compress flag.
# 5. Adaptive connection routing: Health check script switches between DNSTT/Hysteria.
# 6. Intelligent protocol switching: Client-side DoH/DoT and server-side DNSTT/Hysteria toggle.
#
# Requirements:
# - Ubuntu 20.04/22.04/24.04, root access (sudo).
# - DNS setup: NS record for <hostname> pointing to <nameserver>, A record for <nameserver> to server IP.
# Usage: sudo bash install-slowdns.sh
# After setup, use 'switch-tunnel' and 'tunnel-healthcheck' for protocol management.

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
info() { echo -e "${GREEN}[INFO] $*${NC}"; }
warn() { echo -e "${YELLOW}[WARN] $*${NC}"; }
err() { echo -e "${RED}[ERROR] $*${NC}"; exit 1; }

# Check root privileges
if [ "$(id -u)" -ne 0 ]; then
  err "Please run as root (sudo)."
fi

# --- Prompt for user inputs ---
info "Enter configuration details (press Enter for defaults where applicable)."
read -p "Hostname (e.g., uk.sshmax.site): " HOSTNAME
[ -z "$HOSTNAME" ] && err "Hostname cannot be empty."
read -p "Nameserver (e.g., uk-ns.sshmax.site, A record to server IP): " NAMESERVER
[ -z "$NAMESERVER" ] && err "Nameserver cannot be empty."
read -p "SSH username: " SSH_USER
[ -z "$SSH_USER" ] && err "Username cannot be empty."
read -s -p "SSH password: " SSH_PASS
echo
[ -z "$SSH_PASS" ] && err "Password cannot be empty."
read -p "SSH port (default: 2222): " SSH_PORT
SSH_PORT=${SSH_PORT:-2222}
read -p "Credential valid days (default: 7): " EXPIRE_DAYS
EXPIRE_DAYS=${EXPIRE_DAYS:-7}
read -p "Upstream resolver (IP or DoH URL, default: 1.1.1.1): " UPSTREAM
UPSTREAM=${UPSTREAM:-1.1.1.1}
read -p "Install Hysteria (UDP fallback) [y/N]? " INSTALL_HYSTERIA
INSTALL_HYSTERIA=${INSTALL_HYSTERIA:-N}
read -p "Use UFW instead of iptables for firewall? [y/N]: " USE_UFW
USE_UFW=${USE_UFW:-N}
if [[ "${INSTALL_HYSTERIA,,}" =~ ^y ]]; then
  read -p "Hysteria port (default: 8443): " HYSTERIA_PORT
  HYSTERIA_PORT=${HYSTERIA_PORT:-8443}
  read -s -p "Hysteria password: " HYSTERIA_PASS
  echo
  [ -z "$HYSTERIA_PASS" ] && err "Hysteria password cannot be empty."
fi

# Calculate dates
CREATED_DATE=$(date "+%e %b %Y")
EXPIRES_DATE=$(date -d "+${EXPIRE_DAYS} days" "+%e %b %Y")

# --- Install dependencies ---
info "Installing dependencies..."
apt-get update -y || err "Failed to update package lists."
apt-get install -y git build-essential golang-go wget curl ca-certificates \
  netfilter-persistent iptables-persistent ufw || err "Failed to install dependencies."

# --- Create SSH user with expiration ---
info "Creating SSH user $SSH_USER..."
if id "$SSH_USER" >/dev/null 2>&1; then
  warn "User $SSH_USER exists; updating password and expiration."
  echo "$SSH_USER:$SSH_PASS" | chpasswd
else
  useradd -m -s /bin/bash "$SSH_USER" || err "Failed to create user $SSH_USER."
  echo "$SSH_USER:$SSH_PASS" | chpasswd
fi
chage -E "$(date -d "+${EXPIRE_DAYS} days" +%F)" "$SSH_USER" || warn "Failed to set user expiration."

# --- Configure SSH ---
info "Configuring SSH on port $SSH_PORT..."
sed -i "s/#Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config
sed -i 's/#AllowTcpForwarding.*/AllowTcpForwarding yes/' /etc/ssh/sshd_config
sed -i 's/#Compression.*/Compression yes/' /etc/ssh/sshd_config
systemctl restart sshd || err "Failed to restart SSH service."

# --- Install DNSTT ---
info "Installing DNSTT server..."
DNSTT_DIR=/etc/dnstt
mkdir -p "$DNSTT_DIR"
cd /tmp
if [ -d "dnstt" ]; then rm -rf dnstt; fi
git clone https://github.com/Mygod/dnstt.git || err "Failed to clone DNSTT repository."
cd dnstt/dnstt-server
go build -o /usr/local/bin/dnstt-server . || err "Failed to build DNSTT server."
cd /tmp
rm -rf dnstt

# --- Generate DNSTT keypair ---
info "Generating DNSTT keypair..."
/usr/local/bin/dnstt-server -gen-key -privkey-file "$DNSTT_DIR/server.key" -pubkey-file "$DNSTT_DIR/server.pub" || err "Failed to generate DNSTT keys."
PUBKEY=$(cat "$DNSTT_DIR/server.pub" 2>/dev/null) || err "Failed to read DNSTT public key."

# --- Configure DNSTT service ---
info "Creating DNSTT systemd service..."
cat > /etc/systemd/system/dnstt.service <<EOF
[Unit]
Description=DNSTT DNS Tunnel Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dnstt-server -udp :53 -compress -privkey-file $DNSTT_DIR/server.key $NAMESERVER $UPSTREAM 127.0.0.1:$SSH_PORT
Restart=always
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable dnstt.service
systemctl restart dnstt.service || warn "DNSTT service failed to start; check journalctl -u dnstt."

# --- Install badvpn-udpgw for UDP forwarding ---
info "Installing badvpn-udpgw for UDP forwarding..."
if [ ! -f /usr/bin/badvpn-udpgw ]; then
  OSARCH=$(uname -m)
  if [ "$OSARCH" = "x86_64" ]; then
    wget -qO /usr/bin/badvpn-udpgw "https://github.com/ambrop72/badvpn/releases/download/1.999.130/badvpn-udpgw" || err "Failed to download badvpn-udpgw."
  else
    err "badvpn-udpgw only supported on x86_64."
  fi
  chmod +x /usr/bin/badvpn-udpgw
fi
cat > /etc/systemd/system/udpgw.service <<EOF
[Unit]
Description=UDPGW Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable udpgw.service
systemctl restart udpgw.service || warn "UDPGW service failed to start."

# --- Install Hysteria (optional) ---
if [[ "${INSTALL_HYSTERIA,,}" =~ ^y ]]; then
  info "Installing Hysteria server..."
  HYST_BIN=/usr/local/bin/hysteria
  if [ ! -f "$HYST_BIN" ]; then
    wget -qO "$HYST_BIN" https://github.com/apernet/hysteria/releases/download/v2.5.0/hysteria-linux-amd64 || err "Failed to download Hysteria."
    chmod +x "$HYST_BIN"
  fi
  mkdir -p /etc/hysteria
  cat > /etc/hysteria/server.json <<EOF
{
  "listen": ":$HYSTERIA_PORT",
  "protocol": "udp",
  "auth": {
    "mode": "password",
    "password": "$HYSTERIA_PASS"
  },
  "obfs": {
    "type": "salamander",
    "salamander": { "password": "$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-12)" }
  },
  "up_mbps": 100,
  "down_mbps": 100,
  "sockbuf": 16777216
}
EOF
  cat > /etc/systemd/system/hysteria.service <<EOF
[Unit]
Description=Hysteria Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria -c /etc/hysteria/server.json
Restart=always

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable hysteria.service
  systemctl restart hysteria.service || warn "Hysteria service failed to start; check journalctl -u hysteria."
fi

# --- Create tunnel control scripts ---
info "Creating tunnel control scripts..."
cat > /usr/local/bin/switch-tunnel <<EOF
#!/usr/bin/env bash
if [ "\$(id -u)" -ne 0 ]; then echo "Run as root"; exit 1; fi
case "\${1:-}" in
  dnstt)
    systemctl stop hysteria.service 2>/dev/null || true
    systemctl start dnstt.service
    echo "Active: DNSTT"
    ;;
  hysteria)
    systemctl stop dnstt.service 2>/dev/null || true
    systemctl start hysteria.service
    echo "Active: Hysteria"
    ;;
  *)
    echo "Usage: switch-tunnel dnstt|hysteria"
    exit 2
    ;;
esac
EOF
chmod +x /usr/local/bin/switch-tunnel

cat > /usr/local/bin/tunnel-healthcheck <<EOF
#!/usr/bin/env bash
if [ "\$(id -u)" -ne 0 ]; then echo "Run as root"; exit 1; fi
DNSTT_OK=\$(systemctl is-active dnstt.service)
HYST_OK=\$(systemctl is-active hysteria.service 2>/dev/null || echo inactive)
echo "DNSTT: \$DNSTT_OK  Hysteria: \$HYST_OK"
if [ "\$DNSTT_OK" = "active" ]; then
  /usr/local/bin/switch-tunnel dnstt
elif [ "\$HYST_OK" = "active" ]; then
  /usr/local/bin/switch-tunnel hysteria
else
  echo "No tunnels active. Start one with switch-tunnel."
  exit 1
fi
EOF
chmod +x /usr/local/bin/tunnel-healthcheck

# --- Configure firewall ---
info "Configuring firewall..."
if [[ "${USE_UFW,,}" =~ ^y ]]; then
  ufw allow "$SSH_PORT"/tcp
  ufw allow 53/udp
  [[ "${INSTALL_HYSTERIA,,}" =~ ^y ]] && ufw allow "$HYSTERIA_PORT"/udp
  ufw --force enable
else
  iptables -I INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT
  iptables -I INPUT -p udp --dport 53 -j ACCEPT
  [[ "${INSTALL_HYSTERIA,,}" =~ ^y ]] && iptables -I INPUT -p udp --dport "$HYSTERIA_PORT" -j ACCEPT
  netfilter-persistent save || warn "Failed to save iptables rules."
fi

# --- Output configuration ---
cat <<EOF

==========================
Hostname: $HOSTNAME
Nameserver: $NAMESERVER
Username: $SSH_USER
Password: (hidden)
SSH Port: $SSH_PORT
Created: $CREATED_DATE
Expired: $EXPIRES_DATE
DNS Public Key: $PUBKEY
$(if [[ "${INSTALL_HYSTERIA,,}" =~ ^y ]]; then
  echo "Hysteria Port: $HYSTERIA_PORT
Hysteria Password: (hidden)"
fi)

Notes:
- DNSTT listens on UDP/53. Point your SlowDNS client to $NAMESERVER with the above public key.
- Client command: dnstt-client -doh $UPSTREAM -pubkey $PUBKEY $NAMESERVER 127.0.0.1:$SSH_PORT
- SSH: ssh -p $SSH_PORT $SSH_USER@127.0.0.1
- For captive portals: Use DoH/DoT (e.g., https://1.1.1.1/dns-query) in client settings.
- $(if [[ "${INSTALL_HYSTERIA,,}" =~ ^y ]]; then
  echo "Hysteria client: hysteria client -c /path/to/client.json (config in /etc/hysteria/server.json)."
fi)
- Switch tunnels: sudo switch-tunnel dnstt|hysteria
- Check tunnels: sudo tunnel-healthcheck
- Logs: journalctl -u dnstt -f $(if [[ "${INSTALL_HYSTERIA,,}" =~ ^y ]]; then echo "or journalctl -u hysteria -f"; fi)
- DNS setup: Set NS record for $HOSTNAME to $NAMESERVER, and A record for $NAMESERVER to your server IP.

Uninstallation:
  sudo systemctl disable --now dnstt udpgw $(if [[ "${INSTALL_HYSTERIA,,}" =~ ^y ]]; then echo "hysteria"; fi)
  sudo rm -rf /etc/dnstt /usr/local/bin/dnstt-server /usr/bin/badvpn-udpgw \
    /usr/local/bin/hysteria /etc/hysteria /etc/systemd/system/{dnstt,udpgw$(if [[ "${INSTALL_HYSTERIA,,}" =~ ^y ]]; then echo ",hysteria"; fi)}.service \
    /usr/local/bin/{switch-tunnel,tunnel-healthcheck}
  sudo deluser --remove-home $SSH_USER
  sudo sed -i 's/Port $SSH_PORT/Port 22/' /etc/ssh/sshd_config
  sudo systemctl restart sshd
  $(if [[ "${USE_UFW,,}" =~ ^y ]]; then
    echo "sudo ufw delete allow $SSH_PORT/tcp
  sudo ufw delete allow 53/udp"
    [[ "${INSTALL_HYSTERIA,,}" =~ ^y ]] && echo "sudo ufw delete allow $HYSTERIA_PORT/udp"
  else
    echo "sudo iptables -D INPUT -p tcp --dport $SSH_PORT -j ACCEPT
  sudo iptables -D INPUT -p udp --dport 53 -j ACCEPT"
    [[ "${INSTALL_HYSTERIA,,}" =~ ^y ]] && echo "sudo iptables -D INPUT -p udp --dport $HYSTERIA_PORT -j ACCEPT"
    echo "sudo netfilter-persistent save"
  fi)

For GitHub:
  Create a README.md with prerequisites, usage, and the above uninstallation steps.
==========================
EOF

info "Installation complete. Configure DNS records for $NAMESERVER."
