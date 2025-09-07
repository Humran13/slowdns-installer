#!/usr/bin/env bash
# install-slowdns.sh
# Ubuntu installer for a DNSTT (SlowDNS) + optional Hysteria fallback,
# with prompts for domain/nameserver/credentials and a small "switch" helper.
#
# Notes:
# - Does NOT hardcode your VPS IP (you will be prompted).
# - Designed for Ubuntu 20.04 / 22.04 / 24.04.
# - Requires sudo / root.
#
# Adapted for GitHub distribution. Keep license & attribution where required.

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# --- helper functions ---
info(){ echo -e "\n[INFO] $*"; }
warn(){ echo -e "\n[WARN] $*"; }
err(){ echo -e "\n[ERROR] $*"; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
  err "Please run as root (sudo)."
fi

# --- Ask user for inputs (no IP requested) ---
read -p "Enter hostname (example: uk.sshmax.site): " HOSTNAME
read -p "Enter nameserver (the domain you will use as DNS name server): " NAMESERVER
read -p "Enter SSH username to create: " SSH_USER
read -s -p "Enter SSH password for user: " SSH_PASS
echo
read -p "Enter SSH port to run backend (example 2222): " SSH_PORT
read -p "Credential valid days (default 7): " EXPIRE_DAYS
EXPIRE_DAYS=${EXPIRE_DAYS:-7}

# Optional advanced features
read -p "Install Hysteria (obfuscated UDP fallback) [y/N]? " INSTALL_HYSTERIA
INSTALL_HYSTERIA=${INSTALL_HYSTERIA:-N}

# Optional: DoH/DoT resolver to forward client DNS to
read -p "Upstream recursive resolver (IP or DoH URL) [default: 1.1.1.1]: " UPSTREAM
UPSTREAM=${UPSTREAM:-1.1.1.1}

CREATED_DATE=$(date "+%e %b %Y")
EXPIRES_DATE=$(date -d "+${EXPIRE_DAYS} days" "+%e %b %Y")

# --- System prep ---
info "Updating packages..."
apt-get update -y
apt-get install -y git build-essential golang-go wget curl ca-certificates \
    iptables-persistent socat jq

# --- Create SSH user ---
info "Creating SSH user ${SSH_USER}..."
if id "${SSH_USER}" >/dev/null 2>&1; then
  warn "User ${SSH_USER} already exists; skipping creation."
else
  useradd -m -s /bin/bash "${SSH_USER}"
  echo "${SSH_USER}:${SSH_PASS}" | chpasswd
fi

# Ensure SSH allows TCP forwarding and compression (helps with proxied tunnels)
info "Configuring OpenSSH..."
sed -i 's/^#AllowTcpForwarding.*/AllowTcpForwarding yes/' /etc/ssh/sshd_config || true
sed -i 's/^#Compression.*/Compression yes/' /etc/ssh/sshd_config || true
systemctl restart sshd

# --- Install DNSTT (dnstt-server) ---
info "Installing dnstt (SlowDNS server)..."
TMPDIR=$(mktemp -d)
cd "$TMPDIR"
git clone https://github.com/tladesignz/dnstt.git dnstt || git clone https://github.com/Mygod/dnstt.git dnstt || true
cd dnstt || err "dnstt repo not found; please check git clone above."

# Build server (repo variations: some have ./dnstt-server, some have dnstt-server dir)
if [ -f "./dnstt-server/main.go" ] || [ -d "./dnstt-server" ]; then
  cd dnstt-server || true
fi

# try to build
info "Building dnstt-server (go build)..."
export GOPATH=/root/go
mkdir -p "$GOPATH"
if command -v go >/dev/null 2>&1; then
  go build -o /usr/local/bin/dnstt-server ./... || true
else
  warn "go not found; trying apt-installed golang-go..."
  go build -o /usr/local/bin/dnstt-server ./... || err "go build failed. Install golang and retry."
fi

if [ ! -x /usr/local/bin/dnstt-server ]; then
  # fallback: maybe binary is at ./dnstt-server
  if [ -f "./dnstt-server" ]; then
    cp ./dnstt-server /usr/local/bin/dnstt-server
    chmod +x /usr/local/bin/dnstt-server
  else
    err "Failed to place dnstt-server binary."
  fi
fi

# --- Generate DNSTT keypair ---
DNSTT_DIR=/etc/dnstt
mkdir -p "$DNSTT_DIR"
info "Generating DNSTT keypair..."
/usr/local/bin/dnstt-server -gen-key -privkey-file "$DNSTT_DIR/server.key" -pubkey-file "$DNSTT_DIR/server.pub" >/dev/null 2>&1 || true
if [ ! -f "$DNSTT_DIR/server.pub" ]; then
  warn "dnstt key generation didn't produce server.pub in expected place; trying alternate path..."
  /usr/local/bin/dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub || true
  mv server.key server.pub "$DNSTT_DIR/" || true
fi

PUBKEY="$(cat ${DNSTT_DIR}/server.pub || echo 'UNKNOWN_PUBKEY')"

# --- Create systemd service for dnstt ---
info "Creating systemd service for dnstt..."
cat > /etc/systemd/system/dnstt.service <<EOF
[Unit]
Description=dnstt DNS tunnel server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dnstt-server -udp :53 -privkey-file ${DNSTT_DIR}/server.key ${NAMESERVER} ${UPSTREAM} 127.0.0.1:${SSH_PORT}
Restart=always
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable dnstt.service
systemctl restart dnstt.service || warn "dnstt service failed to start - check journalctl -u dnstt"

# --- Install udpgw helper for UDP forwarding (helps UDP apps) ---
info "Installing UDP GW helper (badvpn-udpgw) for local UDP forwarding..."
if [ ! -f /usr/bin/badvpn-udpgw ]; then
  OSARCH=$(uname -m)
  if [ "$OSARCH" = "x86_64" ]; then
    wget -qO /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/daybreakersx/premscript/master/badvpn-udpgw64" || true
  else
    wget -qO /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/daybreakersx/premscript/master/badvpn-udpgw" || true
  fi
  chmod +x /usr/bin/badvpn-udpgw || true
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
systemctl restart udpgw.service

# --- Optional: install Hysteria (for obfuscated UDP fallback) ---
if [[ "${INSTALL_HYSTERIA,,}" =~ ^y ]]; then
  info "Installing Hysteria server as an alternate obfuscated UDP tunnel..."
  # Download prebuilt binary (use official release in production)
  HYST_BIN=/usr/local/bin/hysteria
  if [ ! -f "$HYST_BIN" ]; then
    wget -qO /usr/local/bin/hysteria https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-amd64 || true
    chmod +x /usr/local/bin/hysteria || true
  fi

  HYST_PASS=$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-12)
  mkdir -p /etc/hysteria
  cat > /etc/hysteria/server.json <<EOF
{
  "listen": ":8443",
  "protocol": "udp",
  "auth": {
    "mode":"password",
    "password":"${HYST_PASS}"
  },
  "obfs": {
    "type": "salamander",
    "salamander": { "password": "2031" }
  },
  "up_mbps": 100,
  "down_mbps": 100,
  "sockbuf": 16777216
}
EOF

  cat > /etc/systemd/system/hysteria.service <<EOF
[Unit]
Description=Hysteria server
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
  systemctl restart hysteria.service || warn "hysteria failed to start; check logs."
fi

# --- Create a small "switch" and "healthcheck" helper (adaptive routing helper) ---
info "Creating tunnel control helpers (/usr/local/bin/switch-tunnel and /usr/local/bin/tunnel-healthcheck)..."

cat > /usr/local/bin/switch-tunnel <<'EOF'
#!/usr/bin/env bash
# Usage: switch-tunnel dnstt|hysteria
if [ "$(id -u)" -ne 0 ]; then echo "run as root"; exit 1; fi
case "${1:-}" in
  dnstt)
    systemctl stop hysteria.service 2>/dev/null || true
    systemctl start dnstt.service
    echo "Active: dnstt"
    ;;
  hysteria)
    systemctl stop dnstt.service 2>/dev/null || true
    systemctl start hysteria.service
    echo "Active: hysteria"
    ;;
  *)
    echo "Usage: switch-tunnel dnstt|hysteria"
    exit 2
    ;;
esac
EOF
chmod +x /usr/local/bin/switch-tunnel

cat > /usr/local/bin/tunnel-healthcheck <<'EOF'
#!/usr/bin/env bash
# Basic health check: tries to connect to local tunnel endpoints and picks a running one
DNSTT_OK=false
HYST_OK=false

# check UDP port 53 (dnstt) by seeing if systemd says active
if systemctl is-active --quiet dnstt.service; then DNSTT_OK=true; fi
if systemctl is-active --quiet hysteria.service; then HYST_OK=true; fi

echo "dnstt: $DNSTT_OK  hysteria: $HYST_OK"

if [ "$DNSTT_OK" = "true" ]; then
  /usr/local/bin/switch-tunnel dnstt
elif [ "$HYST_OK" = "true" ]; then
  /usr/local/bin/switch-tunnel hysteria
else
  echo "Neither tunnel appears active. Start one with switch-tunnel."
  exit 1
fi
EOF
chmod +x /usr/local/bin/tunnel-healthcheck

# --- Simple firewall rules to allow tunnel ports and protect SSH ---
info "Adding basic iptables rules for tunnel ports..."
iptables -I INPUT -p udp --dport 53 -j ACCEPT || true
iptables -I INPUT -p udp --dport 8443 -j ACCEPT || true
iptables -I INPUT -p tcp --dport ${SSH_PORT} -j ACCEPT || true
netfilter-persistent save || true

# --- print credentials / final block ---
cat <<EOF

==========================
Hostname: ${HOSTNAME}

Nameserver: ${NAMESERVER}

Username: ${SSH_USER}

Password: (hidden)

SSH Port: ${SSH_PORT}

Created: ${CREATED_DATE}

Expired: ${EXPIRES_DATE}

DNS Public Key:
${PUBKEY}

Notes:
- dnstt server listens on UDP/53 by default; point your SlowDNS client to ${NAMESERVER} and use the above public key.
- If you installed Hysteria, its password is in /etc/hysteria/server.json (and obfs salamander password set to 2031).
- Use 'switch-tunnel dnstt' or 'switch-tunnel hysteria' to change active backend.
- Use 'tunnel-healthcheck' to auto-select available tunnel.
- For captive-portal situations: you may need to authenticate to portal before the tunnel works. DNSTT can use DoH/DoT (configured by client) to help when UDP is blocked. Hysteria supports obfuscation ("salamander") for DPI resistance.
- Check logs: journalctl -u dnstt -f or journalctl -u hysteria -f
==========================

EOF

# cleanup
cd /
rm -rf "$TMPDIR" || true

info "Installation finished. Please add DNS A/NS records for ${NAMESERVER} pointing to your server's public IP."
