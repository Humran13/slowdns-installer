# SlowDNS Installer
A bash script to set up an undetectable SlowDNS (dnstt) tunnel on Ubuntu, compatible with HTTP Injector on Android.

## Features
- Install dnstt with automated DNS tunneling setup.
- Add SSH users for Dropbear.
- Uninstall, backup, restore, and check status.
- Designed for stealth with low-speed, randomized DNS queries.

## Usage
1. Download: `wget https://raw.githubusercontent.com/Humran13/slowdns-installer/main/slowdns-installer.sh`
2. bash <(curl -s https://raw.githubusercontent.com/Humran13/SlowDNS-Installer/main/install.sh)

3. Make executable: `chmod +x slowdns-installer.sh`
4. Run: `sudo ./slowdns-installer.sh`
5. Follow prompts to install, add users, or manage the service.

## Requirements
- Ubuntu server with root access.
- Domain with DNS control (A/AAAA and NS records).
- HTTP Injector app on Android.
