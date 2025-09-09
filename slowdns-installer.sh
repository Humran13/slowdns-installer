#!/bin/bash
# Check if the current user is root
if [ "$EUID" -ne 0 ]; then
  echo "Please execute this script as root user!"
  echo "You can use 'sudo -i' to enter root user mode."
  exit 1
fi

check_sys() {
  if [[ -f /etc/redhat-release ]]; then
    release="centos"
  elif grep -qi "debian" /etc/issue; then
    release="debian"
  elif grep -qi "ubuntu" /etc/issue; then
    release="ubuntu"
  elif grep -qi -E "centos|red hat|redhat|rocky" /etc/issue || grep -qi -E "centos|red hat|redhat|rocky" /proc/version; then
    release="centos"
  fi

  if [[ -f /etc/debian_version ]]; then
    OS_type="Debian"
    echo "Detected Debian-based system, please report any errors"
  elif [[ -f /etc/redhat-release || -f /etc/centos-release || -f /etc/fedora-release || -f /etc/rocky-release ]]; then
    OS_type="CentOS"
    echo "Detected CentOS-based system, please report any errors"
  else
    echo "Unknown"
  fi
}


_exists() {
    local cmd="$1"
    if eval type type >/dev/null 2>&1; then
      eval type "$cmd" >/dev/null 2>&1
    elif command >/dev/null 2>&1; then
      command -v "$cmd" >/dev/null 2>&1
    else
      which "$cmd" >/dev/null 2>&1
    fi
    local rt=$?
    return ${rt}
}

random_color() {
  colors=("31" "32" "33" "34" "35" "36" "37")
  echo -e "\e[${colors[$((RANDOM % 7))]}m$1\e[0m"
}

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_TYPE=$ID
    OS_VERSION=$VERSION_ID
else
    echo "Unable to determine operating system type."
    exit 1
fi

install_custom_packages() {
    if [ "$OS_TYPE" = "debian" ] || [ "$OS_TYPE" = "ubuntu" ]; then
        apt update
        apt install -y wget sed sudo openssl net-tools psmisc procps iptables iproute2 ca-certificates jq
    elif [ "$OS_TYPE" = "centos" ] || [ "$OS_TYPE" = "rhel" ] || [ "$OS_TYPE" = "fedora" ] || [ "$OS_TYPE" = "rocky" ]; then
        yum install -y epel-release
        yum install -y wget sed sudo openssl net-tools psmisc procps-ng iptables iproute ca-certificates jq
    else
        echo "Unsupported operating system."
        exit 1
    fi
}

install_custom_packages

echo "Installed software packages:"
for pkg in wget sed openssl iptables jq; do
    if command -v $pkg >/dev/null 2>&1; then
        echo "$pkg installed"
    else
        echo "$pkg not installed"
    fi
done

echo "All specified software packages have been installed."

set_architecture() {
  case "$(uname -m)" in
    'i386' | 'i686')
     
      arch='386'
      ;;
    'amd64' | 'x86_64')
    
      arch='amd64'
      ;;
    'armv5tel' | 'armv6l' | 'armv7' | 'armv7l')
      
      arch='arm'
      ;;
    'armv8' | 'aarch64')
   
      arch='arm64'
      ;;
    'mips' | 'mipsle' | 'mips64' | 'mips64le')
      
      arch='mipsle'
      ;;
    's390x')
      
      arch='s390x'
      ;;
    *)

      echo "Temporarily does not support your system, possibly because it's not within the known architecture range."
      exit 1
      ;;
  esac
}

get_installed_version() {
    if [ -x "/root/hy3/hysteria-linux-$arch" ]; then
        version="$("/root/hy3/hysteria-linux-$arch" version | grep Version | grep -o 'v[.0-9]*')"
    else
        version="You haven't installed it yet, old chap"
    fi
}

get_latest_version() {
  local tmpfile
  tmpfile=$(mktemp)

  if ! curl -sS "https://api.hy2.io/v1/update?cver=installscript&plat=linux&arch="$arch"&chan=release&side=server" -o "$tmpfile"; then
    error "Failed to get the latest version from Hysteria 2 API, please check your network and try again."
    exit 11
  fi

  local latest_version
  latest_version=$(grep -oP '"lver":\s*\K"v.*?"' "$tmpfile" | head -1)
  latest_version=${latest_version#'"'}
  latest_version=${latest_version%'"'}

  if [[ -n "$latest_version" ]]; then
    echo "$latest_version"
  fi

  rm -f "$tmpfile"
}

checkact() {
pid=$(pgrep -f "hysteria-linux-$arch")

if [ -n "$pid" ]; then
  hy2zt="Running"
else
  hy2zt="Not running"
fi
}

BBR_grub() {
  if [[ "${OS_type}" == "CentOS" ]]; then
    if [[ ${version} == "6" ]]; then
      if [ -f "/boot/grub/grub.conf" ]; then
        sed -i 's/^default=.*/default=0/g' /boot/grub/grub.conf
      elif [ -f "/boot/grub/grub.cfg" ]; then
        grub-mkconfig -o /boot/grub/grub.cfg
        grub-set-default 0
      elif [ -f "/boot/efi/EFI/centos/grub.cfg" ]; then
        grub-mkconfig -o /boot/efi/EFI/centos/grub.cfg
        grub-set-default 0
      elif [ -f "/boot/efi/EFI/redhat/grub.cfg" ]; then
        grub-mkconfig -o /boot/efi/EFI/redhat/grub.cfg
        grub-set-default 0
      else
        echo -e "${Error} grub.conf/grub.cfg not found, please check."
        exit
      fi
    elif [[ ${version} == "7" ]]; then
      if [ -f "/boot/grub2/grub.cfg" ]; then
        grub2-mkconfig -o /boot/grub2/grub.cfg
        grub2-set-default 0
      elif [ -f "/boot/efi/EFI/centos/grub.cfg" ]; then
        grub2-mkconfig -o /boot/efi/EFI/centos/grub.cfg
        grub2-set-default 0
      elif [ -f "/boot/efi/EFI/redhat/grub.cfg" ]; then
        grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg
        grub2-set-default 0
      else
        echo -e "${Error} grub.cfg not found, please check."
        exit
      fi
    elif [[ ${version} == "8" ]]; then
      if [ -f "/boot/grub2/grub.cfg" ]; then
        grub2-mkconfig -o /boot/grub2/grub.cfg
        grub2-set-default 0
      elif [ -f "/boot/efi/EFI/centos/grub.cfg" ]; then
        grub2-mkconfig -o /boot/efi/EFI/centos/grub.cfg
        grub2-set-default 0
      elif [ -f "/boot/efi/EFI/redhat/grub.cfg" ]; then
        grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg
        grub2-set-default 0
      else
        echo -e "${Error} grub.cfg not found, please check."
        exit
      fi
      grubby --info=ALL | awk -F= '$1=="kernel" {print i++ " : " $2}'
    fi
  elif [[ "${OS_type}" == "Debian" ]]; then
    if _exists "update-grub"; then
      update-grub
    elif [ -f "/usr/sbin/update-grub" ]; then
      /usr/sbin/update-grub
    else
      apt install grub2-common -y
      update-grub
    fi
    #exit 1
  fi
}
check_version() {
  if [[ -s /etc/redhat-release ]]; then
    version=$(grep -oE "[0-9.]+" /etc/redhat-release | cut -d . -f 1)
  else
    version=$(grep -oE "[0-9.]+" /etc/issue | cut -d . -f 1)
  fi
  bit=$(uname -m)
  check_github
}
installxanmod1 () {
# Check if the system is Debian or Ubuntu
if [[ $(cat /etc/os-release) =~ ^(Debian|Ubuntu) ]]; then
  echo "OJBK"
else
  echo "System is not Debian or Ubuntu"
  exit 1
fi

# Check system architecture
if [[ $(uname -m) =~ ^(x86_64|amd64) ]]; then
  echo "Installing, please wait..."
else
  echo "System architecture is not x86/amd64, buddy, buy a better one"
  exit 1
fi

echo "System meets requirements, continuing script execution"
wget -qO - https://dl.xanmod.org/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | sudo tee /etc/apt/sources.list.d/xanmod-release.list
sudo apt update && sudo apt install linux-xanmod-x64v3
BBR_grub
echo -e "${Tip} Kernel installation complete, please refer to the above information to check if installation was successful, defaults to booting from the first high-version kernel"
echo "Installation successful, please restart the system manually"
}
installxanmod2 () {
  check_version
  wget -O check_x86-64_psabi.sh https://dl.xanmod.org/check_x86-64_psabi.sh
  chmod +x check_x86-64_psabi.sh
  cpu_level=$(./check_x86-64_psabi.sh | awk -F 'v' '{print $2}')
  echo -e "CPU supports \033[32m${cpu_level}\033[0m"
  # exit
  if [[ ${bit} != "x86_64" ]]; then
    echo -e "${Error} Does not support systems other than x86_64 !" && exit 1
  fi

  if [[ "${OS_type}" == "Debian" ]]; then
    apt update
    apt-get install gnupg gnupg2 gnupg1 sudo -y
    echo 'deb http://deb.xanmod.org releases main' | sudo tee /etc/apt/sources.list.d/xanmod-kernel.list
    wget -qO - https://dl.xanmod.org/gpg.key | sudo apt-key --keyring /etc/apt/trusted.gpg.d/xanmod-kernel.gpg add -
    if [[ "${cpu_level}" == "4" ]]; then
      apt update && apt install linux-xanmod-x64v4 -y
    elif [[ "${cpu_level}" == "3" ]]; then
      apt update && apt install linux-xanmod-x64v3 -y
    elif [[ "${cpu_level}" == "2" ]]; then
      apt update && apt install linux-xanmod-x64v2 -y
    else
      apt update && apt install linux-xanmod-x64v1 -y
    fi
  else
    echo -e "${Error} Does not support current system ${release} ${version} ${bit} !" && exit 1
  fi

  BBR_grub
  echo -e "${Tip} Kernel installation complete, please refer to the above information to check if installation was successful, defaults to booting from the first high-version kernel, please restart the system manually"
}
detele_kernel() {
  if [[ "${OS_type}" == "CentOS" ]]; then
    rpm_total=$(rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | wc -l)
    if [ "${rpm_total}" ] >"1"; then
      echo -e "Detected ${rpm_total} other kernels, starting removal..."
      for ((integer = 1; integer <= ${rpm_total}; integer++)); do
        rpm_del=$(rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | head -${integer})
        echo -e "Starting removal of ${rpm_del} kernel..."
        rpm --nodeps -e ${rpm_del}
        echo -e "Removal of ${rpm_del} kernel completed, continuing..."
      done
      echo --nodeps -e "Kernel removal completed, continuing..."
    else
      echo -e " Detected incorrect kernel count, please check !" && exit 1
    fi
  elif [[ "${OS_type}" == "Debian" ]]; then
    deb_total=$(dpkg -l | grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | wc -l)
    if [ "${deb_total}" ] >"1"; then
      echo -e "Detected ${deb_total} other kernels, starting removal..."
      for ((integer = 1; integer <= ${deb_total}; integer++)); do
        deb_del=$(dpkg -l | grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | head -${integer})
        echo -e "Starting removal of ${deb_del} kernel..."
        apt-get purge -y ${deb_del}
        apt-get autoremove -y
        echo -e "Removal of ${deb_del} kernel completed, continuing..."
      done
      echo -e "Kernel removal completed, continuing..."
    else
      echo -e " Detected incorrect kernel count, please check !" && exit 1
    fi
  fi
}
detele_kernel_head() {
  if [[ "${OS_type}" == "CentOS" ]]; then
    rpm_total=$(rpm -qa | grep kernel-headers | grep -v "${kernel_version}" | grep -v "noarch" | wc -l)
    if [ "${rpm_total}" ] >"1"; then
      echo -e "Detected ${rpm_total} other head kernels, starting removal..."
      for ((integer = 1; integer <= ${rpm_total}; integer++)); do
        rpm_del=$(rpm -qa | grep kernel-headers | grep -v "${kernel_version}" | grep -v "noarch" | head -${integer})
        echo -e "Starting removal of ${rpm_del} headers kernel..."
        rpm --nodeps -e ${rpm_del}
        echo -e "Removal of ${rpm_del} kernel completed, continuing..."
      done
      echo --nodeps -e "Kernel removal completed, continuing..."
    else
      echo -e " Detected incorrect kernel count, please check !" && exit 1
    fi
  elif [[ "${OS_type}" == "Debian" ]]; then
    deb_total=$(dpkg -l | grep linux-headers | awk '{print $2}' | grep -v "${kernel_version}" | wc -l)
    if [ "${deb_total}" ] >"1"; then
      echo -e "Detected ${deb_total} other head kernels, starting removal..."
      for ((integer = 1; integer <= ${deb_total}; integer++)); do
        deb_del=$(dpkg -l | grep linux-headers | awk '{print $2}' | grep -v "${kernel_version}" | head -${integer})
        echo -e "Starting removal of ${deb_del} headers kernel..."
        apt-get purge -y ${deb_del}
        apt-get autoremove -y
        echo -e "Removal of ${deb_del} kernel completed, continuing..."
      done
      echo -e "Kernel removal completed, continuing..."
    else
      echo -e " Detected incorrect kernel count, please check !" && exit 1
    fi
  fi
}
detele_kernel_custom() {
  BBR_grub
  read -p " View the above kernel input keyword to retain the kernel to keep (e.g., 5.15.0-11) :" kernel_version
  detele_kernel
  detele_kernel_head
  BBR_grub
}
welcome() {

echo -e "$(random_color '
â–‘â–ˆâ–ˆ  â–‘â–ˆâ–ˆ
â–‘â–ˆâ–ˆ  â–‘â–ˆâ–ˆ       â–‘â–ˆâ–ˆâ–ˆâ–ˆ        â–‘â–ˆ         â–‘â–ˆ        â–‘â–ˆâ–‘â–ˆâ–‘â–ˆ
â–‘â–ˆâ–ˆ  â–‘â–ˆâ–ˆ     â–‘â–ˆ      â–ˆ      â–‘â–ˆ         â–‘â–ˆ        â–‘â–ˆ    â–‘â–ˆ
â–‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆ     â–‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆ         â–‘â–ˆ         â–‘â–ˆ        â–‘â–ˆ    â–‘â–ˆ
â–‘â–ˆâ–ˆ  â–‘â–ˆâ–ˆ     â–‘â–ˆ             â–‘â–ˆ â–‘â–ˆ      â–‘â–ˆ  â–‘â–ˆ     â–‘â–ˆâ–‘â–ˆâ–‘â–ˆ
â–‘â–ˆâ–ˆ  â–‘â–ˆâ–ˆ      â–‘â–ˆâ–ˆ  â–ˆ         â–‘â–ˆ         â–‘â–ˆ                   ')"
 echo -e "$(random_color '
Life has two tragedies: one is despair, the other is complacency ')"
 
}

echo -e "$(random_color 'Installing necessary dependencies......')"
install_missing_commands > /dev/null 2>&1
echo -e "$(random_color 'Dependency installation complete')"

set_architecture

get_installed_version

latest_version=$(get_latest_version)

checkact

uninstall_hysteria() {

sudo systemctl stop hysteria.service

sudo systemctl disable hysteria.service

if [ -f "/etc/systemd/system/hysteria.service" ]; then
  sudo rm "/etc/systemd/system/hysteria.service"
  echo "Hysteria server service file has been removed."
else
  echo "Hysteria server service file does not exist."
fi

process_name="hysteria-linux-$arch"
pid=$(pgrep -f "$process_name")

if [ -n "$pid" ]; then
  echo "Found $process_name process (PID: $pid), killing..."
  kill "$pid"
  echo "$process_name process has been killed."
else
  echo "No $process_name process found."
fi

if [ -f "/root/hy3/hysteria-linux-$arch" ]; then
  rm -f "/root/hy3/hysteria-linux-$arch"
  echo "Hysteria server binary file has been removed."
else
  echo "Hysteria server binary file does not exist."
fi

if [ -f "/root/hy3/config.yaml" ]; then
  rm -f "/root/hy3/config.yaml"
  echo "Hysteria server configuration file has been removed."
else
  echo "Hysteria server configuration file does not exist."
fi

rm -rf /root/hy3
systemctl stop ipppp.service
systemctl disable ipppp.service
rm -rf /etc/systemd/system/ipppp.service
rm -rf /bin/hy2
echo "Uninstallation complete(à¸‡ à¸·â–¿ à¸·)à¸§."
 }

hy2easy() {
    rm -rf /usr/local/bin/hy2
    sudo wget -q hy2.crazyact.com -O /usr/local/bin/hy2
    sudo chmod +x /usr/local/bin/hy2
    echo "Added hy2 shortcut method"
}

hy2easy
welcome

#These are just prompts for your input ðŸ˜‡
echo "$(random_color 'Choose an operation, little buddy(à¸‡ à¸·â–¿ à¸·)à¸§:')"
echo -e "$(random_color 'Input hy2 to quickly start the script')"
echo "1. Install (Dream as horse)"
echo "2. Uninstall (Heart as shield)"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "3. View configuration (Through time and space)"
echo "4. Exit script (Return to the future)"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "5. Online update hy2 core (Your current hy2 version:$version)"
echo "6. hy2 core management"
echo "7. Install xanmod kernel (Better network resource scheduling)"
echo "hy2 core latest version is: $latest_version"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "hysteria2 status: $hy2zt"

read -p "Enter operation number (1/2/3/4/5): " choice

case $choice in
   1)
     #Nothing here
     ;;

   2)

uninstall_hysteria > /dev/null 2>&1
echo -e "$(random_color 'Don't rush, don't rush, uninstalling......')"
echo -e "$(random_color 'Uninstallation complete, old chapÏˆ(ï½€âˆ‡Â´)Ïˆï¼')"

     exit
     ;;

   4)

     # Exit script
     exit
     ;;

   3)

echo "$(random_color 'Below is your nekobox node information')"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
cd /root/hy3/

cat /root/hy3/neko.txt

echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "$(random_color 'Below is your clashmate configuration')"

cat /root/hy3/clash-mate.yaml

echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
     exit
     ;;
    
   5)

get_updated_version() {
    if [ -x "/root/hy3/hysteria-linux-$arch" ]; then
        version2="$("/root/hy3/hysteria-linux-$arch" version | grep Version | grep -o 'v[.0-9]*')"
    else
        version2="You haven't installed it yet, old chap"
    fi
}

updatehy2 () {
process_name="hysteria-linux-$arch"

pid=$(pgrep -f "$process_name")

if [ -n "$pid" ]; then
  echo "Found $process_name process (PID: $pid), killing..."
  kill "$pid"
  echo "$process_name process has been killed."
else
  echo "No $process_name process found."
fi

cd /root/hy3

rm -r hysteria-linux-$arch

if wget -O hysteria-linux-$arch https://download.hysteria.network/app/latest/hysteria-linux-$arch; then
  chmod +x hysteria-linux-$arch
else
  if wget -O hysteria-linux-$arch https://github.com/apernet/hysteria/releases/download/app/$latest_version/hysteria-linux-$arch; then
    chmod +x hysteria-linux-$arch
  else
    echo "Unable to download file from any website"
    exit 1
  fi
fi

systemctl stop hysteria.service
systemctl start hysteria.service

echo "Update complete, not bro, what strength do you have, you directly make me sit down(à¸‡ à¸·â–¿ à¸·)à¸§."
}
echo "$(random_color 'Updating, don't rush, old chap')"
sleep 1
updatehy2 > /dev/null 2>&1
echo "$(random_color 'Update complete, old chap')"
get_updated_version
echo "Your updated hy2 version:$version2"

      exit
      ;;

    6)

echo "Input 1 to start hy2 core, input 2 to stop hy2 core, input 3 to restart hy2 core"
read choicehy2
if [ "$choicehy2" = "1" ]; then
sudo systemctl start hysteria.service
echo "hy2 core started successfully"
elif [ "$choicehy2" = "2" ]; then
sudo systemctl stop hysteria.service
echo "hy2 core stopped successfully"
elif [ "$choicehy2" = "3" ]; then
sudo systemctl restart hysteria.service
echo "hy2 core restarted successfully"
else
  echo "Please enter correct option"
fi

      exit
      ;;


   7)

echo "Input y to install, input n to cancel, input o to uninstall (y/n/o)"
read answer
if [ "$answer" = "y" ]; then
check_sys
installxanmod2
elif [ "$answer" = "n" ]; then
  echo "Canceling and exiting..."
  exit 0
elif [ "$answer" = "o" ]; then
check_sys
detele_kernel_custom
else
  echo "Invalid input. Please enter y, n, or o."
fi
     exit
     ;;

   *)
     echo "$(random_color 'Invalid choice, exiting script.')"

     exit
     ;;

esac

echo "$(random_color 'Don't rush, don't rush, don't rush, old chap')"
sleep 1

if [ "$hy2zt" = "Running" ]; then
  echo "Hysteria is running, please uninstall first before installing."
  exit 1
else
  echo "Original god, start."
fi

uninstall_hysteria > /dev/null 2>&1

installhy2 () {
  cd /root
  mkdir -p ~/hy3
  cd ~/hy3

  REPO_URL="https://github.com/apernet/hysteria/releases"
  LATEST_RELEASE=$(curl -s $REPO_URL/latest | jq -r '.tag_name')
  DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/$LATEST_RELEASE/hysteria-linux-$arch"

  if wget -O hysteria-linux-$arch https://download.hysteria.network/app/latest/hysteria-linux-$arch; then
    chmod +x hysteria-linux-$arch
  else
    if wget -O hysteria-linux-$arch $DOWNLOAD_URL; then
      chmod +x hysteria-linux-$arch
    else
      echo "Unable to download file from any website"
      exit 1
    fi
  fi

  echo "Latest release version: $LATEST_RELEASE"
  echo "Download URL: $DOWNLOAD_URL"
}

echo "$(random_color 'Downloading, old chap( ï¾ŸÐ´ï¾Ÿ)ã¤Bye')"
sleep 1
installhy2 > /dev/null 2>&1

# Just writing a configuration file, you can modify it yourself, don't mess it up, it's fine
cat <<EOL > config.yaml
listen: :443



auth:
  type: password
  password: Se7RAuFZ8Lzg

masquerade:
  type: proxy
  file:
    dir: /www/masq
  proxy:
    url: https://news.ycombinator.com/
    rewriteHost: true
  string:
    content: hello stupid world
    headers:
      content-type: text/plain
      custom-stuff: ice cream so good
    statusCode: 200

bandwidth:
  up: 0 gbps
  down: 0 gbps

udpIdleTimeout: 90s

EOL

while true; do
    echo "$(random_color 'Please enter port number (leave blank defaults to 443, input 0 random 2000-60000, you can input 1-65630 to specify port number): ')"
    read -p "" port
  
    if [ -z "$port" ]; then
      port=443
    elif [ "$port" -eq 0 ]; then
      port=$((RANDOM % 58001 + 2000))
    elif ! [[ "$port" =~ ^[0-9]+$ ]]; then
      echo "$(random_color 'My animal friend, please enter numbers, please re-enter port number:')"
      continue
    fi
  
    while netstat -tuln | grep -q ":$port "; do
      echo "$(random_color 'Port is occupied, please re-enter port number:')"
      read -p "" port
    done
  
    if sed -i "s/443/$port/" config.yaml; then
      echo "$(random_color 'Port number set to:')" "$port"
    else
      echo "$(random_color 'Failed to replace port number, exiting script.')"
      exit 1
    fi
  

generate_certificate() {
    read -p "Please enter the domain name for the self-signed certificate (defaults to bing.com): " user_domain
    domain_name=${user_domain:-"bing.com"}
    if curl --output /dev/null --silent --head --fail "$domain_name"; then
        mkdir -p /etc/ssl/private
        openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) -keyout "/etc/ssl/private/$domain_name.key" -out "/etc/ssl/private/$domain_name.crt" -subj "/CN=$domain_name" -days 36500
        chmod 777 "/etc/ssl/private/$domain_name.key" "/etc/ssl/private/$domain_name.crt"
        echo -e "Self-signed certificate and private key have been generated!"
    else
        echo -e "Invalid domain name or domain name unavailable, please enter a valid domain name!"
        generate_certificate
    fi
}

read -p "Please choose certificate type (input 1 use ACME certificate, input 2 use self-signed certificate, enter defaults to acme certificate application): " cert_choice

if [ "$cert_choice" == "2" ]; then
    generate_certificate

    certificate_path="/etc/ssl/private/$domain_name.crt"
    private_key_path="/etc/ssl/private/$domain_name.key"

    echo -e "Certificate file saved to /etc/ssl/private/$domain_name.crt"
    echo -e "Private key file saved to /etc/ssl/private/$domain_name.key"

    temp_file=$(mktemp)
    echo -e "temp_file: $temp_file"
    sed '3i\tls:\n  cert: '"/etc/ssl/private/$domain_name.crt"'\n  key: '"/etc/ssl/private/$domain_name.key"'' /root/hy3/config.yaml > "$temp_file"
    mv "$temp_file" /root/hy3/config.yaml
    touch /root/hy3/ca
   #Added a small variable here
    ovokk="insecure=1&"
    choice1="true"
    echo -e "Certificate and key information written to /root/hy3/config.yaml file."
    
get_ipv4_info() {
  ip_address=$(wget -4 -qO- --no-check-certificate --user-agent=Mozilla --tries=2 --timeout=3 http://ip-api.com/json/) &&
  
  ispck=$(expr "$ip_address" : '.*isp\":[ ]*\"\([^"]*\).*')

  if echo "$ispck" | grep -qi "cloudflare"; then
    echo "Detected Warp, please enter the correct server IP:"
    read new_ip
    ipwan="$new_ip"
  else
    ipwan="$(expr "$ip_address" : '.*query\":[ ]*\"\([^"]*\).*')"
  fi
}

get_ipv6_info() {
  ip_address=$(wget -6 -qO- --no-check-certificate --user-agent=Mozilla --tries=2 --timeout=3 https://api.ip.sb/geoip) &&
  
  ispck=$(expr "$ip_address" : '.*isp\":[ ]*\"\([^"]*\).*')

  if echo "$ispck" | grep -qi "cloudflare"; then
    echo "Detected Warp, please enter the correct server IP:"
    read new_ip
    ipwan="[$new_ip]"
  else
    ipwan="[$(expr "$ip_address" : '.*ip\":[ ]*\"\([^"]*\).*')]"
  fi
}

while true; do
  echo "1. IPv4 mode"
  echo "2. IPv6 mode"
  echo "Press enter key to choose default IPv4 mode."

  read -p "Please choose: " choice

  case $choice in
    1)
      get_ipv4_info
      echo "Old chap your IP address is: $ipwan"
      ipta="iptables"
      break
      ;;
    2)
      get_ipv6_info
      echo "Old chap your IP address is: $ipwan"
      ipta="ip6tables"
      break
      ;;
    "")
      echo "Using default IPv4 mode."
      get_ipv4_info
      echo "Old chap your IP address is: $ipwan"
      ipta="iptables"
      break
      ;;
    *)
      echo "Invalid input. Please enter 1 or 2, or press enter to use default IPv4 mode."
      ;;
  esac
done

fi

if [ -f "/root/hy3/ca" ]; then
  echo "$(random_color '/root/hy3/ folder contains a file named ca. Skipping add operation.')"
else

  echo "$(random_color 'Please enter your domain name (must be a resolved domain name): ')"
  read -p "" domain

  while [ -z "$domain" ]; do
    echo "$(random_color 'Domain name cannot be empty, please re-enter: ')"
    read -p "" domain
  done


  echo "$(random_color 'Please enter your email (default random email): ')"
  read -p "" email

  if [ -z "$email" ]; then

    random_part=$(head /dev/urandom | LC_ALL=C tr -dc A-Za-z0-9 | head -c 6 ; echo '')

    email="${random_part}@gmail.com"
  fi

  if [ -f "config.yaml" ]; then
    echo -e "\nAppending to config.yaml..."
    sed -i '3i\acme:\n  domains:\n    - '$domain'\n  email: '$email'' config.yaml
    echo "$(random_color 'Domain name and email added to config.yaml file.')"
    ipta="iptables"
    choice2="false"
  else
    echo "$(random_color 'config.yaml file does not exist, cannot add.')"
    exit 1
  fi
fi

echo "Please choose an option:"
echo "1. Whether to enable dns certificate application method (default cloudflare application method, requires api token, email must be registered email)"
echo "2. Skip (Self-signed users and those who don't know this just press enter to skip by default)"

read -p "Please enter your choice (1 or 2): " choice

# If user directly presses enter, default to option 2
if [ -z "$choice" ]; then
    choice=2
fi

if [ "$choice" -eq 1 ]; then
    read -p "Please enter Cloudflare's API token: " api_key

    # Find the line number of the email line
    line_number=$(grep -n "email" /root/hy3/config.yaml | cut -d: -f1)

    if [ -z "$line_number" ]; then
        echo "Email line not found, please check configuration file."
        exit 1
    fi

    sed -i "${line_number}a\\
  type: dns\\
  dns:\\
    name: cloudflare\\
    config:\\
      cloudflare_api_token: $api_key" /root/hy3/config.yaml

    echo "Configuration successfully added to /root/hy3/config.yaml"
else
    echo "Skipping DNS configuration steps."
fi

echo "$(random_color 'Please enter your password (leave blank will generate random password, no more than 20 characters): ')"
read -p "" password

if [ -z "$password" ]; then
  password=$(openssl rand -base64 20 | tr -dc 'a-zA-Z0-9')
fi

if sed -i "s/Se7RAuFZ8Lzg/$password/" config.yaml; then
  echo "$(random_color 'Password set to:')" $password
else
  echo "$(random_color 'Failed to replace password, exiting script.')"
  exit 1
fi

echo "$(random_color 'Please enter masquerade URL (default https://news.ycombinator.com/): ')"
read -p "" masquerade_url

if [ -z "$masquerade_url" ]; then
  masquerade_url="https://news.ycombinator.com/"
fi

if sed -i "s|https://news.ycombinator.com/|$masquerade_url|" config.yaml; then
  echo "$(random_color 'Masquerade domain set to:')" $masquerade_url
else
  echo "$(random_color 'Failed to replace masquerade domain, exiting script.')"
  exit 1
fi
   
    echo "$(random_color 'Do you want to enable port jump function? If you don't know what it's for, forget it, no need to enable(à¸‡ à¸·â–¿ à¸·)à¸§ (Enter defaults to not enable, input 1 to enable): ')"
    read -p "" port_jump
  
    if [ -z "$port_jump" ]; then
      
      break
    elif [ "$port_jump" -eq 1 ]; then
    
      echo "$(random_color 'Please enter starting port number (starting port must be less than ending port): ')"
      read -p "" start_port
  
      echo "$(random_color 'Please enter ending port number (ending port must be greater than starting port): ')"
      read -p "" end_port
  
     if [ "$start_port" -lt "$end_port" ]; then

"$ipta" -t nat -A PREROUTING -i eth0 -p udp --dport "$start_port":"$end_port" -j DNAT --to-destination :"$port"
        echo "$(random_color 'Port jump function enabled, redirecting range to main port:')" "$port"
        break
      else
        echo "$(random_color 'Ending port must be greater than starting port, please re-enter.')"
      fi
    else
      echo "$(random_color 'Invalid input, please enter 1 to enable port jump function, or press enter directly to skip.')"
    fi
done

if [ -n "$port_jump" ] && [ "$port_jump" -eq 1 ]; then
  echo "#!/bin/bash" > /root/hy3/ipppp.sh
  echo "$ipta -t nat -A PREROUTING -i eth0 -p udp --dport $start_port:$end_port -j DNAT --to-destination :$port" >> /root/hy3/ipppp.sh
  
 
  chmod +x /root/hy3/ipppp.sh
  
  echo "[Unit]" > /etc/systemd/system/ipppp.service
  echo "Description=IP Port Redirect" >> /etc/systemd/system/ipppp.service
  echo "" >> /etc/systemd/system/ipppp.service
  echo "[Service]" >> /etc/systemd/system/ipppp.service
  echo "ExecStart=/root/hy3/ipppp.sh" >> /etc/systemd/system/ipppp.service
  echo "" >> /etc/systemd/system/ipppp.service
  echo "[Install]" >> /etc/systemd/system/ipppp.service
  echo "WantedBy=multi-user.target" >> /etc/systemd/system/ipppp.service
  
  # Enable service to start on boot
  systemctl enable ipppp.service
  
  # Start service
  systemctl start ipppp.service
  
  echo "$(random_color 'Created /ipppp.sh script file and set up auto-start.')"
fi

fuser -k -n udp $port

cat <<EOL > clash-mate.yaml
system-port: 7890
external-controller: 127.0.0.1:9090
allow-lan: false
mode: rule
log-level: info
ipv6: true
unified-delay: true
profile:
  store-selected: true
  store-fake-ip: true
tun:
  enable: true
  stack: system
  auto-route: true
  auto-detect-interface: true
dns:
  enable: true
  prefer-h3: true
  listen: 0.0.0.0:53
  enhanced-mode: fake-ip
  nameserver:
    - 223.5.5.5
    - 8.8.8.8
proxies:
  - name: Hysteria2
    type: hysteria2
    server: $domain$ipwan
    port: $port
    password: $password
    sni: $domain$domain_name
    skip-cert-verify: $choice1$choice2
proxy-groups:
  - name: auto
    type: select
    proxies:
      - Hysteria2
rules:
  - MATCH,auto
EOL
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "
clash-mate.yaml has been saved to current folder
"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"

if nohup ./hysteria-linux-$arch server & then
  echo "$(random_color '
  Hysteria server has started.')"
else
  echo "$(random_color 'Failed to start Hysteria server, exiting script.')"
  exit 1
fi
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
hysteria_directory="/root/hy3/"
hysteria_executable="/root/hy3/hysteria-linux-$arch"
hysteria_service_file="/etc/systemd/system/hysteria.service"

create_and_configure_service() {
  if [ -e "$hysteria_directory" ] && [ -e "$hysteria_executable" ]; then
    cat > "$hysteria_service_file" <<EOF
[Unit]
Description=My Hysteria Server

[Service]
Type=simple
WorkingDirectory=$hysteria_directory
ExecStart=$hysteria_executable server
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    echo "Hysteria server service file created and configured."
  else
    echo "Hysteria directory or executable file does not exist, please check path."
    exit 1
  fi
}

enable_and_start_service() {
  if [ -f "$hysteria_service_file" ]; then
    systemctl enable hysteria.service
    systemctl start hysteria.service
    echo "Hysteria server service enabled for auto-start and successfully started."
  else
    echo "Hysteria service file does not exist, please create and configure service file first."
    exit 1
  fi
}

create_and_configure_service
enable_and_start_service

echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "
Complete.
"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"

echo "$(random_color 'Old chap, immediately, immediately on------')"
sleep 2

echo "$(random_color '
This is your clash configuration:')"
cat /root/hy3/clash-mate.yaml

echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"

if [ -n "$start_port" ] && [ -n "$end_port" ]; then

  echo -e "$(random_color 'This is your Hysteria2 node link information, please save it joker (old chap, please use the latest version of neko): ')\nhysteria2://$password@$ipwan$domain:$port/?${ovokk}mport=$port,$start_port-$end_port&sni=$domain$domain_name#Hysteria2"
  
  echo "hysteria2://$password@$ipwan$domain:$port/?${ovokk}mport=$port,$start_port-$end_port&sni=$domain$domain_name#Hysteria2" > neko.txt
  
else

  echo -e "$(random_color 'This is your Hysteria2 node link information, please save it little buddy: ')\nhysteria2://$password@$ipwan$domain:$port/?${ovokk}sni=$domain$domain_name#Hysteria2"
  
  echo "hysteria2://$password@$ipwan$domain:$port/?${ovokk}sni=$domain$domain_name#Hysteria2" > neko.txt
  
fi

echo -e "$(random_color '

Hysteria2 installation successful, please use it reasonably, you straight--straight make me sit down')"
