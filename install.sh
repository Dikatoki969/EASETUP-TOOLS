```bash
#!/bin/bash

# =========================================
# EASETUP TOOLS - FULL SHELL VERSION
# =========================================

clear

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# =========================================
# ROOT CHECK
# =========================================

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Run this script as root!${NC}"
   exit 1
fi

# =========================================
# AUTO INSTALL DEPENDENCIES
# =========================================

apt update -y >/dev/null 2>&1

for pkg in curl wget sudo nano ufw; do
    if ! dpkg -s $pkg >/dev/null 2>&1; then
        apt install -y $pkg >/dev/null 2>&1
    fi
done

# =========================================
# DEVICE INFO
# =========================================

show_banner() {

clear

HOSTNAME=$(hostname)
OS=$(grep PRETTY_NAME /etc/os-release | cut -d '"' -f2)
KERNEL=$(uname -r)
CPU=$(grep "model name" /proc/cpuinfo | head -1 | cut -d ":" -f2)
RAM=$(free -h | awk '/Mem:/ {print $2}')
DISK=$(df -h / | awk 'NR==2 {print $3 " / " $2}')
UPTIME=$(uptime -p)

echo -e "${CYAN}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "             EASETUP TOOLS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${NC}"

echo -e "${GREEN}Hostname :${NC} $HOSTNAME"
echo -e "${GREEN}OS       :${NC} $OS"
echo -e "${GREEN}Kernel   :${NC} $KERNEL"
echo -e "${GREEN}CPU      :${NC} $CPU"
echo -e "${GREEN}RAM      :${NC} $RAM"
echo -e "${GREEN}Disk     :${NC} $DISK"
echo -e "${GREEN}Uptime   :${NC} $UPTIME"

echo ""
echo -e "${YELLOW}Use this tool carefully.${NC}"
echo ""
}

# =========================================
# LOADING
# =========================================

loading() {
echo -ne "${CYAN}Loading"

for i in {1..5}; do
    echo -ne "."
    sleep 0.3
done

echo -e "${NC}"
}

# =========================================
# COMMAND RUNNER
# =========================================

run_cmd() {

echo ""
echo -e "${CYAN}[ INFO ]${NC} $2"
echo ""

bash -c "$1"

echo ""
echo -e "${GREEN}[ DONE ]${NC}"
sleep 1
}

# =========================================
# HOSTING MENU
# =========================================

hosting_menu() {

while true; do

clear

echo -e "${CYAN}========== HOSTING MENU ==========${NC}"
echo ""
echo "1. Install Minecraft Server"
echo "2. Install Pterodactyl Panel"
echo "3. Install Rust Server"
echo "4. Host HTML Website"
echo "5. Setup Domain & SSL"
echo "6. Setup DDoS Firewall"
echo "0. Back"
echo ""

read -p "Select option: " host

case $host in

1)
run_cmd \
"curl -o ~/install.sh https://minetrax.github.io/install.sh && chmod +x ~/install.sh && bash ~/install.sh" \
"Installing Minecraft Server"
;;

2)
run_cmd \
"bash <(curl -s https://pterodactyl-installer.se)" \
"Installing Pterodactyl Panel"
;;

3)
run_cmd \
"curl -s https://rustserverinstaller.com/install.sh | bash" \
"Installing Rust Server"
;;

4)
echo ""
echo "Paste HTML below."
echo "Press CTRL+D when finished."
echo ""

cat > /var/www/html/index.html

systemctl restart nginx

echo ""
echo -e "${GREEN}Website hosted in /var/www/html/index.html${NC}"
read -p "Press enter..."
;;

5)

read -p "Enter domain: " domain

cat > /etc/nginx/sites-available/$domain << EOF
server {
    listen 80;
    server_name $domain;

    root /var/www/html;
    index index.html;
}
EOF

ln -sf /etc/nginx/sites-available/$domain /etc/nginx/sites-enabled/

nginx -t && systemctl reload nginx

certbot --nginx -d $domain

;;

6)

run_cmd \
"ufw allow OpenSSH && ufw --force enable && apt install fail2ban -y" \
"Setting up Firewall & Fail2Ban"

;;

0)
break
;;

*)
echo "Invalid option"
sleep 1
;;

esac

done
}

# =========================================
# OPTIMIZATION MENU
# =========================================

optimization_menu() {

while true; do

clear

echo -e "${CYAN}======= SERVER OPTIMIZATION =======${NC}"
echo ""
echo "1. Auto sysctl Optimize"
echo "2. Create 2GB Swap"
echo "3. Clean Logs"
echo "4. Update System"
echo "0. Back"
echo ""

read -p "Select option: " opt

case $opt in

1)

run_cmd \
"echo 'net.core.somaxconn=65535' >> /etc/sysctl.conf && sysctl -p" \
"Optimizing sysctl"

;;

2)

run_cmd \
"fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile" \
"Creating swap"

;;

3)

run_cmd \
"journalctl --vacuum-time=3d" \
"Cleaning logs"

;;

4)

run_cmd \
"apt update -y && apt upgrade -y" \
"Updating system"

;;

0)
break
;;

*)
echo "Invalid option"
sleep 1
;;

esac

done
}

# =========================================
# MONITORING MENU
# =========================================

monitoring_menu() {

while true; do

clear

echo -e "${CYAN}========== MONITORING ==========${NC}"
echo ""
echo "1. CPU & RAM Usage"
echo "2. Disk Usage"
echo "3. Open Ports"
echo "4. Running Services"
echo "0. Back"
echo ""

read -p "Select option: " mon

case $mon in

1)

clear

echo ""
top
;;

2)

clear

df -h

read -p "Press enter..."
;;

3)

clear

ss -tuln

read -p "Press enter..."
;;

4)

clear

systemctl list-units --type=service

read -p "Press enter..."
;;

0)
break
;;

*)
echo "Invalid option"
sleep 1
;;

esac

done
}

# =========================================
# SECURITY MENU
# =========================================

security_menu() {

while true; do

clear

echo -e "${CYAN}=========== SECURITY ===========${NC}"
echo ""
echo "1. Setup UFW Firewall"
echo "2. Install Fail2Ban"
echo "3. Disable Root Login"
echo "4. SSH Hardening"
echo "5. Install ClamAV"
echo "0. Back"
echo ""

read -p "Select option: " sec

case $sec in

1)

run_cmd \
"ufw allow OpenSSH && ufw --force enable" \
"Configuring Firewall"

;;

2)

run_cmd \
"apt install fail2ban -y && systemctl enable fail2ban && systemctl start fail2ban" \
"Installing Fail2Ban"

;;

3)

run_cmd \
"sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart ssh" \
"Disabling root login"

;;

4)

read -p "Enter new SSH port: " port

run_cmd \
"sed -i 's/#Port 22/Port $port/' /etc/ssh/sshd_config && systemctl restart ssh" \
"Changing SSH port"

;;

5)

run_cmd \
"apt install clamav -y && freshclam" \
"Installing ClamAV"

;;

0)
break
;;

*)
echo "Invalid option"
sleep 1
;;

esac

done
}

# =========================================
# INSTALLER MENU
# =========================================

installer_menu() {

while true; do

clear

echo -e "${CYAN}=========== INSTALLER ===========${NC}"
echo ""
echo "1. Install Essential Tools"
echo "2. Install Docker"
echo "3. Install Web Stack"
echo "4. Install Dev Tools"
echo "5. Install Full Pack"
echo "0. Back"
echo ""

read -p "Select option: " ins

case $ins in

1)

run_cmd \
"apt install -y curl wget git unzip htop nano vim net-tools" \
"Installing Essential Tools"

;;

2)

run_cmd \
"apt install -y docker.io docker-compose" \
"Installing Docker"

;;

3)

run_cmd \
"apt install -y nginx php php-fpm mysql-server redis-server" \
"Installing Web Stack"

;;

4)

run_cmd \
"apt install -y nodejs npm python3 python3-pip gcc g++ make" \
"Installing Dev Tools"

;;

5)

run_cmd \
"apt install -y curl wget git unzip htop nano vim net-tools nginx php mysql-server redis-server docker.io docker-compose nodejs npm python3 python3-pip gcc g++ make" \
"Installing FULL PACK"

;;

0)
break
;;

*)
echo "Invalid option"
sleep 1
;;

esac

done
}

# =========================================
# MAIN MENU
# =========================================

main_menu() {

while true; do

show_banner

echo -e "${CYAN}============= MAIN MENU =============${NC}"
echo ""
echo "1. Setup Hosting"
echo "2. Server Optimization"
echo "3. Monitoring"
echo "4. Security"
echo "5. Installer"
echo "0. Exit"
echo ""

read -p "Select option: " menu

case $menu in

1)
hosting_menu
;;

2)
optimization_menu
;;

3)
monitoring_menu
;;

4)
security_menu
;;

5)
installer_menu
;;

0)

clear

echo ""
echo -e "${GREEN}Bye!${NC}"
echo ""

exit
;;

*)

echo "Invalid option"
sleep 1
;;

esac

done
}

loading
main_menu
```
