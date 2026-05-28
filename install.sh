#!/bin/bash

# ==========================================

# EASETUP TOOLS

# ==========================================

clear

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# ==========================================

# ROOT CHECK

# ==========================================

if [[ $EUID -ne 0 ]]; then
echo -e "${RED}Please run as root!${NC}"
exit 1
fi

# ==========================================

# AUTO INSTALL DEPENDENCIES

# ==========================================

apt update -y >/dev/null 2>&1

for pkg in curl wget sudo nginx; do
if ! dpkg -s $pkg >/dev/null 2>&1; then
apt install -y $pkg >/dev/null 2>&1
fi
done

# ==========================================

# BANNER

# ==========================================

banner() {

clear

HOSTNAME=$(hostname)
OS=$(grep PRETTY_NAME /etc/os-release | cut -d '"' -f2)
RAM=$(free -h | awk '/Mem:/ {print $2}')
CPU=$(grep "model name" /proc/cpuinfo | head -1 | cut -d ":" -f2)
DISK=$(df -h / | awk 'NR==2 {print $3 " / " $2}')
UPTIME=$(uptime -p)

echo -e "${CYAN}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "          EASETUP TOOLS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${NC}"

echo -e "${GREEN}Hostname :${NC} $HOSTNAME"
echo -e "${GREEN}OS       :${NC} $OS"
echo -e "${GREEN}CPU      :${NC} $CPU"
echo -e "${GREEN}RAM      :${NC} $RAM"
echo -e "${GREEN}Disk     :${NC} $DISK"
echo -e "${GREEN}Uptime   :${NC} $UPTIME"

echo ""
}

# ==========================================

# RUN COMMAND

# ==========================================

run_cmd() {

echo ""
echo -e "${CYAN}[ INFO ]${NC} $2"
echo ""

bash -c "$1"

echo ""
echo -e "${GREEN}[ DONE ]${NC}"

read -p "Press enter to continue..."
}

# ==========================================

# HOSTING MENU

# ==========================================

hosting_menu() {

while true; do

banner

echo "========== HOSTING =========="
echo ""
echo "1. Install Pterodactyl"
echo "2. Install Minecraft"
echo "3. Host HTML Website"
echo "4. Setup Firewall"
echo "0. Back"
echo ""

read -p "Select: " hosting

case $hosting in

1.

run_cmd 
"bash <(curl -s https://pterodactyl-installer.se)" 
"Installing Pterodactyl"

;;

2.

run_cmd 
"curl -o install.sh https://minetrax.github.io/install.sh && chmod +x install.sh && bash install.sh" 
"Installing Minecraft Server"

;;

3.

echo ""
echo "Paste HTML below."
echo "Press CTRL+D when done."
echo ""

cat > /var/www/html/index.html

systemctl restart nginx

echo ""
echo -e "${GREEN}Website hosted successfully${NC}"

read -p "Press enter..."

;;

4.

run_cmd 
"ufw allow OpenSSH && ufw --force enable && apt install fail2ban -y" 
"Setting up firewall"

;;

0.

break

;;

*)

echo "Invalid option"
sleep 1

;;

esac

done
}

# ==========================================

# OPTIMIZATION MENU

# ==========================================

optimization_menu() {

while true; do

banner

echo "======= OPTIMIZATION ======="
echo ""
echo "1. Update System"
echo "2. Create 2GB Swap"
echo "3. Clean Logs"
echo "0. Back"
echo ""

read -p "Select: " opt

case $opt in

1.

run_cmd 
"apt update -y && apt upgrade -y" 
"Updating system"

;;

2.

run_cmd 
"fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile" 
"Creating swap"

;;

3.

run_cmd 
"journalctl --vacuum-time=3d" 
"Cleaning logs"

;;

0.

break

;;

*)

echo "Invalid option"
sleep 1

;;

esac

done
}

# ==========================================

# MONITOR MENU

# ==========================================

monitor_menu() {

while true; do

banner

echo "========== MONITOR =========="
echo ""
echo "1. Disk Usage"
echo "2. Open Ports"
echo "3. Running Services"
echo "0. Back"
echo ""

read -p "Select: " mon

case $mon in

1.

clear
df -h
read -p "Press enter..."

;;

2.

clear
ss -tuln
read -p "Press enter..."

;;

3.

clear
systemctl list-units --type=service
read -p "Press enter..."

;;

0.

break

;;

*)

echo "Invalid option"
sleep 1

;;

esac

done
}

# ==========================================

# INSTALLER MENU

# ==========================================

installer_menu() {

while true; do

banner

echo "========== INSTALLER =========="
echo ""
echo "1. Install Docker"
echo "2. Install NodeJS"
echo "3. Install Python"
echo "4. Install FULL PACK"
echo "0. Back"
echo ""

read -p "Select: " ins

case $ins in

1.

run_cmd 
"apt install docker.io docker-compose -y" 
"Installing Docker"

;;

2.

run_cmd 
"apt install nodejs npm -y" 
"Installing NodeJS"

;;

3.

run_cmd 
"apt install python3 python3-pip -y" 
"Installing Python"

;;

4.

run_cmd 
"apt install -y docker.io docker-compose nodejs npm python3 python3-pip git curl wget unzip htop nginx mysql-server" 
"Installing FULL PACK"

;;

0.

break

;;

*)

echo "Invalid option"
sleep 1

;;

esac

done
}

# ==========================================

# MAIN MENU

# ==========================================

while true; do

banner

echo "=========== MAIN MENU ==========="
echo ""
echo "1. Setup Hosting"
echo "2. Server Optimization"
echo "3. Monitoring"
echo "4. Installer"
echo "0. Exit"
echo ""

read -p "Select: " menu

case $menu in

1.

hosting_menu

;;

2.

optimization_menu

;;

3.

monitor_menu

;;

4.

installer_menu

;;

0.

clear

echo ""
echo -e "${GREEN}Thanks for using Easetup!${NC}"
echo ""

exit

;;

*)

echo "Invalid option"
sleep 1

;;

esac

done
#!/bin/bash

# ==========================================

# EASETUP TOOLS

# ==========================================

clear

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# ==========================================

# ROOT CHECK

# ==========================================

if [[ $EUID -ne 0 ]]; then
echo -e "${RED}Please run as root!${NC}"
exit 1
fi

# ==========================================

# AUTO INSTALL DEPENDENCIES

# ==========================================

apt update -y >/dev/null 2>&1

for pkg in curl wget sudo nginx; do
if ! dpkg -s $pkg >/dev/null 2>&1; then
apt install -y $pkg >/dev/null 2>&1
fi
done

# ==========================================

# BANNER

# ==========================================

banner() {

clear

HOSTNAME=$(hostname)
OS=$(grep PRETTY_NAME /etc/os-release | cut -d '"' -f2)
RAM=$(free -h | awk '/Mem:/ {print $2}')
CPU=$(grep "model name" /proc/cpuinfo | head -1 | cut -d ":" -f2)
DISK=$(df -h / | awk 'NR==2 {print $3 " / " $2}')
UPTIME=$(uptime -p)

echo -e "${CYAN}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "          EASETUP TOOLS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${NC}"

echo -e "${GREEN}Hostname :${NC} $HOSTNAME"
echo -e "${GREEN}OS       :${NC} $OS"
echo -e "${GREEN}CPU      :${NC} $CPU"
echo -e "${GREEN}RAM      :${NC} $RAM"
echo -e "${GREEN}Disk     :${NC} $DISK"
echo -e "${GREEN}Uptime   :${NC} $UPTIME"

echo ""
}

# ==========================================

# RUN COMMAND

# ==========================================

run_cmd() {

echo ""
echo -e "${CYAN}[ INFO ]${NC} $2"
echo ""

bash -c "$1"

echo ""
echo -e "${GREEN}[ DONE ]${NC}"

read -p "Press enter to continue..."
}

# ==========================================

# HOSTING MENU

# ==========================================

hosting_menu() {

while true; do

banner

echo "========== HOSTING =========="
echo ""
echo "1. Install Pterodactyl"
echo "2. Install Minecraft"
echo "3. Host HTML Website"
echo "4. Setup Firewall"
echo "0. Back"
echo ""

read -p "Select: " hosting

case $hosting in

1.

run_cmd 
"bash <(curl -s https://pterodactyl-installer.se)" 
"Installing Pterodactyl"

;;

2.

run_cmd 
"curl -o install.sh https://minetrax.github.io/install.sh && chmod +x install.sh && bash install.sh" 
"Installing Minecraft Server"

;;

3.

echo ""
echo "Paste HTML below."
echo "Press CTRL+D when done."
echo ""

cat > /var/www/html/index.html

systemctl restart nginx

echo ""
echo -e "${GREEN}Website hosted successfully${NC}"

read -p "Press enter..."

;;

4.

run_cmd 
"ufw allow OpenSSH && ufw --force enable && apt install fail2ban -y" 
"Setting up firewall"

;;

0.

break

;;

*)

echo "Invalid option"
sleep 1

;;

esac

done
}

# ==========================================

# OPTIMIZATION MENU

# ==========================================

optimization_menu() {

while true; do

banner

echo "======= OPTIMIZATION ======="
echo ""
echo "1. Update System"
echo "2. Create 2GB Swap"
echo "3. Clean Logs"
echo "0. Back"
echo ""

read -p "Select: " opt

case $opt in

1.

run_cmd 
"apt update -y && apt upgrade -y" 
"Updating system"

;;

2.

run_cmd 
"fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile" 
"Creating swap"

;;

3.

run_cmd 
"journalctl --vacuum-time=3d" 
"Cleaning logs"

;;

0.

break

;;

*)

echo "Invalid option"
sleep 1

;;

esac

done
}

# ==========================================

# MONITOR MENU

# ==========================================

monitor_menu() {

while true; do

banner

echo "========== MONITOR =========="
echo ""
echo "1. Disk Usage"
echo "2. Open Ports"
echo "3. Running Services"
echo "0. Back"
echo ""

read -p "Select: " mon

case $mon in

1.

clear
df -h
read -p "Press enter..."

;;

2.

clear
ss -tuln
read -p "Press enter..."

;;

3.

clear
systemctl list-units --type=service
read -p "Press enter..."

;;

0.

break

;;

*)

echo "Invalid option"
sleep 1

;;

esac

done
}

# ==========================================

# INSTALLER MENU

# ==========================================

installer_menu() {

while true; do

banner

echo "========== INSTALLER =========="
echo ""
echo "1. Install Docker"
echo "2. Install NodeJS"
echo "3. Install Python"
echo "4. Install FULL PACK"
echo "0. Back"
echo ""

read -p "Select: " ins

case $ins in

1.

run_cmd 
"apt install docker.io docker-compose -y" 
"Installing Docker"

;;

2.

run_cmd 
"apt install nodejs npm -y" 
"Installing NodeJS"

;;

3.

run_cmd 
"apt install python3 python3-pip -y" 
"Installing Python"

;;

4.

run_cmd 
"apt install -y docker.io docker-compose nodejs npm python3 python3-pip git curl wget unzip htop nginx mysql-server" 
"Installing FULL PACK"

;;

0.

break

;;

*)

echo "Invalid option"
sleep 1

;;

esac

done
}

# ==========================================

# MAIN MENU

# ==========================================

while true; do

banner

echo "=========== MAIN MENU ==========="
echo ""
echo "1. Setup Hosting"
echo "2. Server Optimization"
echo "3. Monitoring"
echo "4. Installer"
echo "0. Exit"
echo ""

read -p "Select: " menu

case $menu in

1.

hosting_menu

;;

2.

optimization_menu

;;

3.

monitor_menu

;;

4.

installer_menu

;;

0.

clear

echo ""
echo -e "${GREEN}Thanks for using Easetup!${NC}"
echo ""

exit

;;

*)

echo "Invalid option"
sleep 1

;;

esac

done
