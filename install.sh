#!/bin/bash

# ============================================================================
# EASETUP TOOLS - Professional VPS Installer & Management System
# ============================================================================

set -e

# Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;36m'
PURPLE='\033[0;35m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
NC='\033[0m'

# Spinner Characters
SPINNER=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
SPINNER_IDX=0

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

spinner() {
    local pid=$1
    local delay=0.1
    while kill -0 $pid 2>/dev/null; do
        printf "\r${BLUE}${SPINNER[$SPINNER_IDX]}${NC} "
        SPINNER_IDX=$(( (SPINNER_IDX + 1) % 10 ))
        sleep $delay
    done
    printf "\r"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

print_separator() {
    echo -e "${GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

run_cmd() {
    local cmd=$1
    local desc=$2
    
    echo -ne "${BLUE}▶${NC} $desc... "
    
    if output=$(eval "$cmd" 2>&1); then
        log_success "Selesai"
        return 0
    else
        log_error "Gagal"
        echo "$output"
        return 1
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Script ini harus dijalankan sebagai root!"
        exit 1
    fi
}

check_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        log_error "Sistem operasi tidak didukung"
        exit 1
    fi
    
    if [[ ! "$OS" =~ "Ubuntu"|"Debian" ]]; then
        log_warning "OS ini mungkin tidak fully support, tapi akan coba..."
    fi
}

clear_screen() {
    clear
}

press_enter() {
    echo ""
    echo -e "${GRAY}Tekan ENTER untuk melanjutkan...${NC}"
    read
}

# ============================================================================
# SYSTEM INFO FUNCTIONS
# ============================================================================

get_system_info() {
    HOSTNAME=$(hostname)
    KERNEL=$(uname -r)
    UPTIME=$(uptime -p 2>/dev/null || uptime | awk -F'up' '{print $2}' | cut -d',' -f1)
    CPU_CORES=$(nproc)
    CPU_MODEL=$(grep "model name" /proc/cpuinfo | head -1 | cut -d':' -f2 | xargs)
    RAM_TOTAL=$(free -h | grep Mem | awk '{print $2}')
    RAM_USED=$(free -h | grep Mem | awk '{print $3}')
    DISK_TOTAL=$(df -h / | tail -1 | awk '{print $2}')
    DISK_USED=$(df -h / | tail -1 | awk '{print $3}')
    DISK_PERCENT=$(df -h / | tail -1 | awk '{print $5}')
}

show_banner() {
    clear_screen
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                  EASETUP TOOLS INSTALLER                   ║"
    echo "║              Professional VPS Management Suite              ║"
    echo "╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

show_device_info() {
    show_banner
    
    get_system_info
    
    echo -e "${PURPLE}┌─ DEVICE INFORMATION ─────────────────────────────┐${NC}"
    echo -e "${PURPLE}│${NC} ${BLUE}🖥  Hostname    :${NC} $HOSTNAME"
    echo -e "${PURPLE}│${NC} ${BLUE}🐧 OS           :${NC} $OS $VER"
    echo -e "${PURPLE}│${NC} ${BLUE}🔧 Kernel       :${NC} $KERNEL"
    echo -e "${PURPLE}│${NC} ${BLUE}⚙️  CPU          :${NC} $CPU_CORES cores - $CPU_MODEL"
    echo -e "${PURPLE}│${NC} ${BLUE}📊 RAM          :${NC} $RAM_USED / $RAM_TOTAL"
    echo -e "${PURPLE}│${NC} ${BLUE}💾 Disk         :${NC} $DISK_USED / $DISK_TOTAL ($DISK_PERCENT)"
    echo -e "${PURPLE}│${NC} ${BLUE}⏱  Uptime       :${NC} $UPTIME"
    echo -e "${PURPLE}└───────────────────────────────────────────────────┘${NC}"
    echo ""
}

# ============================================================================
# MENU FUNCTIONS
# ============================================================================

show_main_menu() {
    show_device_info
    
    echo -e "${BLUE}┌─ MAIN MENU ───────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│${NC}"
    echo -e "${BLUE}│${NC}  ${GREEN}[1]${NC} ${WHITE}🌐 Hosting${NC}"
    echo -e "${BLUE}│${NC}  ${GREEN}[2]${NC} ${WHITE}⚡ Optimization${NC}"
    echo -e "${BLUE}│${NC}  ${GREEN}[3]${NC} ${WHITE}📊 Monitoring${NC}"
    echo -e "${BLUE}│${NC}  ${GREEN}[4]${NC} ${WHITE}🛡  Security${NC}"
    echo -e "${BLUE}│${NC}  ${GREEN}[5]${NC} ${WHITE}📦 Installer${NC}"
    echo -e "${BLUE}│${NC}  ${GREEN}[0]${NC} ${WHITE}Exit${NC}"
    echo -e "${BLUE}│${NC}"
    echo -e "${BLUE}└───────────────────────────────────────────────────┘${NC}"
    echo -ne "${BLUE}▶${NC} Pilih menu: "
}

# ============================================================================
# HOSTING MENU
# ============================================================================

hosting_install_pterodactyl() {
    log_info "Memulai instalasi Pterodactyl Panel..."
    
    run_cmd "apt-get update" "Update package manager" || true
    run_cmd "apt-get install -y curl wget" "Install dependencies" || true
    
    echo -e "${YELLOW}Pastikan Anda sudah mempersiapkan:${NC}"
    echo "  • Domain yang sudah di-pointing ke server ini"
    echo "  • SSL certificate (opsional, akan di-generate otomatis)"
    echo "  • Versi PHP yang sesuai"
    echo ""
    echo -e "${BLUE}Silakan ikuti dokumentasi resmi di:${NC}"
    echo "https://pterodactyl.io/project/introduction.html"
    
    press_enter
}

hosting_install_minecraft() {
    log_info "Memulai setup Minecraft Server..."
    
    run_cmd "apt-get update" "Update package manager" || true
    run_cmd "apt-get install -y openjdk-17-jre-headless wget" "Install Java & dependencies" && log_success "Java terinstall"
    
    echo -ne "${BLUE}▶${NC} Masukkan direktori instalasi (default: /opt/minecraft): "
    read MC_DIR
    MC_DIR=${MC_DIR:-/opt/minecraft}
    
    mkdir -p "$MC_DIR"
    cd "$MC_DIR"
    
    log_info "Download server jar..."
    wget -q https://launcher.mojang.com/v1/objects/886711d5eac54b2bf3eab5d7364f98b5c89b0c81/server.jar -O server.jar || {
        log_error "Download gagal, cek koneksi internet"
        return 1
    }
    
    echo "eula=true" > eula.txt
    
    log_success "Minecraft Server terinstall di $MC_DIR"
    echo -e "${BLUE}Jalankan server dengan: ${NC}cd $MC_DIR && java -Xmx30G -Xms30G -jar server.jar nogui"
    
    press_enter
}

hosting_host_website() {
    log_info "Setup hosting website..."
    
    run_cmd "apt-get update && apt-get install -y nginx" "Install Nginx" || true
    run_cmd "systemctl start nginx && systemctl enable nginx" "Enable Nginx" && log_success "Nginx berjalan"
    
    echo -ne "${BLUE}▶${NC} Masukkan nama domain: "
    read DOMAIN
    
    mkdir -p /var/www/$DOMAIN/html
    
    cat > /etc/nginx/sites-available/$DOMAIN <<EOF
server {
    listen 80;
    server_name $DOMAIN www.$DOMAIN;
    
    root /var/www/$DOMAIN/html;
    index index.html index.htm;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
    
    ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/$DOMAIN
    run_cmd "nginx -t" "Test Nginx config" || true
    run_cmd "systemctl reload nginx" "Reload Nginx" && log_success "Website siap di /var/www/$DOMAIN/html"
    
    press_enter
}

hosting_ssl_setup() {
    log_info "Setup SSL Certificate dengan Certbot..."
    
    run_cmd "apt-get install -y certbot python3-certbot-nginx" "Install Certbot" || true
    
    echo -ne "${BLUE}▶${NC} Masukkan email untuk SSL notifications: "
    read EMAIL
    
    echo -ne "${BLUE}▶${NC} Masukkan nama domain: "
    read DOMAIN
    
    run_cmd "certbot certonly --nginx -d $DOMAIN -d www.$DOMAIN --non-interactive --agree-tos -m $EMAIL" "Generate SSL Certificate" && log_success "SSL Certificate berhasil"
    
    press_enter
}

hosting_ddos_protection() {
    log_info "Setup DDoS Protection..."
    
    run_cmd "apt-get install -y fail2ban ufw" "Install proteksi tools" || true
    
    log_success "Fail2Ban dan UFW terinstall. Konfigurasi dilakukan di menu Security"
    
    press_enter
}

show_hosting_menu() {
    clear_screen
    show_banner
    
    echo -e "${PURPLE}┌─ HOSTING MENU ────────────────────────────────────┐${NC}"
    echo -e "${PURPLE}│${NC}"
    echo -e "${PURPLE}│${NC}  ${GREEN}[1]${NC} Install Pterodactyl Panel"
    echo -e "${PURPLE}│${NC}  ${GREEN}[2]${NC} Install Minecraft Server"
    echo -e "${PURPLE}│${NC}  ${GREEN}[3]${NC} Host HTML Website"
    echo -e "${PURPLE}│${NC}  ${GREEN}[4]${NC} Domain & SSL Setup"
    echo -e "${PURPLE}│${NC}  ${GREEN}[5]${NC} DDoS Protection Setup"
    echo -e "${PURPLE}│${NC}  ${GREEN}[0]${NC} Back to Main Menu"
    echo -e "${PURPLE}│${NC}"
    echo -e "${PURPLE}└───────────────────────────────────────────────────┘${NC}"
    echo -ne "${BLUE}▶${NC} Pilih opsi: "
}

# ============================================================================
# OPTIMIZATION MENU
# ============================================================================

optimization_login_theme() {
    log_info "Mengatur login theme..."
    
    cat > /etc/issue <<'EOF'

 ███████╗ █████╗ ███████╗███████╗████████╗██╗   ██╗██████╗ 
 ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██║   ██║██╔══██╗
 █████╗  ███████║███████╗███████╗   ██║   ██║   ██║██████╔╝
 ██╔══╝  ██╔══██║╚════██║╚════██║   ██║   ██║   ██║██╔═══╝ 
 ███████╗██║  ██║███████║███████║   ██║   ╚██████╔╝██║     
 ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝     

 Professional VPS Management System
 Hostname: \n
 IP Address: \4

EOF
    
    log_success "Login theme diatur"
    press_enter
}

optimization_system_update() {
    log_info "Melakukan system update..."
    
    run_cmd "apt-get update" "Update package list" || true
    run_cmd "apt-get upgrade -y" "Upgrade packages" && log_success "System update selesai"
    
    press_enter
}

optimization_sysctl() {
    log_info "Mengoptimalkan sysctl parameters..."
    
    cat >> /etc/sysctl.conf <<'EOF'

# Network Optimization
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.core.netdev_max_backlog=5000
net.ipv4.tcp_max_syn_backlog=5000
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=30
EOF
    
    run_cmd "sysctl -p" "Apply sysctl config" && log_success "Sysctl optimization selesai"
    
    press_enter
}

optimization_swap_creation() {
    log_info "Membuat swap file..."
    
    echo -ne "${BLUE}▶${NC} Ukuran swap (GB, default: 4): "
    read SWAP_SIZE
    SWAP_SIZE=${SWAP_SIZE:-4}
    
    SWAP_BYTES=$((SWAP_SIZE * 1024 * 1024 * 1024))
    
    run_cmd "fallocate -l ${SWAP_SIZE}G /swapfile" "Create swap file" || true
    run_cmd "chmod 600 /swapfile" "Set permissions" || true
    run_cmd "mkswap /swapfile" "Setup swap" || true
    run_cmd "swapon /swapfile" "Enable swap" && log_success "Swap ${SWAP_SIZE}GB siap"
    
    grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    
    press_enter
}

optimization_log_cleaner() {
    log_info "Membersihkan log files..."
    
    run_cmd "find /var/log -type f -name '*.gz' -delete" "Remove gz logs" || true
    run_cmd "find /var/log -type f -name '*.1' -delete" "Remove old logs" || true
    run_cmd "truncate -s 0 /var/log/*/*.log" "Clear log files" && log_success "Log files dibersihkan"
    
    press_enter
}

show_optimization_menu() {
    clear_screen
    show_banner
    
    echo -e "${PURPLE}┌─ OPTIMIZATION MENU ───────────────────────────────┐${NC}"
    echo -e "${PURPLE}│${NC}"
    echo -e "${PURPLE}│${NC}  ${GREEN}[1]${NC} Login Theme Customization"
    echo -e "${PURPLE}│${NC}  ${GREEN}[2]${NC} System Update"
    echo -e "${PURPLE}│${NC}  ${GREEN}[3]${NC} Sysctl Optimization"
    echo -e "${PURPLE}│${NC}  ${GREEN}[4]${NC} Swap Creation"
    echo -e "${PURPLE}│${NC}  ${GREEN}[5]${NC} Log Cleaner"
    echo -e "${PURPLE}│${NC}  ${GREEN}[0]${NC} Back to Main Menu"
    echo -e "${PURPLE}│${NC}"
    echo -e "${PURPLE}└───────────────────────────────────────────────────┘${NC}"
    echo -ne "${BLUE}▶${NC} Pilih opsi: "
}

# ============================================================================
# MONITORING MENU
# ============================================================================

monitoring_disk_usage() {
    clear_screen
    show_banner
    
    echo -e "${PURPLE}┌─ DISK USAGE ───────────────────────────────────────┐${NC}"
    df -h | tail -n +2 | while read line; do
        echo -e "${PURPLE}│${NC} $line"
    done
    echo -e "${PURPLE}└────────────────────────────────────────────────────┘${NC}"
    
    press_enter
}

monitoring_open_ports() {
    clear_screen
    show_banner
    
    echo -e "${PURPLE}┌─ OPEN PORTS ───────────────────────────────────────┐${NC}"
    
    if command -v netstat &> /dev/null; then
        netstat -tuln | grep LISTEN | while read line; do
            echo -e "${PURPLE}│${NC} $line"
        done
    elif command -v ss &> /dev/null; then
        ss -tuln | grep LISTEN | while read line; do
            echo -e "${PURPLE}│${NC} $line"
        done
    fi
    
    echo -e "${PURPLE}└────────────────────────────────────────────────────┘${NC}"
    
    press_enter
}

monitoring_running_services() {
    clear_screen
    show_banner
    
    echo -e "${PURPLE}┌─ RUNNING SERVICES ────────────────────────────────┐${NC}"
    systemctl list-units --type=service --state=running | head -20 | while read line; do
        echo -e "${PURPLE}│${NC} $line"
    done
    echo -e "${PURPLE}└────────────────────────────────────────────────────┘${NC}"
    
    press_enter
}

monitoring_live_monitoring() {
    clear_screen
    show_banner
    
    echo -e "${PURPLE}Live System Monitoring (Ctrl+C untuk exit)${NC}"
    echo ""
    
    while true; do
        clear_screen
        show_device_info
        
        echo -e "${BLUE}TOP 5 PROCESSES:${NC}"
        ps aux --sort=-%mem | head -6 | tail -5 | while read line; do
            echo "  $line"
        done
        
        echo ""
        sleep 2
    done
}

show_monitoring_menu() {
    clear_screen
    show_banner
    
    echo -e "${PURPLE}┌─ MONITORING MENU ─────────────────────────────────┐${NC}"
    echo -e "${PURPLE}│${NC}"
    echo -e "${PURPLE}│${NC}  ${GREEN}[1]${NC} Disk Usage"
    echo -e "${PURPLE}│${NC}  ${GREEN}[2]${NC} Open Ports"
    echo -e "${PURPLE}│${NC}  ${GREEN}[3]${NC} Running Services"
    echo -e "${PURPLE}│${NC}  ${GREEN}[4]${NC} Live Monitoring"
    echo -e "${PURPLE}│${NC}  ${GREEN}[0]${NC} Back to Main Menu"
    echo -e "${PURPLE}│${NC}"
    echo -e "${PURPLE}└───────────────────────────────────────────────────┘${NC}"
    echo -ne "${BLUE}▶${NC} Pilih opsi: "
}

# ============================================================================
# SECURITY MENU
# ============================================================================

security_firewall_setup() {
    log_info "Mengatur UFW Firewall..."
    
    run_cmd "apt-get install -y ufw" "Install UFW" || true
    run_cmd "ufw reset --force" "Reset UFW" || true
    run_cmd "ufw default deny incoming" "Set default deny" || true
    run_cmd "ufw default allow outgoing" "Set default allow outgoing" || true
    run_cmd "ufw allow 22/tcp" "Allow SSH" || true
    run_cmd "ufw allow 80/tcp" "Allow HTTP" || true
    run_cmd "ufw allow 443/tcp" "Allow HTTPS" || true
    run_cmd "echo 'y' | ufw enable" "Enable UFW" && log_success "Firewall aktif"
    
    press_enter
}

security_fail2ban_setup() {
    log_info "Mengatur Fail2Ban..."
    
    run_cmd "apt-get install -y fail2ban" "Install Fail2Ban" || true
    
    cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
EOF
    
    run_cmd "systemctl restart fail2ban" "Restart Fail2Ban" && log_success "Fail2Ban aktif"
    
    press_enter
}

security_ssh_hardening() {
    log_info "Hardening SSH..."
    
    sed -i 's/#Port 22/Port 22/' /etc/ssh/sshd_config
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
    
    run_cmd "sshd -t" "Test SSH config" && log_success "SSH config valid"
    run_cmd "systemctl restart sshd" "Restart SSH" && log_success "SSH hardening selesai"
    
    press_enter
}

security_disable_root_login() {
    log_info "Menonaktifkan root login..."
    
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    run_cmd "systemctl restart sshd" "Restart SSH" && log_success "Root login dinonaktifkan"
    
    press_enter
}

security_clamav_scanner() {
    log_info "Install ClamAV Antivirus..."
    
    run_cmd "apt-get install -y clamav clamav-daemon" "Install ClamAV" || true
    run_cmd "freshclam" "Update virus database" || true
    run_cmd "systemctl start clamav-daemon" "Start ClamAV" && log_success "ClamAV siap"
    
    echo -e "${BLUE}Scan dengan: ${NC}clamscan -r /path/to/scan"
    
    press_enter
}

show_security_menu() {
    clear_screen
    show_banner
    
    echo -e "${PURPLE}┌─ SECURITY MENU ───────────────────────────────────┐${NC}"
    echo -e "${PURPLE}│${NC}"
    echo -e "${PURPLE}│${NC}  ${GREEN}[1]${NC} UFW Firewall Setup"
    echo -e "${PURPLE}│${NC}  ${GREEN}[2]${NC} Fail2Ban Configuration"
    echo -e "${PURPLE}│${NC}  ${GREEN}[3]${NC} SSH Hardening"
    echo -e "${PURPLE}│${NC}  ${GREEN}[4]${NC} Disable Root Login"
    echo -e "${PURPLE}│${NC}  ${GREEN}[5]${NC} ClamAV Antivirus"
    echo -e "${PURPLE}│${NC}  ${GREEN}[0]${NC} Back to Main Menu"
    echo -e "${PURPLE}│${NC}"
    echo -e "${PURPLE}└───────────────────────────────────────────────────┘${NC}"
    echo -ne "${BLUE}▶${NC} Pilih opsi: "
}

# ============================================================================
# INSTALLER MENU
# ============================================================================

installer_docker() {
    log_info "Install Docker..."
    
    run_cmd "apt-get remove -y docker docker-engine docker.io" "Remove old Docker" || true
    run_cmd "apt-get install -y apt-transport-https ca-certificates curl gnupg" "Install dependencies" || true
    run_cmd "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -" "Add Docker GPG" || true
    run_cmd "add-apt-repository 'deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable'" "Add Docker repo" || true
    run_cmd "apt-get update && apt-get install -y docker-ce docker-compose" "Install Docker" && log_success "Docker terinstall"
    run_cmd "systemctl start docker && systemctl enable docker" "Enable Docker" && log_success "Docker berjalan"
    
    press_enter
}

installer_nodejs() {
    log_info "Install Node.js..."
    
    echo -ne "${BLUE}▶${NC} Node.js versi (default: 20): "
    read NODE_VER
    NODE_VER=${NODE_VER:-20}
    
    run_cmd "curl -fsSL https://deb.nodesource.com/setup_${NODE_VER}.x | bash -" "Add Node.js repo" || true
    run_cmd "apt-get install -y nodejs npm" "Install Node.js" && log_success "Node.js v$NODE_VER terinstall"
    
    node --version
    npm --version
    
    press_enter
}

installer_python() {
    log_info "Install Python..."
    
    echo -ne "${BLUE}▶${NC} Python versi (default: 3): "
    read PYTHON_VER
    PYTHON_VER=${PYTHON_VER:-3}
    
    run_cmd "apt-get install -y python${PYTHON_VER} python${PYTHON_VER}-pip python${PYTHON_VER}-venv" "Install Python" && log_success "Python $PYTHON_VER terinstall"
    
    python${PYTHON_VER} --version
    
    press_enter
}

installer_fullstack() {
    log_info "Install Full Stack Packages..."
    
    run_cmd "apt-get install -y git curl wget build-essential" "Install build tools" || true
    run_cmd "apt-get install -y nodejs npm" "Install Node.js" || true
    run_cmd "apt-get install -y python3 python3-pip" "Install Python" || true
    run_cmd "apt-get install -y nginx" "Install Nginx" || true
    run_cmd "apt-get install -y postgresql postgresql-contrib" "Install PostgreSQL" || true
    
    log_success "Full Stack packages terinstall"
    
    press_enter
}

show_installer_menu() {
    clear_screen
    show_banner
    
    echo -e "${PURPLE}┌─ INSTALLER MENU ──────────────────────────────────┐${NC}"
    echo -e "${PURPLE}│${NC}"
    echo -e "${PURPLE}│${NC}  ${GREEN}[1]${NC} Docker"
    echo -e "${PURPLE}│${NC}  ${GREEN}[2]${NC} Node.js"
    echo -e "${PURPLE}│${NC}  ${GREEN}[3]${NC} Python"
    echo -e "${PURPLE}│${NC}  ${GREEN}[4]${NC} Full Stack Packages"
    echo -e "${PURPLE}│${NC}  ${GREEN}[0]${NC} Back to Main Menu"
    echo -e "${PURPLE}│${NC}"
    echo -e "${PURPLE}└───────────────────────────────────────────────────┘${NC}"
    echo -ne "${BLUE}▶${NC} Pilih opsi: "
}

# ============================================================================
# MAIN LOOP
# ============================================================================

main() {
    check_root
    check_os
    
    while true; do
        show_main_menu
        read choice
        
        case $choice in
            1)
                while true; do
                    show_hosting_menu
                    read sub_choice
                    case $sub_choice in
                        1) hosting_install_pterodactyl ;;
                        2) hosting_install_minecraft ;;
                        3) hosting_host_website ;;
                        4) hosting_ssl_setup ;;
                        5) hosting_ddos_protection ;;
                        0) break ;;
                        *) log_error "Pilihan tidak valid" ;;
                    esac
                done
                ;;
            2)
                while true; do
                    show_optimization_menu
                    read sub_choice
                    case $sub_choice in
                        1) optimization_login_theme ;;
                        2) optimization_system_update ;;
                        3) optimization_sysctl ;;
                        4) optimization_swap_creation ;;
                        5) optimization_log_cleaner ;;
                        0) break ;;
                        *) log_error "Pilihan tidak valid" ;;
                    esac
                done
                ;;
            3)
                while true; do
                    show_monitoring_menu
                    read sub_choice
                    case $sub_choice in
                        1) monitoring_disk_usage ;;
                        2) monitoring_open_ports ;;
                        3) monitoring_running_services ;;
                        4) monitoring_live_monitoring ;;
                        0) break ;;
                        *) log_error "Pilihan tidak valid" ;;
                    esac
                done
                ;;
            4)
                while true; do
                    show_security_menu
                    read sub_choice
                    case $sub_choice in
                        1) security_firewall_setup ;;
                        2) security_fail2ban_setup ;;
                        3) security_ssh_hardening ;;
                        4) security_disable_root_login ;;
                        5) security_clamav_scanner ;;
                        0) break ;;
                        *) log_error "Pilihan tidak valid" ;;
                    esac
                done
                ;;
            5)
                while true; do
                    show_installer_menu
                    read sub_choice
                    case $sub_choice in
                        1) installer_docker ;;
                        2) installer_nodejs ;;
                        3) installer_python ;;
                        4) installer_fullstack ;;
                        0) break ;;
                        *) log_error "Pilihan tidak valid" ;;
                    esac
                done
                ;;
            0)
                echo ""
                log_success "Terima kasih telah menggunakan EASETUP TOOLS"
                exit 0
                ;;
            *)
                log_error "Pilihan tidak valid"
                ;;
        esac
    done
}

# ============================================================================
# SCRIPT START
# ============================================================================

main "$@"
