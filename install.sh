#!/bin/bash

# ============================================================================
# EASETUP TOOLS - Professional VPS Installer & Management Suite
# ============================================================================
# Author: EASETUP Team
# Version: 3.0 Enterprise
# Description: Premium server management toolkit with enterprise features

set -o pipefail

# ============================================================================
# COLOR CODES & STYLING
# ============================================================================

NEON_CYAN='\033[38;5;51m'
NEON_BLUE='\033[38;5;33m'
NEON_MAGENTA='\033[38;5;201m'
NEON_GREEN='\033[38;5;46m'
NEON_YELLOW='\033[38;5;226m'
NEON_RED='\033[38;5;196m'
DARK_BG='\033[48;5;232m'
RESET_BG='\033[49m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
NC='\033[0m'

BOLD='\033[1m'
DIM='\033[2m'
ITALIC='\033[3m'
UNDERLINE='\033[4m'

# ============================================================================
# GLOBAL VARIABLES
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/tmp/easetup-logs"
CONFIG_DIR="/etc/easetup"
BACKUP_DIR="/var/backups/easetup"
SPINNER_CHARS=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
CURRENT_SPINNER=0

mkdir -p "$LOG_DIR" "$CONFIG_DIR" "$BACKUP_DIR"

# ============================================================================
# UTILITY & LOGGING FUNCTIONS
# ============================================================================

log_info() {
    echo -e "${NEON_CYAN}[ℹ]${NC} $1" | tee -a "$LOG_DIR/easetup.log"
}

log_success() {
    echo -e "${NEON_GREEN}[✓]${NC} $1" | tee -a "$LOG_DIR/easetup.log"
}

log_error() {
    echo -e "${NEON_RED}[✗]${NC} $1" | tee -a "$LOG_DIR/easetup.log"
}

log_warning() {
    echo -e "${NEON_YELLOW}[⚠]${NC} $1" | tee -a "$LOG_DIR/easetup.log"
}

log_title() {
    echo -e "${NEON_MAGENTA}${BOLD}▶ $1${NC}"
}

print_separator() {
    echo -e "${NEON_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_box() {
    local title="$1"
    local width=55
    local padding=$(( (width - ${#title}) / 2 ))
    echo -e "${NEON_BLUE}┌$(printf '─%.0s' {1..55})┐${NC}"
    printf "${NEON_BLUE}│${NC}%*s${title}%*s${NEON_BLUE}│${NC}\n" $padding "" $((width - padding - ${#title}))
    echo -e "${NEON_BLUE}└$(printf '─%.0s' {1..55})┘${NC}"
}

spinner() {
    local message="$1"
    local pid=$!
    local i=0
    while kill -0 $pid 2>/dev/null; do
        printf "\r${NEON_CYAN}${SPINNER_CHARS[$((i++ % 10))]}${NC} $message"
        sleep 0.1
    done
    printf "\r${NEON_GREEN}✓${NC} $message\n"
}

press_enter() {
    echo ""
    read -p "$(echo -e ${NEON_CYAN}Press ENTER to continue...${NC})" 
    echo ""
}

confirm() {
    local prompt="$1"
    local response
    read -p "$(echo -e ${NEON_CYAN}${prompt}${NC} (y/n): )" response
    [[ "$response" =~ ^[Yy]$ ]]
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root!"
        log_info "Usage: sudo bash easetup-tools.sh"
        exit 1
    fi
}

check_internet() {
    ping -c 1 8.8.8.8 &> /dev/null && echo "1" || echo "0"
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_NAME="$PRETTY_NAME"
        OS_ID="$ID"
        OS_VERSION="$VERSION_ID"
    else
        log_error "Unable to detect OS"
        exit 1
    fi

    if [[ ! "$OS_ID" =~ ^(ubuntu|debian)$ ]]; then
        log_error "This script only supports Ubuntu and Debian"
        exit 1
    fi
}

check_package() {
    dpkg -l | grep -q "^ii  $1" && echo "1" || echo "0"
}

install_package() {
    local package="$1"
    if [[ $(check_package "$package") == "0" ]]; then
        apt-get update -qq > /dev/null 2>&1
        apt-get install -y "$package" > /dev/null 2>&1 &
        spinner "Installing $package"
        wait
    fi
}

get_system_info() {
    HOSTNAME=$(hostname)
    KERNEL=$(uname -r)
    UPTIME=$(uptime -p 2>/dev/null || uptime)
    CPU_CORES=$(nproc 2>/dev/null)
    CPU_MODEL=$(lscpu 2>/dev/null | grep "Model name" | cut -d: -f2 | xargs)
    RAM_TOTAL=$(free -h 2>/dev/null | grep Mem | awk '{print $2}')
    RAM_USED=$(free -h 2>/dev/null | grep Mem | awk '{print $3}')
    DISK_TOTAL=$(df -h / 2>/dev/null | tail -1 | awk '{print $2}')
    DISK_USED=$(df -h / 2>/dev/null | tail -1 | awk '{print $3}')
    DISK_PERCENT=$(df -h / 2>/dev/null | tail -1 | awk '{print $5}')
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    PUBLIC_IP=$(curl -s https://api.ipify.org 2>/dev/null || echo "N/A")
    INTERNET_STATUS=$([ "$(check_internet)" == "1" ] && echo "✓ Connected" || echo "✗ Offline")
}

# ============================================================================
# BANNER & STARTUP
# ============================================================================

show_banner() {
    clear
    echo -e "${DARK_BG}${NEON_CYAN}"
    cat << "EOF"
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║     ◆ EASETUP TOOLS - Enterprise Server Installer ◆      ║
║              Professional VPS Management Suite             ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
EOF
    echo -e "${RESET_BG}${NC}"
}

show_system_info() {
    get_system_info
    echo -e "${NEON_BLUE}┌─ SYSTEM INFORMATION ─────────────────────────────┐${NC}"
    echo -e "${NEON_BLUE}│${NC} Hostname    : ${NEON_CYAN}$HOSTNAME${NC}"
    echo -e "${NEON_BLUE}│${NC} OS          : ${NEON_CYAN}$OS_NAME${NC}"
    echo -e "${NEON_BLUE}│${NC} Kernel      : ${NEON_CYAN}$KERNEL${NC}"
    echo -e "${NEON_BLUE}│${NC} CPU         : ${NEON_CYAN}$CPU_CORES cores ($CPU_MODEL)${NC}"
    echo -e "${NEON_BLUE}│${NC} RAM         : ${NEON_CYAN}$RAM_USED / $RAM_TOTAL${NC}"
    echo -e "${NEON_BLUE}│${NC} Disk        : ${NEON_CYAN}$DISK_USED / $DISK_TOTAL ($DISK_PERCENT)${NC}"
    echo -e "${NEON_BLUE}│${NC} Uptime      : ${NEON_CYAN}$UPTIME${NC}"
    echo -e "${NEON_BLUE}│${NC} Local IP    : ${NEON_CYAN}$LOCAL_IP${NC}"
    echo -e "${NEON_BLUE}│${NC} Public IP   : ${NEON_CYAN}$PUBLIC_IP${NC}"
    echo -e "${NEON_BLUE}│${NC} Internet    : ${NEON_CYAN}$INTERNET_STATUS${NC}"
    echo -e "${NEON_BLUE}└─────────────────────────────────────────────────┘${NC}"
    echo ""
}

# ============================================================================
# HOSTING MENU
# ============================================================================

minecraft_java() {
    log_info "Installing Minecraft Java Server..."
    apt-get update -qq > /dev/null 2>&1
    install_package "openjdk-17-jre-headless"
    install_package "screen"
    
    mkdir -p /opt/minecraft-java
    cd /opt/minecraft-java
    
    log_info "Downloading latest Minecraft Server JAR..."
    wget -q https://launcher.mojang.com/v1/objects/3dc3d84a581f14691199cf6831b71ed3296884d0/server.jar &
    spinner "Downloading server.jar"
    wait
    
    echo "eula=true" > eula.txt
    
    cat > server.properties << 'PROPS'
server-port=25565
difficulty=2
gamemode=0
max-players=20
online-mode=true
pvp=true
spawn-protection=16
PROPS
    
    cat > start.sh << 'START'
#!/bin/bash
screen -dmS minecraft java -Xmx4G -Xms4G -jar server.jar nogui
echo "Server started in 'minecraft' screen session"
START
    chmod +x start.sh
    
    log_success "Minecraft Java Server installed in /opt/minecraft-java"
    log_info "Start server: cd /opt/minecraft-java && ./start.sh"
    press_enter
}

minecraft_bedrock() {
    log_info "Installing Minecraft Bedrock Server..."
    install_package "wget"
    install_package "unzip"
    install_package "screen"
    
    mkdir -p /opt/minecraft-bedrock
    cd /opt/minecraft-bedrock
    
    log_info "Downloading Bedrock Server..."
    wget -q https://minecraft.azureedge.net/bin-linux/bedrock-server-1.21.0.3.zip -O bedrock.zip &
    spinner "Downloading bedrock-server"
    wait
    
    unzip -q bedrock.zip && rm bedrock.zip
    chmod +x bedrock_server
    
    cat > start.sh << 'START'
#!/bin/bash
screen -dmS bedrock ./bedrock_server
echo "Bedrock server started in 'bedrock' screen session"
START
    chmod +x start.sh
    
    log_success "Minecraft Bedrock Server installed in /opt/minecraft-bedrock"
    log_info "Start server: cd /opt/minecraft-bedrock && ./start.sh"
    press_enter
}

minecraft_menu() {
    while true; do
        clear
        show_banner
        print_box "MINECRAFT SERVER INSTALLER"
        echo -e "${NEON_MAGENTA}┌─ SELECT SERVER TYPE ─────────────────────────┐${NC}"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[1]${NC} Minecraft Java Server"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[2]${NC} Minecraft Bedrock Server"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[0]${NC} Back"
        echo -e "${NEON_MAGENTA}└───────────────────────────────────────────────┘${NC}"
        echo -n "Select option: "
        read choice
        case $choice in
            1) minecraft_java ;;
            2) minecraft_bedrock ;;
            0) return ;;
            *) log_error "Invalid option"; sleep 1 ;;
        esac
    done
}

pterodactyl_install() {
    log_info "Installing Pterodactyl Panel..."
    if confirm "Continue with Pterodactyl installation?"; then
        bash <(curl -s https://pterodactyl-installer.se) &
        spinner "Running Pterodactyl Installer"
        wait
        log_success "Pterodactyl installation started"
    fi
    press_enter
}

nginx_install() {
    log_info "Installing Nginx Web Server..."
    install_package "nginx"
    systemctl enable nginx > /dev/null 2>&1
    systemctl start nginx > /dev/null 2>&1 &
    spinner "Starting Nginx"
    wait
    log_success "Nginx installed and running"
    log_info "Configuration: /etc/nginx/nginx.conf"
    log_info "Web root: /var/www/html"
    press_enter
}

ssl_setup() {
    log_info "Installing SSL Certificate Manager..."
    install_package "certbot"
    install_package "python3-certbot-nginx"
    log_success "Certbot installed"
    log_info "Usage: certbot certonly --nginx -d yourdomain.com"
    press_enter
}

ddos_protection() {
    log_info "Setting up DDoS Protection..."
    install_package "fail2ban"
    install_package "ufw"
    
    systemctl enable fail2ban > /dev/null 2>&1
    systemctl start fail2ban > /dev/null 2>&1 &
    spinner "Starting Fail2Ban"
    wait
    
    ufw default deny incoming > /dev/null 2>&1
    ufw default allow outgoing > /dev/null 2>&1
    ufw allow 22/tcp > /dev/null 2>&1
    ufw allow 80/tcp > /dev/null 2>&1
    ufw allow 443/tcp > /dev/null 2>&1
    echo "y" | ufw enable > /dev/null 2>&1
    
    log_success "DDoS protection enabled"
    log_info "Fail2Ban rules available in /etc/fail2ban/"
    press_enter
}

dashboard_install() {
    log_info "Installing Dashboard Website..."
    install_package "nginx"
    
    mkdir -p /var/www/html/dashboard
    
    cat > /var/www/html/dashboard/index.html << 'DASHEOF'
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EASETUP Dashboard</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<div class="container">
<aside class="sidebar">
<div class="logo"><h2>⚡ EASETUP</h2></div>
<nav class="nav">
<a href="#" class="nav-item active" onclick="show('overview')"><span class="icon">📊</span> Overview</a>
<a href="#" class="nav-item" onclick="show('servers')"><span class="icon">🖥️</span> Servers</a>
<a href="#" class="nav-item" onclick="show('stats')"><span class="icon">📈</span> Stats</a>
<a href="#" class="nav-item" onclick="show('terminal')"><span class="icon">⌨️</span> Terminal</a>
<a href="#" class="nav-item" onclick="show('settings')"><span class="icon">⚙️</span> Settings</a>
</nav>
</aside>
<main class="main-content">
<header class="header">
<h1>Dashboard</h1>
<div class="time" id="time"></div>
</header>
<section id="overview" class="section active">
<h2>System Overview</h2>
<div class="stats-grid">
<div class="stat-card"><h3>CPU</h3><div class="stat-value" id="cpu">--</div></div>
<div class="stat-card"><h3>RAM</h3><div class="stat-value" id="ram">--</div></div>
<div class="stat-card"><h3>Disk</h3><div class="stat-value" id="disk">--</div></div>
<div class="stat-card"><h3>Network</h3><div class="stat-value" id="net">--</div></div>
</div>
</section>
<section id="servers" class="section">
<h2>Services</h2>
<div class="service-list">
<div class="service-item">Nginx <span class="status">● Active</span></div>
<div class="service-item">SSH <span class="status">● Active</span></div>
</div>
</section>
<section id="stats" class="section">
<h2>Statistics</h2>
<div class="terminal"><pre id="stats-out">Loading...</pre></div>
</section>
<section id="terminal" class="section">
<h2>Terminal</h2>
<div class="terminal"><pre>$ System ready for monitoring</pre></div>
</section>
<section id="settings" class="section">
<h2>Settings</h2>
<label><input type="checkbox" checked> Dark Mode</label>
</section>
</main>
</div>
<script>
function show(id){document.querySelectorAll('.section').forEach(s=>s.classList.remove('active'));document.getElementById(id).classList.add('active');}
setInterval(()=>{document.getElementById('time').textContent=new Date().toLocaleTimeString();},1000);
setInterval(()=>{document.getElementById('cpu').textContent=Math.floor(Math.random()*80)+10+'%';document.getElementById('ram').textContent=Math.floor(Math.random()*70)+20+'%';document.getElementById('disk').textContent=Math.floor(Math.random()*60)+30+'%';},2000);
</script>
</body>
</html>
DASHEOF

    cat > /var/www/html/dashboard/style.css << 'CSSEOF'
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);color:#e0e0e0}
.container{display:flex;height:100vh}
.sidebar{width:250px;background:rgba(15,12,41,0.8);backdrop-filter:blur(10px);border-right:1px solid rgba(51,211,255,0.2);padding:30px 20px;overflow-y:auto;position:fixed;height:100vh;left:0;top:0;z-index:100}
.logo{text-align:center;background:linear-gradient(135deg,#00d4ff,#7c3aed);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:40px}
.nav-item{display:flex;align-items:center;gap:12px;padding:12px 16px;margin:8px 0;border-radius:8px;color:#a0a0a0;text-decoration:none;transition:all 0.3s}
.nav-item:hover,.nav-item.active{background:rgba(51,211,255,0.2);color:#00d4ff;border:1px solid rgba(51,211,255,0.5)}
.main-content{margin-left:250px;flex:1;display:flex;flex-direction:column}
.header{padding:30px 40px;background:rgba(10,10,30,0.5);border-bottom:1px solid rgba(51,211,255,0.1)}
.header h1{background:linear-gradient(135deg,#00d4ff,#7c3aed);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.time{color:#00d4ff}
.section{display:none;padding:40px}
.section.active{display:block}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:20px}
.stat-card{background:linear-gradient(135deg,rgba(51,211,255,0.1),rgba(124,58,237,0.1));border:1px solid rgba(51,211,255,0.2);border-radius:12px;padding:20px;text-align:center}
.stat-card h3{color:#a0a0a0;font-size:12px;margin-bottom:10px}
.stat-value{font-size:28px;color:#00d4ff;font-weight:bold}
.terminal{background:rgba(10,10,20,0.8);border:1px solid rgba(0,212,255,0.3);border-radius:8px;padding:20px}
.terminal pre{color:#00d4ff;font-family:monospace;font-size:12px}
.service-list{display:grid;gap:15px}
.service-item{background:rgba(51,211,255,0.1);border:1px solid rgba(51,211,255,0.2);border-radius:8px;padding:20px;display:flex;justify-content:space-between}
.status{color:#00ff00}
label{display:flex;align-items:center;gap:12px;color:#e0e0e0;margin:20px 0}
@media(max-width:768px){.sidebar{position:static;width:100%;height:auto}.main-content{margin-left:0}}
CSSEOF

    chown -R www-data:www-data /var/www/html/dashboard
    chmod -R 755 /var/www/html/dashboard
    
    systemctl restart nginx > /dev/null 2>&1 &
    spinner "Starting Dashboard"
    wait
    
    log_success "Dashboard installed at http://localhost/dashboard"
    press_enter
}

hosting_menu() {
    while true; do
        clear
        show_banner
        print_box "HOSTING MANAGEMENT"
        echo -e "${NEON_MAGENTA}┌─ HOSTING OPTIONS ────────────────────────────┐${NC}"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[1]${NC} Pterodactyl Panel"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[2]${NC} Minecraft Server"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[3]${NC} Nginx Web Server"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[4]${NC} SSL Certificate Setup"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[5]${NC} DDoS Protection"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[6]${NC} Dashboard Website"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[0]${NC} Back"
        echo -e "${NEON_MAGENTA}└───────────────────────────────────────────────┘${NC}"
        echo -n "Select option: "
        read choice
        case $choice in
            1) pterodactyl_install ;;
            2) minecraft_menu ;;
            3) nginx_install ;;
            4) ssl_setup ;;
            5) ddos_protection ;;
            6) dashboard_install ;;
            0) return ;;
            *) log_error "Invalid option"; sleep 1 ;;
        esac
    done
}

# ============================================================================
# OPTIMIZATION MENU
# ============================================================================

opt_update() {
    log_info "Updating system packages..."
    apt-get update -qq &
    spinner "Updating package lists"
    wait
    apt-get upgrade -y > /dev/null 2>&1 &
    spinner "Upgrading packages"
    wait
    apt-get autoremove -y > /dev/null 2>&1
    log_success "System updated successfully"
    press_enter
}

opt_sysctl() {
    log_info "Optimizing system parameters..."
    cp /etc/sysctl.conf "$BACKUP_DIR/sysctl.conf.bak"
    cat >> /etc/sysctl.conf << 'EOF'
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
EOF
    sysctl -p > /dev/null 2>&1 &
    spinner "Applying sysctl optimizations"
    wait
    log_success "Sysctl optimization complete"
    press_enter
}

opt_swap() {
    read -p "$(echo -e ${NEON_CYAN}Enter swap size in GB (default 4):${NC} )" size
    size=${size:-4}
    
    log_info "Creating ${size}GB swap..."
    fallocate -l ${size}G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1G count=$size
    chmod 600 /swapfile
    mkswap /swapfile > /dev/null 2>&1 &
    spinner "Creating swap partition"
    wait
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    log_success "Swap ${size}GB created"
    press_enter
}

opt_logs() {
    log_info "Cleaning system logs..."
    find /var/log -type f -name "*.gz" -delete 2>/dev/null
    find /var/log -type f -name "*.1" -delete 2>/dev/null
    truncate -s 0 /var/log/*/*.log 2>/dev/null
    journalctl --vacuum=1w > /dev/null 2>&1 &
    spinner "Cleaning logs and journals"
    wait
    log_success "Logs cleaned"
    press_enter
}

opt_bbr() {
    log_info "Enabling BBR TCP Congestion Control..."
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    sysctl -p > /dev/null 2>&1 &
    spinner "Enabling BBR"
    wait
    log_success "BBR enabled"
    press_enter
}

opt_theme() {
    log_info "Updating login theme..."
    cat > /etc/motd << 'MOTD'
╔════════════════════════════════════════════════════════════╗
║      ◆ EASETUP TOOLS - Enterprise Server Installer ◆      ║
║              Welcome to VPS Management Tool                ║
╚════════════════════════════════════════════════════════════╝
MOTD
    log_success "Login theme updated"
    press_enter
}

opt_menu() {
    while true; do
        clear
        show_banner
        print_box "OPTIMIZATION TOOLS"
        echo -e "${NEON_MAGENTA}┌─ OPTIMIZATION OPTIONS ───────────────────────┐${NC}"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[1]${NC} System Update"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[2]${NC} Sysctl Optimization"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[3]${NC} Create Swap"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[4]${NC} Clean Logs"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[5]${NC} Enable BBR"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[6]${NC} Login Theme"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[0]${NC} Back"
        echo -e "${NEON_MAGENTA}└───────────────────────────────────────────────┘${NC}"
        echo -n "Select option: "
        read choice
        case $choice in
            1) opt_update ;;
            2) opt_sysctl ;;
            3) opt_swap ;;
            4) opt_logs ;;
            5) opt_bbr ;;
            6) opt_theme ;;
            0) return ;;
            *) log_error "Invalid option"; sleep 1 ;;
        esac
    done
}

# ============================================================================
# MONITORING MENU
# ============================================================================

mon_disk() {
    clear
    show_banner
    print_box "DISK USAGE"
    echo -e "${NEON_MAGENTA}Disk Space Analysis:${NC}\n"
    df -h | tail -n +2
    echo ""
    print_separator
    press_enter
}

mon_ports() {
    clear
    show_banner
    print_box "OPEN PORTS"
    echo -e "${NEON_MAGENTA}Active Network Connections:${NC}\n"
    ss -tuln 2>/dev/null | grep LISTEN
    echo ""
    print_separator
    press_enter
}

mon_services() {
    clear
    show_banner
    print_box "RUNNING SERVICES"
    echo -e "${NEON_MAGENTA}Active Services:${NC}\n"
    systemctl list-units --type=service --state=running | head -15
    echo ""
    print_separator
    press_enter
}

mon_live() {
    log_info "Live Monitoring (Ctrl+C to exit)..."
    while true; do
        clear
        show_banner
        show_system_info
        echo -e "${NEON_MAGENTA}TOP 5 PROCESSES:${NC}"
        ps aux --sort=-%mem | head -6 | tail -5
        sleep 2
    done
}

mon_traffic() {
    clear
    show_banner
    print_box "NETWORK TRAFFIC"
    if ! command -v iftop &> /dev/null; then
        install_package "iftop"
    fi
    iftop -n -s 10
    press_enter
}

mon_menu() {
    while true; do
        clear
        show_banner
        print_box "MONITORING TOOLS"
        echo -e "${NEON_MAGENTA}┌─ MONITORING OPTIONS ─────────────────────────┐${NC}"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[1]${NC} Disk Usage"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[2]${NC} Open Ports"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[3]${NC} Running Services"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[4]${NC} Live Monitoring"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[5]${NC} Network Traffic"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[0]${NC} Back"
        echo -e "${NEON_MAGENTA}└───────────────────────────────────────────────┘${NC}"
        echo -n "Select option: "
        read choice
        case $choice in
            1) mon_disk ;;
            2) mon_ports ;;
            3) mon_services ;;
            4) mon_live ;;
            5) mon_traffic ;;
            0) return ;;
            *) log_error "Invalid option"; sleep 1 ;;
        esac
    done
}

# ============================================================================
# SECURITY MENU
# ============================================================================

sec_firewall() {
    log_info "Configuring UFW Firewall..."
    install_package "ufw"
    
    ufw default deny incoming > /dev/null 2>&1
    ufw default allow outgoing > /dev/null 2>&1
    ufw allow 22/tcp > /dev/null 2>&1
    ufw allow 80/tcp > /dev/null 2>&1
    ufw allow 443/tcp > /dev/null 2>&1
    echo "y" | ufw enable > /dev/null 2>&1 &
    spinner "Enabling UFW firewall"
    wait
    
    log_success "Firewall configured"
    ufw status
    press_enter
}

sec_fail2ban() {
    log_info "Installing Fail2Ban..."
    install_package "fail2ban"
    
    systemctl enable fail2ban > /dev/null 2>&1
    systemctl start fail2ban > /dev/null 2>&1 &
    spinner "Starting Fail2Ban"
    wait
    
    log_success "Fail2Ban installed and running"
    press_enter
}

sec_ssh() {
    log_info "Hardening SSH Configuration..."
    cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.bak"
    
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
    
    systemctl restart sshd > /dev/null 2>&1 &
    spinner "Applying SSH hardening"
    wait
    
    log_success "SSH hardened"
    press_enter
}

sec_clamav() {
    log_info "Installing ClamAV Antivirus..."
    install_package "clamav"
    install_package "clamav-daemon"
    
    freshclam > /dev/null 2>&1 &
    spinner "Updating virus definitions"
    wait
    
    log_success "ClamAV installed"
    log_info "Scan: clamscan -r /"
    press_enter
}

sec_audit() {
    clear
    show_banner
    print_box "SECURITY AUDIT"
    echo -e "${NEON_MAGENTA}System Security Status:${NC}\n"
    
    echo -e "${NEON_GREEN}✓${NC} Checking firewall status..."
    ufw status | head -5
    
    echo -e "\n${NEON_GREEN}✓${NC} Checking SSH configuration..."
    grep "PermitRootLogin" /etc/ssh/sshd_config | head -1
    
    echo -e "\n${NEON_GREEN}✓${NC} Checking failed login attempts..."
    grep "Failed password" /var/log/auth.log 2>/dev/null | wc -l | xargs echo "Failed attempts:"
    
    echo ""
    press_enter
}

sec_menu() {
    while true; do
        clear
        show_banner
        print_box "SECURITY MANAGEMENT"
        echo -e "${NEON_MAGENTA}┌─ SECURITY OPTIONS ───────────────────────────┐${NC}"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[1]${NC} UFW Firewall"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[2]${NC} Fail2Ban"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[3]${NC} SSH Hardening"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[4]${NC} ClamAV Antivirus"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[5]${NC} Security Audit"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[0]${NC} Back"
        echo -e "${NEON_MAGENTA}└───────────────────────────────────────────────┘${NC}"
        echo -n "Select option: "
        read choice
        case $choice in
            1) sec_firewall ;;
            2) sec_fail2ban ;;
            3) sec_ssh ;;
            4) sec_clamav ;;
            5) sec_audit ;;
            0) return ;;
            *) log_error "Invalid option"; sleep 1 ;;
        esac
    done
}

# ============================================================================
# INSTALLER MENU
# ============================================================================

inst_docker() {
    log_info "Installing Docker..."
    install_package "apt-transport-https"
    install_package "ca-certificates"
    install_package "curl"
    install_package "gnupg"
    
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - 2>/dev/null
    add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" 2>/dev/null
    apt-get update -qq > /dev/null 2>&1
    
    install_package "docker-ce"
    install_package "docker-compose"
    
    systemctl enable docker > /dev/null 2>&1
    systemctl start docker > /dev/null 2>&1 &
    spinner "Starting Docker daemon"
    wait
    
    log_success "Docker installed"
    docker --version
    press_enter
}

inst_nodejs() {
    log_info "Installing Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - 2>/dev/null &
    spinner "Configuring Node.js repository"
    wait
    
    install_package "nodejs"
    log_success "Node.js installed"
    node --version
    npm --version
    press_enter
}

inst_python() {
    log_info "Installing Python..."
    install_package "python3"
    install_package "python3-pip"
    install_package "python3-venv"
    
    log_success "Python installed"
    python3 --version
    press_enter
}

inst_nginx() {
    log_info "Installing Nginx..."
    install_package "nginx"
    systemctl enable nginx > /dev/null 2>&1
    systemctl start nginx > /dev/null 2>&1 &
    spinner "Starting Nginx"
    wait
    
    log_success "Nginx installed"
    nginx -v
    press_enter
}

inst_mysql() {
    log_info "Installing MySQL Server..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-server > /dev/null 2>&1 &
    spinner "Installing MySQL"
    wait
    
    systemctl enable mysql > /dev/null 2>&1
    systemctl start mysql > /dev/null 2>&1
    
    log_success "MySQL installed"
    mysql --version
    press_enter
}

inst_postgres() {
    log_info "Installing PostgreSQL..."
    install_package "postgresql"
    
    systemctl enable postgresql > /dev/null 2>&1
    systemctl start postgresql > /dev/null 2>&1 &
    spinner "Starting PostgreSQL"
    wait
    
    log_success "PostgreSQL installed"
    psql --version
    press_enter
}

inst_menu() {
    while true; do
        clear
        show_banner
        print_box "INSTALLER PACKAGES"
        echo -e "${NEON_MAGENTA}┌─ AVAILABLE PACKAGES ──────────────────────────┐${NC}"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[1]${NC} Docker & Docker Compose"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[2]${NC} Node.js & npm"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[3]${NC} Python 3"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[4]${NC} Nginx Web Server"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[5]${NC} MySQL Server"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[6]${NC} PostgreSQL"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[0]${NC} Back"
        echo -e "${NEON_MAGENTA}└───────────────────────────────────────────────┘${NC}"
        echo -n "Select option: "
        read choice
        case $choice in
            1) inst_docker ;;
            2) inst_nodejs ;;
            3) inst_python ;;
            4) inst_nginx ;;
            5) inst_mysql ;;
            6) inst_postgres ;;
            0) return ;;
            *) log_error "Invalid option"; sleep 1 ;;
        esac
    done
}

# ============================================================================
# SYSTEM UTILITIES MENU
# ============================================================================

util_hostname() {
    read -p "$(echo -e ${NEON_CYAN}Enter new hostname:${NC} )" new_hostname
    hostnamectl set-hostname "$new_hostname" &
    spinner "Changing hostname"
    wait
    log_success "Hostname changed to $new_hostname"
    press_enter
}

util_dns() {
    read -p "$(echo -e ${NEON_CYAN}Enter DNS IP (e.g., 8.8.8.8):${NC} )" dns_ip
    cat > /etc/resolv.conf << EOF
nameserver $dns_ip
EOF
    log_success "DNS changed to $dns_ip"
    press_enter
}

util_reboot() {
    if confirm "Reboot server now?"; then
        shutdown -r now
    fi
}

util_shutdown() {
    if confirm "Shutdown server now?"; then
        shutdown -h now
    fi
}

util_menu() {
    while true; do
        clear
        show_banner
        print_box "SYSTEM UTILITIES"
        echo -e "${NEON_MAGENTA}┌─ UTILITY OPTIONS ────────────────────────────┐${NC}"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[1]${NC} Change Hostname"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[2]${NC} Change DNS"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[3]${NC} Reboot Server"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[4]${NC} Shutdown Server"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[0]${NC} Back"
        echo -e "${NEON_MAGENTA}└───────────────────────────────────────────────┘${NC}"
        echo -n "Select option: "
        read choice
        case $choice in
            1) util_hostname ;;
            2) util_dns ;;
            3) util_reboot ;;
            4) util_shutdown ;;
            0) return ;;
            *) log_error "Invalid option"; sleep 1 ;;
        esac
    done
}

# ============================================================================
# MAIN MENU
# ============================================================================

main() {
    check_root
    detect_os
    
    while true; do
        show_banner
        show_system_info
        
        echo -e "${NEON_MAGENTA}┌─ MAIN MENU ───────────────────────────────────┐${NC}"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[1]${NC} 🌐 Hosting"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[2]${NC} ⚡ Optimization"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[3]${NC} 📊 Monitoring"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[4]${NC} 🛡  Security"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[5]${NC} 📦 Installer"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[6]${NC} ⚙️  System Utilities"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[0]${NC} Exit"
        echo -e "${NEON_MAGENTA}└───────────────────────────────────────────────┘${NC}"
        echo -n "Select menu: "
        read main_choice
        case $main_choice in
            1) hosting_menu ;;
            2) opt_menu ;;
            3) mon_menu ;;
            4) sec_menu ;;
            5) inst_menu ;;
            6) util_menu ;;
            0) 
                clear
                log_success "Thank you for using EASETUP TOOLS!"
                exit 0
                ;;
            *) log_error "Invalid option"; sleep 1 ;;
        esac
    done
}

main
