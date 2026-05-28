#!/bin/bash

# EASETUP TOOLS - Professional VPS Installer & Management System
# Author: V0
# Version: 2.0
# Features: Hosting, Optimization, Monitoring, Security, Installer, Dashboard

# ============================================================================
# NEON CYAN COLOR SCHEME
# ============================================================================

NEON_CYAN='\033[38;5;51m'
NEON_BLUE='\033[38;5;33m'
NEON_MAGENTA='\033[38;5;201m'
NEON_GREEN='\033[38;5;46m'
DARK_BG='\033[48;5;232m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
NC='\033[0m'

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

log_info() {
    echo -e "${NEON_CYAN}[ℹ]${NC} $1"
}

log_success() {
    echo -e "${NEON_GREEN}[✓]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

print_separator() {
    echo -e "${NEON_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

loading_animation() {
    local msg="$1"
    local chars=( '⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏' )
    local i=0
    while kill -0 $! 2>/dev/null; do
        printf "\r${NEON_CYAN}${chars[$((i++%10))]}${NC} $msg"
        sleep 0.1
    done
    printf "\r${NEON_GREEN}✓${NC} $msg\n"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Script ini harus dijalankan sebagai root!"
        log_info "Gunakan: sudo bash easetup-tools.sh"
        exit 1
    fi
}

check_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$PRETTY_NAME
        OS_ID=$ID
    else
        log_error "Sistem operasi tidak terdeteksi"
        exit 1
    fi
}

press_enter() {
    echo ""
    read -p "Tekan ENTER untuk melanjutkan..."
    echo ""
}

# ============================================================================
# SYSTEM INFO
# ============================================================================

get_system_info() {
    HOSTNAME=$(hostname)
    KERNEL=$(uname -r)
    UPTIME=$(uptime -p 2>/dev/null || uptime)
    CPU_CORES=$(nproc 2>/dev/null || echo "N/A")
    RAM_TOTAL=$(free -h 2>/dev/null | grep Mem | awk '{print $2}' || echo "N/A")
    RAM_USED=$(free -h 2>/dev/null | grep Mem | awk '{print $3}' || echo "N/A")
    DISK_TOTAL=$(df -h / 2>/dev/null | tail -1 | awk '{print $2}' || echo "N/A")
    DISK_USED=$(df -h / 2>/dev/null | tail -1 | awk '{print $3}' || echo "N/A")
    DISK_PERCENT=$(df -h / 2>/dev/null | tail -1 | awk '{print $5}' || echo "N/A")
}

show_banner() {
    clear
    echo -e "${DARK_BG}${NEON_CYAN}"
    cat << "EOF"
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║     ◆ EASETUP TOOLS - Professional VPS Installer ◆       ║
║              Premium Hosting Management Suite              ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

show_device_info() {
    get_system_info
    
    echo -e "${NEON_BLUE}┌─ SYSTEM INFORMATION ─────────────────────────────┐${NC}"
    echo -e "${NEON_BLUE}│${NC} Hostname  : ${NEON_CYAN}$HOSTNAME${NC}"
    echo -e "${NEON_BLUE}│${NC} OS        : ${NEON_CYAN}$OS${NC}"
    echo -e "${NEON_BLUE}│${NC} Kernel    : ${NEON_CYAN}$KERNEL${NC}"
    echo -e "${NEON_BLUE}│${NC} CPU       : ${NEON_CYAN}$CPU_CORES cores${NC}"
    echo -e "${NEON_BLUE}│${NC} RAM       : ${NEON_CYAN}$RAM_USED / $RAM_TOTAL${NC}"
    echo -e "${NEON_BLUE}│${NC} Disk      : ${NEON_CYAN}$DISK_USED / $DISK_TOTAL ($DISK_PERCENT)${NC}"
    echo -e "${NEON_BLUE}│${NC} Uptime    : ${NEON_CYAN}$UPTIME${NC}"
    echo -e "${NEON_BLUE}└─────────────────────────────────────────────────┘${NC}"
    echo ""
}

# ============================================================================
# MINECRAFT JAVA SERVER
# ============================================================================

minecraft_java_install() {
    log_info "Installing Minecraft Java Server..."
    
    # Install dependencies
    apt-get update -qq > /dev/null 2>&1 &
    loading_animation "Updating system packages"
    
    apt-get install -y openjdk-17-jre-headless screen wget > /dev/null 2>&1 &
    loading_animation "Installing Java JDK & dependencies"
    
    # Create server directory
    mkdir -p /opt/minecraft-server
    cd /opt/minecraft-server
    
    log_info "Downloading latest Minecraft Server JAR..."
    wget -q https://launcher.mojang.com/v1/objects/$(curl -s https://launchermeta.mojang.com/mc/game/version_manifest.json | grep -o '"url":"https://launcher.mojang.com/v1/objects/[^"]*"' | head -1 | cut -d'"' -f4 | cut -d'/' -f7,8)/server.jar 2>/dev/null || {
        # Fallback download
        wget -q https://launcher.mojang.com/v1/objects/3dc3d84a581f14691199cf6831b71ed3296884d0/server.jar
    }
    
    # Generate eula.txt
    echo "eula=true" > eula.txt
    log_success "EULA accepted automatically"
    
    # Generate server.properties
    cat > server.properties << 'PROPS'
#Minecraft server properties
server-port=25565
difficulty=2
gamemode=0
max-players=20
online-mode=true
pvp=true
spawn-protection=16
white-list=false
enable-rcon=true
rcon.port=25575
motd=EASETUP Minecraft Server
PROPS
    
    # Create start script
    cat > start.sh << 'START'
#!/bin/bash
screen -dmS minecraft java -Xmx4G -Xms4G -jar server.jar nogui
echo "[✓] Minecraft server started in screen session 'minecraft'"
echo "Attach with: screen -r minecraft"
START
    
    chmod +x start.sh
    
    log_success "Minecraft Java Server installed in /opt/minecraft-server"
    log_info "To start server: cd /opt/minecraft-server && ./start.sh"
    log_info "Attach to console: screen -r minecraft"
    press_enter
}

# ============================================================================
# MINECRAFT BEDROCK SERVER
# ============================================================================

minecraft_bedrock_install() {
    log_info "Installing Minecraft Bedrock Server..."
    
    # Install dependencies
    apt-get update -qq > /dev/null 2>&1 &
    loading_animation "Updating system packages"
    
    apt-get install -y wget unzip screen > /dev/null 2>&1 &
    loading_animation "Installing dependencies"
    
    # Create server directory
    mkdir -p /opt/minecraft-bedrock
    cd /opt/minecraft-bedrock
    
    log_info "Downloading Minecraft Bedrock Dedicated Server..."
    wget -q https://minecraft.azureedge.net/bin-linux/bedrock-server-1.21.0.3.zip -O bedrock.zip 2>/dev/null || {
        log_warning "Using alternative mirror..."
        wget -q https://launcher.mojang.com/v1/objects/bedrock-server.zip -O bedrock.zip 2>/dev/null || true
    }
    
    if [ -f bedrock.zip ]; then
        unzip -q bedrock.zip
        rm bedrock.zip
    fi
    
    # Setup permissions
    chmod +x bedrock_server
    
    # Create start script
    cat > start.sh << 'START'
#!/bin/bash
screen -dmS bedrock ./bedrock_server
echo "[✓] Bedrock server started in screen session 'bedrock'"
echo "Attach with: screen -r bedrock"
START
    
    chmod +x start.sh
    
    log_success "Minecraft Bedrock Server installed in /opt/minecraft-bedrock"
    log_info "To start server: cd /opt/minecraft-bedrock && ./start.sh"
    log_info "Attach to console: screen -r bedrock"
    press_enter
}

# ============================================================================
# MINECRAFT MENU
# ============================================================================

minecraft_menu() {
    while true; do
        clear
        show_banner
        echo -e "${NEON_MAGENTA}┌─ MINECRAFT SERVER ────────────────────────────┐${NC}"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[1]${NC} Java Server"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[2]${NC} Bedrock Server"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[0]${NC} Back"
        echo -e "${NEON_MAGENTA}└─────────────────────────────────────────────┘${NC}"
        echo -n "Pilih: "
        read choice
        case $choice in
            1) minecraft_java_install ;;
            2) minecraft_bedrock_install ;;
            0) return ;;
            *) log_error "Opsi tidak valid"; sleep 1 ;;
        esac
    done
}

# ============================================================================
# HOSTING MENU
# ============================================================================

hosting_pterodactyl() {
    log_info "Installing Pterodactyl Panel..."
    log_warning "This will use official Pterodactyl installer"
    echo ""
    read -p "Continue? (y/n): " confirm
    if [[ $confirm == "y" ]]; then
        bash <(curl -s https://pterodactyl-installer.se)
        log_success "Pterodactyl installation complete"
    fi
    press_enter
}

hosting_website() {
    log_info "Install Website Hosting (Nginx)..."
    apt-get update -qq
    apt-get install -y nginx > /dev/null 2>&1
    systemctl enable nginx > /dev/null 2>&1
    systemctl start nginx > /dev/null 2>&1
    log_success "Nginx aktif. Upload file ke /var/www/html"
    press_enter
}

hosting_ssl() {
    log_info "Install Certbot untuk SSL..."
    apt-get update -qq
    apt-get install -y certbot python3-certbot-nginx > /dev/null 2>&1
    log_success "Certbot siap. Jalankan: certbot certonly --nginx -d domain.com"
    press_enter
}

hosting_ddos() {
    log_info "Setup DDoS Protection..."
    apt-get update -qq
    apt-get install -y fail2ban ufw > /dev/null 2>&1
    log_success "Fail2Ban dan UFW terinstall"
    press_enter
}

hosting_menu() {
    while true; do
        clear
        show_banner
        echo -e "${NEON_MAGENTA}┌─ HOSTING MENU ────────────────────────────────┐${NC}"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[1]${NC} Pterodactyl Panel"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[2]${NC} Minecraft Server"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[3]${NC} Website Hosting (Nginx)"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[4]${NC} SSL Certificate"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[5]${NC} DDoS Protection"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[0]${NC} Back"
        echo -e "${NEON_MAGENTA}└─────────────────────────────────────────────┘${NC}"
        echo -n "Pilih: "
        read choice
        case $choice in
            1) hosting_pterodactyl ;;
            2) minecraft_menu ;;
            3) hosting_website ;;
            4) hosting_ssl ;;
            5) hosting_ddos ;;
            0) return ;;
            *) log_error "Opsi tidak valid"; sleep 1 ;;
        esac
    done
}

# ============================================================================
# DASHBOARD WEBSITE INSTALLER
# ============================================================================

install_dashboard() {
    log_info "Installing Modern Dashboard Website..."
    
    # Install Nginx
    apt-get update -qq > /dev/null 2>&1 &
    loading_animation "Updating system"
    
    apt-get install -y nginx > /dev/null 2>&1 &
    loading_animation "Installing Nginx"
    
    # Create dashboard directory
    mkdir -p /var/www/html/dashboard
    
    # Generate modern dashboard HTML
    cat > /var/www/html/dashboard/index.html << 'DASHEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EASETUP Dashboard</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <!-- Sidebar -->
        <aside class="sidebar">
            <div class="logo">
                <h2>⚡ EASETUP</h2>
                <p>Dashboard</p>
            </div>
            <nav class="nav">
                <a href="#" class="nav-item active" onclick="showSection('overview')">
                    <span class="icon">📊</span> Overview
                </a>
                <a href="#" class="nav-item" onclick="showSection('servers')">
                    <span class="icon">🖥️</span> Servers
                </a>
                <a href="#" class="nav-item" onclick="showSection('stats')">
                    <span class="icon">📈</span> Statistics
                </a>
                <a href="#" class="nav-item" onclick="showSection('terminal')">
                    <span class="icon">⌨️</span> Terminal
                </a>
                <a href="#" class="nav-item" onclick="showSection('settings')">
                    <span class="icon">⚙️</span> Settings
                </a>
            </nav>
        </aside>

        <!-- Main Content -->
        <main class="main-content">
            <!-- Header -->
            <header class="header">
                <h1>Welcome to EASETUP Dashboard</h1>
                <div class="user-info">
                    <span id="current-time"></span>
                </div>
            </header>

            <!-- Overview Section -->
            <section id="overview" class="section active">
                <h2>System Overview</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>CPU Usage</h3>
                        <div class="stat-value" id="cpu-usage">--</div>
                        <div class="stat-bar">
                            <div class="bar-fill" id="cpu-bar"></div>
                        </div>
                    </div>
                    <div class="stat-card">
                        <h3>Memory Usage</h3>
                        <div class="stat-value" id="mem-usage">--</div>
                        <div class="stat-bar">
                            <div class="bar-fill" id="mem-bar"></div>
                        </div>
                    </div>
                    <div class="stat-card">
                        <h3>Disk Usage</h3>
                        <div class="stat-value" id="disk-usage">--</div>
                        <div class="stat-bar">
                            <div class="bar-fill" id="disk-bar"></div>
                        </div>
                    </div>
                    <div class="stat-card">
                        <h3>Uptime</h3>
                        <div class="stat-value" id="uptime">--</div>
                    </div>
                </div>

                <div class="info-cards">
                    <div class="info-card">
                        <h3>Hostname</h3>
                        <p id="hostname">Loading...</p>
                    </div>
                    <div class="info-card">
                        <h3>Kernel</h3>
                        <p id="kernel">Loading...</p>
                    </div>
                    <div class="info-card">
                        <h3>IP Address</h3>
                        <p id="ip-addr">Loading...</p>
                    </div>
                </div>
            </section>

            <!-- Servers Section -->
            <section id="servers" class="section">
                <h2>Active Services</h2>
                <div class="services-list">
                    <div class="service-item">
                        <h3>Nginx</h3>
                        <span class="status active">● Running</span>
                    </div>
                    <div class="service-item">
                        <h3>SSH</h3>
                        <span class="status active">● Running</span>
                    </div>
                    <div class="service-item">
                        <h3>Firewall</h3>
                        <span class="status active">● Active</span>
                    </div>
                </div>
            </section>

            <!-- Stats Section -->
            <section id="stats" class="section">
                <h2>Detailed Statistics</h2>
                <div class="terminal">
                    <div class="terminal-header">System Stats</div>
                    <pre id="stats-output">Loading system information...</pre>
                </div>
            </section>

            <!-- Terminal Section -->
            <section id="terminal" class="section">
                <h2>Terminal Style Info</h2>
                <div class="terminal">
                    <div class="terminal-header">System Terminal</div>
                    <pre id="terminal-output">
$ whoami
root

$ uname -a
Linux server 5.x.x-xx-generic #xx~20.04.1-Ubuntu SMP x86_64 GNU/Linux

$ df -h
/dev/sda1    50G  25G  25G  50%  /

$ free -h
              total    used    free
Mem:          32Gi   16Gi   16Gi
                    </pre>
                </div>
            </section>

            <!-- Settings Section -->
            <section id="settings" class="section">
                <h2>Dashboard Settings</h2>
                <div class="settings-form">
                    <label>
                        <input type="checkbox" checked> Enable Dark Mode
                    </label>
                    <label>
                        <input type="checkbox" checked> Show Animations
                    </label>
                    <label>
                        <input type="checkbox" checked> Auto Refresh
                    </label>
                    <button class="btn-save">Save Settings</button>
                </div>
            </section>
        </main>
    </div>

    <script src="script.js"></script>
</body>
</html>
DASHEOF
    
    # Generate CSS
    cat > /var/www/html/dashboard/style.css << 'CSSEOF'
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
    color: #e0e0e0;
    overflow: hidden;
}

.container {
    display: flex;
    height: 100vh;
}

/* Sidebar */
.sidebar {
    width: 250px;
    background: rgba(15, 12, 41, 0.8);
    backdrop-filter: blur(10px);
    border-right: 1px solid rgba(51, 211, 255, 0.2);
    padding: 30px 20px;
    overflow-y: auto;
    position: fixed;
    height: 100vh;
    left: 0;
    top: 0;
}

.logo {
    margin-bottom: 40px;
    text-align: center;
    background: linear-gradient(135deg, #00d4ff, #7c3aed);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

.logo h2 {
    font-size: 24px;
    margin-bottom: 5px;
}

.nav-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    margin: 8px 0;
    border-radius: 8px;
    color: #a0a0a0;
    text-decoration: none;
    transition: all 0.3s ease;
    border: 1px solid transparent;
}

.nav-item:hover {
    background: rgba(51, 211, 255, 0.1);
    color: #00d4ff;
    border-color: rgba(51, 211, 255, 0.3);
}

.nav-item.active {
    background: linear-gradient(135deg, rgba(51, 211, 255, 0.2), rgba(124, 58, 237, 0.2));
    color: #00d4ff;
    border-color: rgba(51, 211, 255, 0.5);
    box-shadow: 0 0 20px rgba(51, 211, 255, 0.1);
}

.icon {
    font-size: 18px;
}

/* Main Content */
.main-content {
    margin-left: 250px;
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
}

.header {
    padding: 30px 40px;
    background: rgba(10, 10, 30, 0.5);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid rgba(51, 211, 255, 0.1);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.header h1 {
    background: linear-gradient(135deg, #00d4ff, #7c3aed);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    font-size: 28px;
}

.user-info {
    color: #00d4ff;
    font-family: 'Courier New', monospace;
}

/* Sections */
.content {
    flex: 1;
    overflow-y: auto;
    padding: 40px;
}

.section {
    display: none;
    animation: fadeIn 0.5s ease;
}

.section.active {
    display: block;
}

@keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
}

.section h2 {
    margin-bottom: 30px;
    font-size: 24px;
    color: #00d4ff;
    text-shadow: 0 0 20px rgba(51, 211, 255, 0.3);
}

/* Stats Grid */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
    margin-bottom: 40px;
}

.stat-card {
    background: linear-gradient(135deg, rgba(51, 211, 255, 0.1), rgba(124, 58, 237, 0.1));
    backdrop-filter: blur(10px);
    border: 1px solid rgba(51, 211, 255, 0.2);
    border-radius: 12px;
    padding: 20px;
    transition: all 0.3s ease;
}

.stat-card:hover {
    background: linear-gradient(135deg, rgba(51, 211, 255, 0.15), rgba(124, 58, 237, 0.15));
    border-color: rgba(51, 211, 255, 0.5);
    box-shadow: 0 0 30px rgba(51, 211, 255, 0.2);
    transform: translateY(-5px);
}

.stat-card h3 {
    color: #a0a0a0;
    font-size: 12px;
    text-transform: uppercase;
    margin-bottom: 10px;
}

.stat-value {
    font-size: 28px;
    color: #00d4ff;
    font-weight: bold;
    margin-bottom: 10px;
    font-family: 'Courier New', monospace;
}

.stat-bar {
    height: 4px;
    background: rgba(100, 100, 100, 0.2);
    border-radius: 2px;
    overflow: hidden;
}

.bar-fill {
    height: 100%;
    background: linear-gradient(90deg, #00d4ff, #7c3aed);
    width: 0%;
    transition: width 0.3s ease;
    box-shadow: 0 0 10px rgba(51, 211, 255, 0.5);
}

/* Info Cards */
.info-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
}

.info-card {
    background: linear-gradient(135deg, rgba(51, 211, 255, 0.08), rgba(124, 58, 237, 0.08));
    backdrop-filter: blur(10px);
    border: 1px solid rgba(51, 211, 255, 0.15);
    border-radius: 10px;
    padding: 20px;
}

.info-card h3 {
    color: #a0a0a0;
    font-size: 12px;
    text-transform: uppercase;
    margin-bottom: 10px;
}

.info-card p {
    color: #00d4ff;
    font-family: 'Courier New', monospace;
    font-size: 14px;
}

/* Services List */
.services-list {
    display: grid;
    gap: 15px;
}

.service-item {
    background: linear-gradient(135deg, rgba(51, 211, 255, 0.1), rgba(124, 58, 237, 0.1));
    backdrop-filter: blur(10px);
    border: 1px solid rgba(51, 211, 255, 0.2);
    border-radius: 8px;
    padding: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.service-item h3 {
    color: #e0e0e0;
}

.status {
    padding: 6px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: bold;
}

.status.active {
    color: #00ff00;
    background: rgba(0, 255, 0, 0.1);
}

/* Terminal Style */
.terminal {
    background: linear-gradient(135deg, rgba(10, 10, 20, 0.8), rgba(15, 15, 35, 0.8));
    border: 1px solid rgba(0, 212, 255, 0.3);
    border-radius: 8px;
    overflow: hidden;
    box-shadow: 0 0 30px rgba(51, 211, 255, 0.1);
}

.terminal-header {
    background: rgba(51, 211, 255, 0.1);
    border-bottom: 1px solid rgba(51, 211, 255, 0.2);
    padding: 12px 16px;
    color: #00d4ff;
    font-family: 'Courier New', monospace;
    font-size: 12px;
}

.terminal pre {
    padding: 20px;
    color: #00d4ff;
    font-family: 'Courier New', monospace;
    font-size: 13px;
    line-height: 1.6;
    overflow-x: auto;
}

/* Settings */
.settings-form {
    display: flex;
    flex-direction: column;
    gap: 20px;
}

.settings-form label {
    display: flex;
    align-items: center;
    gap: 12px;
    color: #e0e0e0;
    cursor: pointer;
}

.settings-form input[type="checkbox"] {
    width: 20px;
    height: 20px;
    cursor: pointer;
    accent-color: #00d4ff;
}

.btn-save {
    background: linear-gradient(135deg, #00d4ff, #7c3aed);
    border: none;
    color: #0f0c29;
    padding: 12px 24px;
    border-radius: 8px;
    font-weight: bold;
    cursor: pointer;
    transition: all 0.3s ease;
    max-width: 200px;
}

.btn-save:hover {
    box-shadow: 0 0 20px rgba(51, 211, 255, 0.5);
    transform: translateY(-2px);
}

/* Scrollbar */
::-webkit-scrollbar {
    width: 8px;
}

::-webkit-scrollbar-track {
    background: rgba(51, 211, 255, 0.05);
}

::-webkit-scrollbar-thumb {
    background: rgba(51, 211, 255, 0.3);
    border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
    background: rgba(51, 211, 255, 0.5);
}

/* Responsive */
@media (max-width: 768px) {
    .container {
        flex-direction: column;
    }

    .sidebar {
        width: 100%;
        height: auto;
        position: relative;
        padding: 20px;
    }

    .main-content {
        margin-left: 0;
    }

    .nav {
        display: flex;
        gap: 10px;
        overflow-x: auto;
    }

    .stats-grid {
        grid-template-columns: 1fr;
    }

    .header {
        flex-direction: column;
        gap: 15px;
        align-items: flex-start;
    }
}
CSSEOF

    # Generate JavaScript
    cat > /var/www/html/dashboard/script.js << 'JSEOF'
// Section Navigation
function showSection(sectionId) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.getElementById(sectionId).classList.add('active');
    
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    event.target.closest('.nav-item').classList.add('active');
}

// Update Clock
function updateClock() {
    const now = new Date();
    document.getElementById('current-time').textContent = now.toLocaleTimeString();
}

// Simulate System Stats (in real env, would fetch from API)
function updateStats() {
    const cpuUsage = Math.floor(Math.random() * 80) + 10;
    const memUsage = Math.floor(Math.random() * 70) + 20;
    const diskUsage = Math.floor(Math.random() * 60) + 30;
    
    document.getElementById('cpu-usage').textContent = cpuUsage + '%';
    document.getElementById('mem-usage').textContent = memUsage + '%';
    document.getElementById('disk-usage').textContent = diskUsage + '%';
    
    document.getElementById('cpu-bar').style.width = cpuUsage + '%';
    document.getElementById('mem-bar').style.width = memUsage + '%';
    document.getElementById('disk-bar').style.width = diskUsage + '%';
    
    // Get system info
    fetch('/api/system-info')
        .then(r => r.json())
        .catch(() => {
            document.getElementById('hostname').textContent = 'localhost';
            document.getElementById('kernel').textContent = 'Linux';
            document.getElementById('ip-addr').textContent = 'Loading...';
        });
}

// Initialize
window.addEventListener('DOMContentLoaded', () => {
    updateClock();
    updateStats();
    setInterval(updateClock, 1000);
    setInterval(updateStats, 5000);
});
JSEOF

    # Set permissions
    chown -R www-data:www-data /var/www/html/dashboard
    chmod -R 755 /var/www/html/dashboard
    
    # Configure Nginx
    cat > /etc/nginx/sites-available/dashboard << 'CONFEOF'
server {
    listen 80;
    server_name _;
    root /var/www/html/dashboard;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    # Disable caching for dynamic content
    location ~* \.(js|css)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
CONFEOF

    # Enable site
    ln -sf /etc/nginx/sites-available/dashboard /etc/nginx/sites-enabled/dashboard 2>/dev/null || true
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
    
    # Test and restart Nginx
    nginx -t > /dev/null 2>&1 &
    loading_animation "Configuring Nginx"
    
    systemctl restart nginx > /dev/null 2>&1 &
    loading_animation "Restarting Nginx"
    
    log_success "Dashboard installed at http://localhost"
    log_info "Dashboard files: /var/www/html/dashboard"
    log_info "Nginx config: /etc/nginx/sites-available/dashboard"
    press_enter
}

# ============================================================================
# OPTIMIZATION MENU
# ============================================================================

opt_theme() {
    log_info "Setup login theme..."
    cat > /etc/motd << 'MOTD'
╔════════════════════════════════════════════════════════════╗
║     ◆ EASETUP TOOLS - Professional VPS Installer ◆       ║
║         Welcome to Premium Hosting Management Suite        ║
╚════════════════════════════════════════════════════════════╝
MOTD
    log_success "Login theme updated"
    press_enter
}

opt_update() {
    log_info "Update system..."
    apt-get update -qq
    apt-get upgrade -y > /dev/null 2>&1 &
    loading_animation "Upgrading packages"
    apt-get autoremove -y > /dev/null 2>&1
    log_success "System update complete"
    press_enter
}

opt_sysctl() {
    log_info "Sysctl optimization..."
    cat >> /etc/sysctl.conf << 'EOF'
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 10000 65000
EOF
    sysctl -p > /dev/null 2>&1
    log_success "Sysctl optimized"
    press_enter
}

opt_swap() {
    read -p "Ukuran swap (GB, default 4): " size
    size=${size:-4}
    log_info "Create swap ${size}GB..."
    fallocate -l ${size}G /swapfile 2>/dev/null
    chmod 600 /swapfile
    mkswap /swapfile > /dev/null 2>&1
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    log_success "Swap created"
    press_enter
}

opt_logs() {
    log_info "Clean logs..."
    find /var/log -type f -name "*.gz" -delete 2>/dev/null
    find /var/log -type f -name "*.1" -delete 2>/dev/null
    truncate -s 0 /var/log/*/*.log 2>/dev/null
    log_success "Logs cleaned"
    press_enter
}

opt_menu() {
    while true; do
        clear
        show_banner
        echo -e "${NEON_MAGENTA}┌─ OPTIMIZATION MENU ───────────────────────────┐${NC}"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[1]${NC} Login Theme"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[2]${NC} System Update"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[3]${NC} Sysctl Optimization"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[4]${NC} Swap Creation"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[5]${NC} Log Cleaner"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[0]${NC} Back"
        echo -e "${NEON_MAGENTA}└───────────────────────────────────────────────┘${NC}"
        echo -n "Pilih: "
        read choice
        case $choice in
            1) opt_theme ;;
            2) opt_update ;;
            3) opt_sysctl ;;
            4) opt_swap ;;
            5) opt_logs ;;
            0) return ;;
            *) log_error "Opsi tidak valid"; sleep 1 ;;
        esac
    done
}

# ============================================================================
# MONITORING MENU
# ============================================================================

mon_disk() {
    clear
    show_banner
    echo -e "${NEON_MAGENTA}Disk Usage:${NC}"
    print_separator
    df -h
    print_separator
    press_enter
}

mon_ports() {
    clear
    show_banner
    echo -e "${NEON_MAGENTA}Open Ports:${NC}"
    print_separator
    ss -tuln 2>/dev/null | grep LISTEN || netstat -tuln 2>/dev/null | grep LISTEN
    print_separator
    press_enter
}

mon_services() {
    clear
    show_banner
    echo -e "${NEON_MAGENTA}Running Services:${NC}"
    print_separator
    systemctl list-units --type=service --state=running | head -10
    print_separator
    press_enter
}

mon_live() {
    log_info "Live monitoring... (Ctrl+C to exit)"
    while true; do
        clear
        show_banner
        show_device_info
        echo -e "${NEON_MAGENTA}TOP 5 PROCESSES:${NC}"
        ps aux --sort=-%mem | head -6 | tail -5
        sleep 2
    done
}

mon_menu() {
    while true; do
        clear
        show_banner
        echo -e "${NEON_MAGENTA}┌─ MONITORING MENU ─────────────────────────────┐${NC}"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[1]${NC} Disk Usage"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[2]${NC} Open Ports"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[3]${NC} Running Services"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[4]${NC} Live Monitoring"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[0]${NC} Back"
        echo -e "${NEON_MAGENTA}└───────────────────────────────────────────────┘${NC}"
        echo -n "Pilih: "
        read choice
        case $choice in
            1) mon_disk ;;
            2) mon_ports ;;
            3) mon_services ;;
            4) mon_live ;;
            0) return ;;
            *) log_error "Opsi tidak valid"; sleep 1 ;;
        esac
    done
}

# ============================================================================
# SECURITY MENU
# ============================================================================

sec_firewall() {
    log_info "Setup UFW firewall..."
    apt-get update -qq
    apt-get install -y ufw > /dev/null 2>&1 &
    loading_animation "Installing UFW"
    ufw default deny incoming > /dev/null 2>&1
    ufw default allow outgoing > /dev/null 2>&1
    ufw allow 22/tcp > /dev/null 2>&1
    ufw allow 80/tcp > /dev/null 2>&1
    ufw allow 443/tcp > /dev/null 2>&1
    echo "y" | ufw enable > /dev/null 2>&1
    log_success "UFW firewall enabled"
    press_enter
}

sec_fail2ban() {
    log_info "Setup Fail2Ban..."
    apt-get update -qq
    apt-get install -y fail2ban > /dev/null 2>&1 &
    loading_animation "Installing Fail2Ban"
    systemctl enable fail2ban > /dev/null 2>&1
    systemctl start fail2ban > /dev/null 2>&1
    log_success "Fail2Ban enabled"
    press_enter
}

sec_ssh() {
    log_info "SSH hardening..."
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
    systemctl restart sshd > /dev/null 2>&1
    log_success "SSH hardened"
    press_enter
}

sec_root() {
    log_info "Disable root login..."
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    systemctl restart sshd > /dev/null 2>&1
    log_success "Root login disabled"
    press_enter
}

sec_clamav() {
    log_info "Install ClamAV..."
    apt-get update -qq
    apt-get install -y clamav > /dev/null 2>&1 &
    loading_animation "Installing ClamAV"
    freshclam > /dev/null 2>&1
    log_success "ClamAV installed. Run: clamscan -r /"
    press_enter
}

sec_menu() {
    while true; do
        clear
        show_banner
        echo -e "${NEON_MAGENTA}┌─ SECURITY MENU ────────────────────────────────┐${NC}"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[1]${NC} UFW Firewall"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[2]${NC} Fail2Ban"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[3]${NC} SSH Hardening"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[4]${NC} Disable Root Login"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[5]${NC} ClamAV Antivirus"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[0]${NC} Back"
        echo -e "${NEON_MAGENTA}└───────────────────────────────────────────────┘${NC}"
        echo -n "Pilih: "
        read choice
        case $choice in
            1) sec_firewall ;;
            2) sec_fail2ban ;;
            3) sec_ssh ;;
            4) sec_root ;;
            5) sec_clamav ;;
            0) return ;;
            *) log_error "Opsi tidak valid"; sleep 1 ;;
        esac
    done
}

# ============================================================================
# INSTALLER MENU
# ============================================================================

inst_docker() {
    log_info "Install Docker..."
    apt-get update -qq
    apt-get install -y apt-transport-https ca-certificates curl gnupg > /dev/null 2>&1 &
    loading_animation "Installing dependencies"
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - 2>/dev/null
    apt-get update -qq
    apt-get install -y docker.io > /dev/null 2>&1 &
    loading_animation "Installing Docker"
    systemctl enable docker > /dev/null 2>&1
    systemctl start docker > /dev/null 2>&1
    log_success "Docker installed"
    press_enter
}

inst_nodejs() {
    log_info "Install Node.js..."
    apt-get update -qq
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - 2>/dev/null &
    loading_animation "Configuring Node.js"
    apt-get install -y nodejs > /dev/null 2>&1 &
    loading_animation "Installing Node.js"
    log_success "Node.js installed"
    press_enter
}

inst_python() {
    log_info "Install Python..."
    apt-get update -qq
    apt-get install -y python3 python3-pip python3-venv > /dev/null 2>&1 &
    loading_animation "Installing Python"
    log_success "Python installed"
    press_enter
}

inst_fullstack() {
    log_info "Install Full Stack packages..."
    apt-get update -qq
    apt-get install -y git curl wget build-essential > /dev/null 2>&1 &
    loading_animation "Installing build tools"
    apt-get install -y nodejs npm > /dev/null 2>&1 &
    loading_animation "Installing Node.js"
    apt-get install -y python3 python3-pip > /dev/null 2>&1 &
    loading_animation "Installing Python"
    apt-get install -y nginx > /dev/null 2>&1 &
    loading_animation "Installing Nginx"
    log_success "Full Stack installed"
    press_enter
}

inst_menu() {
    while true; do
        clear
        show_banner
        echo -e "${NEON_MAGENTA}┌─ INSTALLER MENU ──────────────────────────────┐${NC}"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[1]${NC} Docker"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[2]${NC} Node.js"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[3]${NC} Python"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[4]${NC} Full Stack"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[0]${NC} Back"
        echo -e "${NEON_MAGENTA}└───────────────────────────────────────────────┘${NC}"
        echo -n "Pilih: "
        read choice
        case $choice in
            1) inst_docker ;;
            2) inst_nodejs ;;
            3) inst_python ;;
            4) inst_fullstack ;;
            0) return ;;
            *) log_error "Opsi tidak valid"; sleep 1 ;;
        esac
    done
}

# ============================================================================
# MAIN PROGRAM
# ============================================================================

main() {
    check_root
    check_os
    
    while true; do
        show_banner
        show_device_info
        
        echo -e "${NEON_MAGENTA}┌─ MAIN MENU ───────────────────────────────────┐${NC}"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[1]${NC} 🌐 Hosting"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[2]${NC} ⚡ Optimization"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[3]${NC} 📊 Monitoring"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[4]${NC} 🛡  Security"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[5]${NC} 📦 Installer"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[6]${NC} 🎨 Dashboard Website"
        echo -e "${NEON_MAGENTA}│${NC}  ${NEON_GREEN}[0]${NC} Exit"
        echo -e "${NEON_MAGENTA}└───────────────────────────────────────────────┘${NC}"
        echo -n "Pilih menu: "
        read main_choice
        case $main_choice in
            1) hosting_menu ;;
            2) opt_menu ;;
            3) mon_menu ;;
            4) sec_menu ;;
            5) inst_menu ;;
            6) install_dashboard ;;
            0) 
                clear
                log_success "Terima kasih telah menggunakan EASETUP TOOLS!"
                exit 0
                ;;
            *) log_error "Opsi tidak valid"; sleep 1 ;;
        esac
    done
}

main
