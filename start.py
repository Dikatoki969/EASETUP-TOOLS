#!/usr/bin/env python3

import os
import subprocess
import questionary
import webbrowser
import psutil
import platform
from rich.console import Console
from rich.panel import Panel
from rich.live import Live
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text  
from rich.align import Align
from rich import box
import time
import shutil

console = Console()

# =====================
# BANNER
# =====================

def banner():
    console.clear()  # bersihkan console dulu

    # Ambil info sistem
    cpu = platform.processor()
    ram = f"{round(psutil.virtual_memory().total / (1024**3), 2)} GB"
    disk_total, disk_used, disk_free = shutil.disk_usage("/")
    disk = f"{round(disk_used/(1024**3),2)} / {round(disk_total/(1024**3),2)} GB"
    py_version = platform.python_version()
    compatible = "✅ Compatible" if psutil.virtual_memory().total >= 2*(1024**3) else "⚠ Might be low RAM"

    # Panel utama
    panel_text = Text()
    panel_text.append(f"Device  : {platform.node()} ({platform.system()} {platform.release()})\n", style="white")
    panel_text.append(f"CPU     : {cpu}\n", style="white")
    panel_text.append(f"RAM     : {ram}\n", style="white")
    panel_text.append(f"Disk    : {disk}\n", style="white")
    panel_text.append(f"Status  : {compatible}\n", style="green" if "✅" in compatible else "red")

    panel = Panel(
        Align.center(panel_text),
        border_style="bright_blue",
        box=box.DOUBLE,
        padding=(1,2),
        title="● DEVICE CHEK ●",
        subtitle="EASETUP - SCRIPT"
    )

    console.print(panel)

    # Pesan peringatan di bawah panel
    warning = Text()
    warning.append("⚠ Gunakan tools ini dengan bijak. \n", style="bold red")
    warning.append("💡 Selalu backup data penting sebelum melakukan perubahan.\n", style="green")
    console.print(Align.center(warning))

# =====================
# OPEN WEBSITE
# =====================

def open_blog():
    url = "https://dikatoki969.github.io/Dikatoki969"

    system = platform.system()  # Deteksi OS

    try:
        if system == "Linux":
            # Termux biasanya Linux + Android
            if "ANDROID_ROOT" in os.environ:
                os.system(f"termux-open-url {url}")  # Termux
            else:
                webbrowser.open(url)  # Linux PC
        elif system == "Windows":
            os.startfile(url)  # Windows
        elif system == "Darwin":
            os.system(f"open {url}")  # macOS
        else:
            webbrowser.open(url)  # fallback
    except Exception:
        webbrowser.open(url)  # fallback kalau error

# =====================
# SPINNER
# =====================

def run_cmd2(cmd):
    subprocess.run(cmd, shell=True, check=True)
    
def run_cmd(cmd, text):
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold white]{task.description}"),
        console=console
    ) as progress:
        progress.add_task(text, total=None)
        subprocess.run(cmd, shell=True)

    console.print("[bold green]✔ Done[/bold green]\n")
    
def loading_main():
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]Loading Main Menu...[/bold cyan]"),
        console=console
    ) as progress:
        task = progress.add_task("loading", total=100)
        for i in range(20):  # animasi 20 langkah
            time.sleep(0.1)
            progress.update(task, advance=5)
    console.clear()  # bersihkan layar setelah loading selesai

# =====================
# SMART INSTALL
# =====================

def is_installed(pkg):
    result = subprocess.run(
        f"dpkg -s {pkg}",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return result.returncode == 0


def smart_install(packages):
    for pkg in packages:
        if is_installed(pkg):
            console.print(f"[green]✔ {pkg} already installed[/green]")
        else:
            run_cmd(f"apt install {pkg} -y", f"Installing {pkg}...")

# =====================
# CHANGE LOGIN BANNER
# =====================
    
def change_login_banner():
    choice = questionary.select(
        "Login Welcome Banner:",
        choices=[
            "Set Default (Default Easetup Banner)",
            "Set Custom Banner",
            "Back"
        ]
    ).ask()

    if choice == "Set Default (Default Easetup Banner)":

        banner_script = """#!/bin/bash
        
OS_NAME=$(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
UPTIME=$(uptime -p)
CPU_LOAD=$(top -bn1 | grep load | awk '{printf "%.2f", $(NF-2)}')
RAM_USAGE=$(free -m | awk '/Mem:/ {printf "%d/%dMB (%.0f%%)", $3, $2, $3*100/$2 }')
DISK_USAGE=$(df -h / | awk 'NR==2 {printf "%s / %s (%s)", $3, $2, $5}')
LOCAL_IP=$(hostname -I | awk '{print $1}')
PUBLIC_IP=$(curl -s ifconfig.me)

RED="\033[31m"
ORANGE="\033[33m"
YELLOW="\033[93m"
GREEN="\033[32m"
CYAN="\033[36m"
BLUE="\033[34m"
MAGENTA="\033[35m"
RESET="\033[0m"

# Fungsi buat print border warna
function border {
    echo -e "${1}$2${RESET}"
}
clear
echo
border $RED    "╔════════════════════════════════════════════════════╗"
border $ORANGE "║         E A S E T U P - S E R V E R"
border $YELLOW "╠════════════════════════════════════════════════════╣"
echo -e "${GREEN}║ Blog         : ${RESET}https://dikatoki969.github.io/Dikatoki969"
echo -e "${GREEN}║ Hostname     : ${RESET}$HOSTNAME"
echo -e "${GREEN}║ OS           : ${RESET}$OS_NAME"
echo -e "${GREEN}║ Uptime       : ${RESET}$UPTIME"
echo -e "${GREEN}║ CPU Load     : ${RESET}$CPU_LOAD"
echo -e "${GREEN}║ RAM Usage    : ${RESET}$RAM_USAGE"
echo -e "${GREEN}║ Disk Usage   : ${RESET}$DISK_USAGE"
echo -e "${GREEN}║ Local IP     : ${RESET}$LOCAL_IP"
echo -e "${GREEN}║ Public IP    : ${RESET}$PUBLIC_IP"
echo -e "${GREEN}║ Date         : ${RESET}$(date)"
border $CYAN "╠════════════════════════════════════════════════════╣"
border $MAGENTA "║   Server Secured • Optimized • Ready"
border $BLUE    "╚════════════════════════════════════════════════════╝"
echo
"""

        with open("/etc/profile.d/easetup_banner.sh", "w") as f:
            f.write(banner_script)

        os.system("chmod +x /etc/profile.d/easetup_banner.sh")

        console.print("[bold green]✔ Premium Easetup banner applied[/bold green]")

    elif choice == "Set Custom Banner":

        text = questionary.text("Enter your custom welcome message:").ask()

        custom_script = f"""#!/bin/bash
clear
echo ""
echo "=============================================="
echo "{text}"
echo "=============================================="
echo ""
"""

        with open("/etc/profile.d/easetup_banner.sh", "w") as f:
            f.write(custom_script)

        os.system("chmod +x /etc/profile.d/easetup_banner.sh")

        console.print("[bold green]✔ Custom login banner updated[/bold green]\n")

# =====================
# HOSTING MENU
# =====================

def game_menu():
    choice = questionary.select(
        "Setup Hosting:",
        choices=[
            "Install Minecraft Server",
            "Install Pterodactyl Panel",
            "Install Rust Server",
            "Host HTML Website",
            "Setup Domain & SSL",
            "Setup DDoS Firewall",
            "Back"
        ]
    ).ask()

    if choice == "Install Minecraft Server":
        run_cmd2("curl -o ~/install.sh https://minetrax.github.io/install.sh && chmod +x ~/install.sh && ~/install.sh")
    elif choice == "Install Pterodactyl Panel":
        run_cmd2("bash <(curl -s https://pterodactyl-installer.se)")
    elif choice == "Install Rust Server":
        run_cmd2("curl -s https://rustserverinstaller.com/install.sh | bash")
    elif choice == "Host HTML Website":
        html_code = questionary.text(
            "Paste HTML code (single line or multiline using \\n):"
        ).ask()
        os.makedirs("/var/www/html", exist_ok=True)
        with open("/var/www/html/index.html", "w") as f:
            f.write(html_code.replace("\\n","\n"))
        run_cmd("systemctl restart nginx")
        console.print("[green]✔ Website hosted di /var/www/html/index.html[/green]")
    elif choice == "Setup Domain & SSL":
        domain = questionary.text("Masukkan nama domain:").ask()
        vhost = f"""
server {{
    listen 80;
    server_name {domain};
    root /var/www/html;
    index index.html;
}}
"""
        os.makedirs("/etc/nginx/sites-available", exist_ok=True)
        os.makedirs("/etc/nginx/sites-enabled", exist_ok=True)

        with open(f"/etc/nginx/sites-available/{domain}", "w") as f:
            f.write(vhost)
        run_cmd2(f"ln -s /etc/nginx/sites-available/{domain} /etc/nginx/sites-enabled/")
        run_cmd2("nginx -t && systemctl reload nginx")
        run_cmd2(f"certbot --nginx -d {domain}")
    elif choice == "Setup DDoS Firewall":
        run_cmd2("ufw allow OpenSSH && ufw enable")
        run_cmd2("apt install fail2ban -y")
        console.print("[green]✔ DDoS Firewall & Fail2Ban aktif[/green]")
    elif choice == "Back":
        return

# =====================
# OPTIMIZATION
# =====================

def optimization_menu():
    choice = questionary.select(
        "Server Optimization:",
        choices=[
            "Auto sysctl Optimize",
            "Create 2GB Swap",
            "Clean Logs",
            "Change Login Welcome Text",
            "Update System",
            "Back"
        ]
    ).ask()

    if choice == "Auto sysctl Optimize":
        run_cmd("echo 'net.core.somaxconn=65535' >> /etc/sysctl.conf && sysctl -p",
                "Optimizing sysctl...")

    elif choice == "Create 2GB Swap":
        run_cmd("fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile",
                "Creating Swap...")

    elif choice == "Clean Logs":
        run_cmd("journalctl --vacuum-time=3d", "Cleaning Logs...")

    elif choice == "Change Login Welcome Text":
        change_login_banner()

    elif choice == "Update System":
        run_cmd("apt update -y && apt upgrade -y", "Updating System...")

# =====================
# MONITORING
# =====================

def monitoring_menu():
    choice = questionary.select(
        "Monitoring:",
        choices=[
            "Live CPU/RAM Monitor",
            "Disk Usage",
            "Open Ports",
            "Running Services",
            "Back"
        ]
    ).ask()

    if choice == "Live CPU/RAM Monitor":
        with Live(refresh_per_second=1) as live:
            for _ in range(20):
                table = Table(title="Live Monitor")
                table.add_column("CPU %")
                table.add_column("RAM %")

                table.add_row(
                    str(psutil.cpu_percent()),
                    str(psutil.virtual_memory().percent)
                )
                live.update(table)
                time.sleep(1)

    elif choice == "Disk Usage":
        console.print(psutil.disk_usage('/'))

    elif choice == "Open Ports":
        os.system("ss -tuln")

    elif choice == "Running Services":
        os.system("systemctl list-units --type=service")

# =====================
# SECURITY MENU
# =====================
def security_menu():
    choice = questionary.select(
        "Security Options:",
        choices=[
            "Setup UFW Firewall",
            "Install & Configure Fail2Ban",
            "Disable Root Login",
            "SSH Hardening",
            "Intrusion Detection (AIDE)",
            "Log Monitoring (Logwatch)",
            "Brute Force Protection",
            "Auto Security Updates",
            "Malware & Rootkit Scan",
            "Backup Configs",
            "Back"
        ]
    ).ask()

    if choice == "Setup UFW Firewall":
        run_cmd("ufw allow OpenSSH && ufw enable", "Configuring Firewall...")

    elif choice == "Install & Configure Fail2Ban":
        run_cmd("apt install fail2ban -y", "Installing Fail2Ban...")
        run_cmd("systemctl enable fail2ban && systemctl start fail2ban", "Starting Fail2Ban...")

    elif choice == "Disable Root Login":
        run_cmd(
            "sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart ssh",
            "Disabling Root Login..."
        )

    elif choice == "SSH Hardening":
        port = questionary.text("Enter new SSH port (e.g., 2222):").ask()
        run_cmd(f"sed -i 's/#Port 22/Port {port}/' /etc/ssh/sshd_config && systemctl restart ssh", f"Setting SSH port to {port}...")
        run_cmd("sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl restart ssh", "Disabling password login for SSH...")

    elif choice == "Intrusion Detection (AIDE)":
        run_cmd("apt install aide -y", "Installing AIDE...")
        run_cmd("aideinit && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db", "Initializing AIDE database...")

    elif choice == "Log Monitoring (Logwatch)":
        run_cmd("apt install logwatch -y", "Installing Logwatch...")
        run_cmd("logwatch --output stdout --detail High", "Running Logwatch report...")

    elif choice == "Brute Force Protection":
        run_cmd("apt install iptables-persistent -y", "Installing iptables persistent rules...")
        run_cmd("iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set", "Adding brute force protection rule...")
        run_cmd("iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 5 -j DROP", "Setting connection limits...")

    elif choice == "Auto Security Updates":
        run_cmd("apt install unattended-upgrades -y", "Installing unattended-upgrades...")
        run_cmd("dpkg-reconfigure --priority=low unattended-upgrades", "Configuring automatic security updates...")

    elif choice == "Malware & Rootkit Scan":
        run_cmd("apt install clamav rkhunter chkrootkit -y", "Installing security scanning tools...")
        run_cmd("freshclam", "Updating ClamAV database...")
        run_cmd("clamscan -r / --bell -i", "Running ClamAV full scan...")
        run_cmd("rkhunter --update && rkhunter --check", "Running Rootkit Hunter scan...")
        run_cmd("chkrootkit", "Running chkrootkit scan...")

    elif choice == "Backup Configs":
        run_cmd("mkdir -p ~/config_backups", "Creating backup folder...")
        run_cmd("cp /etc/ssh/sshd_config ~/config_backups/sshd_config.bak", "Backing up SSH config...")
        run_cmd("cp /etc/ufw/ufw.conf ~/config_backups/ufw.conf.bak", "Backing up UFW config...")
        run_cmd("cp -r /etc/fail2ban ~/config_backups/fail2ban.bak", "Backing up Fail2Ban configs...")

    elif choice == "Back":
        return

# =====================
# USER MANAGEMENT MENU
# =====================

def user_management_menu():
    choice = questionary.select(
        "User Management:",
        choices=[
            "Add User",
            "Delete User",
            "Change Password",
            "List Users",
            "Back"
        ]
    ).ask()

    if choice == "Add User":
        username = questionary.text("Enter new username:").ask()
        password = questionary.password("Enter password:").ask()
        sudo = questionary.confirm("Grant sudo access?").ask()
        cmd = f"useradd -m {username}"
        if sudo:
            cmd += " && usermod -aG sudo {username}"
        run_cmd(f"{cmd} && echo '{username}:{password}' | chpasswd", f"Adding user {username}...")

    elif choice == "Delete User":
        username = questionary.text("Enter username to delete:").ask()
        run_cmd(f"userdel -r {username}", f"Deleting user {username}...")

    elif choice == "Change Password":
        username = questionary.text("Enter username:").ask()
        password = questionary.password("Enter new password:").ask()
        run_cmd(f"echo '{username}:{password}' | chpasswd", f"Changing password for {username}...")

    elif choice == "List Users":
        run_cmd2("cut -d: -f1 /etc/passwd",)

    elif choice == "Back":
        return

# =====================
# INSTALLER
# =====================
def installer_menu():
    choice = questionary.select(
        "Module Installer:",
        choices=[
            "Install Essential Tools",
            "Install Networking Tools",
            "Install Monitoring Tools",
            "Install Security Tools",
            "Install Dev Tools",
            "Install Web Full Stack",
            "Install Database Stack",
            "Install Docker Ecosystem",
            "Install Performance Tools",
            "Install Game Dependencies",
            "Install FULL PACK",
            "Back"
        ]
    ).ask()

    packs = {
        "Install Essential Tools": [
            "curl", "wget", "git", "unzip", "htop", "nano", "vim",
            "net-tools", "software-properties-common",
            "build-essential", "bash-completion"
        ],

        "Install Networking Tools": [
            "net-tools", "dnsutils", "iputils-ping",
            "traceroute", "tcpdump", "nmap",
            "whois", "speedtest-cli"
        ],

        "Install Monitoring Tools": [
            "htop", "glances", "atop",
            "iotop", "iftop", "sysstat", "vnstat"
        ],

        "Install Security Tools": [
            "ufw", "fail2ban", "lynis",
            "chkrootkit", "rkhunter", "clamav"
        ],

        "Install Dev Tools": [
            "nodejs", "npm", "python3",
            "python3-pip", "python3-venv",
            "composer", "gcc", "g++", "make"
        ],

        "Install Web Full Stack": [
            "nginx", "apache2",
            "php", "php-cli", "php-fpm",
            "php-mysql", "php-curl",
            "php-zip", "php-gd", "php-mbstring",
            "mysql-server", "redis-server"
        ],

        "Install Database Stack": [
            "mysql-server", "mariadb-server",
            "postgresql", "mongodb",
            "redis-server"
        ],

        "Install Docker Ecosystem": [
            "docker.io", "docker-compose",
            "containerd"
        ],

        "Install Performance Tools": [
            "tuned", "preload",
            "zram-tools", "cpufrequtils"
        ],

        "Install Game Dependencies": [
            "openjdk-17-jre", "openjdk-21-jre",
            "screen", "tmux", "lib32gcc-s1"
        ]
    }

    if choice == "Install FULL PACK":
        console.print("[bold yellow]Installing FULL PACK...[/bold yellow]\n")

        all_packages = []
        for package_list in packs.values():
            all_packages.extend(package_list)

        # hapus duplikat
        all_packages = list(set(all_packages))

        run_cmd("apt update -y", "Updating Package List...")
        smart_install(all_packages)

        console.print("[bold green]✔ FULL PACK Installed[/bold green]\n")

    elif choice in packs:
        run_cmd("apt update -y", "Updating Package List...")
        smart_install(packs[choice])
        console.print("[bold green]✔ Installation Completed[/bold green]\n")

    elif choice == "Back":
        return
        
        
# =====================
# MAIN MENU
# =====================

def main():
    loading_main()
    while True:
        console.clear()
        if os.geteuid() != 0:
           print("Run as root!")
           return
        banner()
        console.print("[bold cyan]Select an option:[/bold cyan]\n")
        choice = questionary.select(
            "[!]",
            choices=[
                "️[-] Setup Hosting",
                "[-] Server Optimization",
                "[-] Monitoring",
                "[-] Security",
                "[-] User Management",
                "️[-] Installer",
                "[-] Exit"
            ],
            style=questionary.Style([
                ("selected", "fg:green bold"),
                ("pointer", "fg:yellow bold")
                  ])
        ).ask()

        if choice == "️[-] Setup Hosting":
            game_menu()
        elif choice == "[-] Server Optimization":
            optimization_menu()
        elif choice == "[-] Monitoring":
            monitoring_menu()
        elif choice == "[-] Security":
            security_menu()
        elif choice == "[-] User Management":
            user_management_menu()
        elif choice == "️[-] Installer":
            installer_menu()
        elif choice == "[-] Exit":
            console.print("\nBye!")
            break

if __name__ == "__main__":
    main()
    open_blog()
