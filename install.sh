#!/bin/bash
echo "Selamat datang di installer Easetup!"
echo "Update & Install dependency..."
apt update -y && apt install curl git -y
# Pastikan Python3 & pip terinstall
apt update -y && apt install python3 python3-pip -y
# Install module yang dibutuhkan
pip3 install --upgrade pip
pip3 install questionary psutil rich

# Jalankan script utama
curl -s https://raw.githubusercontent.com/username/repo/main/system.py -o ~/start.py
echo "Selesai! Jalankan dengan: python3 ~/start.py"
python3 ~/start.py
