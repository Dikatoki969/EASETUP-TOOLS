#!/bin/bash
echo "Selamat datang di installer Easetup!"
echo "Update & Install dependency..."
apt update -y && apt install curl git -y
apt update -y && apt install python3 python3-pip -y
pip3 install --upgrade pip
pip3 install questionary psutil rich
curl -s https://raw.githubusercontent.com/Dikatoki969/EASETUP-TOOLS/refs/heads/main/start.py -o ~/start.py
echo "Selesai! Jalankan dengan: python ~/start.py"
python ~/start.py
