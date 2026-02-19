#!/bin/bash

echo "=========================================="
echo "AD Enumeration Toolkit - Installation"
echo "For CTF & Authorized Testing Only"
echo "=========================================="
echo ""

# Vérifier si Python 3 est installé
if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 is not installed. Please install it first."
    exit 1
fi

echo "[+] Python 3 found: $(python3 --version)"

# Installer pip si nécessaire
if ! command -v pip3 &> /dev/null; then
    echo "[+] Installing pip3..."
    sudo apt-get update
    sudo apt-get install -y python3-pip
fi

echo "[+] Installing Python dependencies..."
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt

# Rendre les scripts exécutables
echo "[+] Making scripts executable..."
chmod +x ad_acl_enum.py
chmod +x ad_stealth_enum.py
chmod +x ad_exploit_helper.py

echo ""
echo "=========================================="
echo "Installation complete!"
echo "=========================================="
echo ""
echo "Available tools:"
echo "  1. ad_acl_enum.py        - Basic AD enumeration"
echo "  2. ad_stealth_enum.py    - Stealth enumeration with OPSEC features"
echo "  3. ad_exploit_helper.py  - Exploitation command generator"
echo ""
echo "Quick start:"
echo "  ./ad_stealth_enum.py -d domain.local -u user -p 'pass' -dc 10.10.10.10 --mode minimal"
echo ""
echo "For more information, read the README.md"
echo ""

# Créer un répertoire pour les résultats
echo "[+] Creating results directory..."
mkdir -p results

echo ""
echo "Optional: Install Impacket for exploitation"
echo "  pip3 install impacket"
echo ""
echo "Optional: Install other useful tools"
echo "  sudo apt-get install -y bloodhound neo4j netexec"
echo ""
