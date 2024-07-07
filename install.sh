#!/bin/bash

# Colors
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# Execute as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${ORANGE}[!] This Script must be executed as Root${NC}"
  exit 1
fi

# Updating Packets
echo -e "${ORANGE}[+] Updating Packets${NC}"
apt-get update &> /dev/null

# Installing Netexec
echo -e "${ORANGE}[+] Installing netexec${NC}"
apt-get install -y netexec &> /dev/null

# Installing hydra
echo -e "${ORANGE}[+] Installing hydra${NC}"
apt-get install -y hydra &> /dev/null

# Installing snmp
echo -e "${ORANGE}[+] Installing snmp${NC}"
apt-get install -y snmp &> /dev/null

# Installing nmap
echo -e "${ORANGE}[+] Installing nmap${NC}"
apt-get install -y nmap &> /dev/null

echo -e "${GREEN}[V] Installation complete${NC}"
echo -e "${GREEN}[V] Execute python3 ./Trabuco.py"
