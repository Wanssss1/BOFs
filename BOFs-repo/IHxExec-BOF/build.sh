#!/bin/bash
# IHxExec Build Script
# Compiles the BOF automatically

set -e

echo ""
echo "=========================================="
echo "       IHxExec BOF Build Script"
echo "=========================================="
echo ""

# Check if running as root for apt install
install_mingw() {
    echo "[*] Installing mingw-w64..."
    if [ "$EUID" -eq 0 ]; then
        apt update && apt install -y mingw-w64
    else
        sudo apt update && sudo apt install -y mingw-w64
    fi
}

# Check for mingw-w64
if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo "[!] mingw-w64 not found"
    read -p "[?] Install mingw-w64? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_mingw
    else
        echo "[-] Cannot compile without mingw-w64"
        exit 1
    fi
fi

echo "[+] mingw-w64 found: $(which x86_64-w64-mingw32-gcc)"
echo ""

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Compile
echo "[*] Compiling IHxExec BOF..."
make clean 2>/dev/null || true
make

echo ""
echo "=========================================="
echo "            Build Complete!"
echo "=========================================="
echo ""
echo "=== Cobalt Strike ==="
echo "  1. Script Manager -> Load"
echo "  2. Select: cobaltstrike/ihxexec.cna"
echo ""
echo "=== Commands ==="
echo "  ihxexec <session_id> <executable_path>"
echo "  sessions"
echo ""
echo "=== Example ==="
echo "  sessions"
echo "  ihxexec 1 C:\\Windows\\System32\\calc.exe"
echo ""
