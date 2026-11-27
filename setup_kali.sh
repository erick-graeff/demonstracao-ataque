#!/bin/bash
# setup_kali.sh — Baixa os arquivos necessários do GitHub para o Kali
#
# Uso no Kali:
#   curl -sO https://raw.githubusercontent.com/erick-graeff/demonstracao-ataque/refs/heads/main/setup_kali.sh
#   chmod +x setup_kali.sh
#   ./setup_kali.sh
#
# Depois:
#   ./run_shell.sh [TARGET_IP]       → reverse shell
#   ./run_exploit.sh [TARGET_IP]     → só captura a flag

set -eu

REPO="https://raw.githubusercontent.com/erick-graeff/demonstracao-ataque/refs/heads/main"

echo "[*] Baixando arquivos..."
curl -s "$REPO/exploit.py"
curl -sO "$REPO/run_shell.sh"
curl -sO "$REPO/run_exploit.sh"
curl -sO "$REPO/run_all.sh"

chmod +x run_shell.sh run_exploit.sh run_all.sh

echo "[+] Arquivos baixados:"
ls -la exploit.py run_shell.sh run_exploit.sh run_all.sh
echo ""
echo "Uso:"
echo "  ./run_shell.sh [TARGET_IP]    → reverse shell (automatizado)"
echo "  ./run_exploit.sh [TARGET_IP]  → só captura a flag"
