#!/bin/bash
# setup.sh — configura o container local php2shell para o exploit CVE-2026-109618
# Uso: ./setup.sh [PORT]
# Padrão: porta 8080

set -e

IMAGE="php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a"
NAME="php2shell-local"
PORT="${1:-8080}"

echo "[*] Removendo container existente (se houver)..."
docker rm -f "$NAME" 2>/dev/null || true

echo "[*] Iniciando container $NAME (porta $PORT)..."
docker run -d \
  --name "$NAME" \
  -p "$PORT:80" \
  --security-opt seccomp=unconfined \
  "$IMAGE"

echo "[*] Aguardando Apache iniciar..."
sleep 3

# ── PHP: usar php.ini-production como base + overrides do lab ──────────────
echo "[*] Configurando PHP..."
docker exec "$NAME" bash -c '
  # Base: php.ini-production (output_buffering=4096, max_input_vars=1000, etc.)
  cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini

  # Overrides específicos do lab
  cat > /usr/local/etc/php/conf.d/lab.ini << "EOF"
; CVE-2026-109618 lab settings
memory_limit = 8M
post_max_size = 64M
display_errors = On
session.upload_progress.enabled = 1
session.use_strict_mode = 0
EOF
'

# ── Apache: prefork single-worker ─────────────────────────────────────────
echo "[*] Configurando Apache (single worker)..."
docker exec "$NAME" bash -c '
  cat > /etc/apache2/conf-available/lab.conf << "EOF"
ServerLimit 1
MaxRequestWorkers 1
EOF
  a2enconf lab 2>/dev/null || true
'

# ── index.php ─────────────────────────────────────────────────────────────
echo "[*] Criando index.php..."
docker exec "$NAME" bash -c '
  printf "<?php echo \"OK\";" > /var/www/html/index.php
'

# ── proof.txt (flag plantada como www-data, modo 400) ─────────────────────
echo "[*] Plantando proof.txt..."
docker exec "$NAME" bash -c '
  echo "OFFSEC{local_lab_flag_php2shell_CVE-2026-109618}" > /var/www/proof.txt
  chown www-data:www-data /var/www/proof.txt
  chmod 400 /var/www/proof.txt
'

# ── Reinicia Apache graciosamente (sem matar PID 1) ───────────────────────
echo "[*] Recarregando Apache..."
docker exec "$NAME" bash -c 'kill -USR1 1'
sleep 2

# ── Verificação ───────────────────────────────────────────────────────────
echo ""
echo "[*] Verificando configuração..."

echo -n "  index.php: "
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:$PORT/index.php")
echo "HTTP $STATUS"

echo -n "  memory_limit (PHP): "
docker exec "$NAME" php -r "echo ini_get('memory_limit');"
echo ""

echo -n "  upload_progress: "
docker exec "$NAME" php -r "echo ini_get('session.upload_progress.enabled') ? 'On' : 'Off';"
echo ""

echo -n "  use_strict_mode: "
docker exec "$NAME" php -r "echo ini_get('session.use_strict_mode') ? 'On' : 'Off';"
echo ""

echo -n "  MaxRequestWorkers: "
docker exec "$NAME" bash -c 'grep MaxRequestWorkers /etc/apache2/conf-enabled/lab.conf'

echo ""
echo "[+] Container pronto: http://localhost:$PORT/"
echo "[+] Para rodar o exploit: python3 exploit.py --host 127.0.0.1 --port $PORT ..."
