#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ ${EUID} -eq 0 ]] || { echo "Execute como root"; exit 1; }
APP_DIR="/opt/nottina-shield"
[[ -f "$APP_DIR/app.py" ]] || { echo "Clone o repo em $APP_DIR"; exit 1; }
[[ -f /root/.ssh/turbo_poc_ed25519 ]] || { echo "Chave SSH da PoC ausente"; exit 1; }

echo "== Validando sintaxe e testes =="
python3 -m py_compile "$APP_DIR/app.py"
(cd "$APP_DIR" && python3 -m unittest discover -s tests -v)
echo "== Validando SSH e permissao nft no Shield =="
ssh -T -i /root/.ssh/turbo_poc_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=5 lab@172.31.253.14 'sudo -n nft --version'
echo "== Credencial NOVA do painel (não reutilize a senha da VM) =="
python3 - <<'PY'
import getpass,hashlib,os,secrets
password=getpass.getpass("Nova senha do painel: ")
confirm=getpass.getpass("Confirmar senha: ")
if len(password)<12 or password!=confirm:
    raise SystemExit("Senha divergente ou menor que 12 caracteres")
salt=secrets.token_bytes(16)
hashed=salt.hex()+"$"+hashlib.pbkdf2_hmac("sha256",password.encode(),salt,350000).hex()
secret=secrets.token_urlsafe(40)
env = ("ADMIN_USER=admin\n"
       "PASSWORD_HASH="+hashed+"\n"
       "SESSION_SECRET="+secret+"\n"
       "SHIELD_HOST=172.31.253.14\n"
       "SHIELD_USER=lab\n"
       "SHIELD_KEY=/root/.ssh/turbo_poc_ed25519\n"
       "BIND_HOST=127.0.0.1\n"
       "PORT=8787\n"
       "DB_PATH=/var/lib/nottina-shield/console.sqlite3\n")
fd=os.open("/etc/nottina-shield.env", os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
with os.fdopen(fd,"w") as f:f.write(env)
PY
install -d -m 0700 /var/lib/nottina-shield
install -m 0644 "$APP_DIR/deploy/nottina-shield.service" /etc/systemd/system/nottina-shield.service
systemctl daemon-reload
systemctl enable --now nottina-shield
systemctl --no-pager --full status nottina-shield
echo "Console disponivel via tunel: ssh -L 8787:127.0.0.1:8787 root@10.30.5.130"
