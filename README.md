# Nottina Shield Console

Painel operacional para a PoC Anti-DDoS Inline Pré-Borda. Interface escura inspirada em consoles como o Gladius V2. Backend Python 3 (somente biblioteca padrão), SQLite, autenticação PBKDF2, CSRF, gerenciamento de regras **reais** nftables e contadores de descartes.

## Estado validado da PoC (23/10/2026)
- Quatro adjacências BGP estabelecidas.
- Tráfego HTTP legítimo 200 passando por ambas as interfaces do Shield.
- Regra experimental descartou **200 pacotes UDP / 49.600 bytes** no destino `203.0.113.10:8080`.
- Após ativação da regra, HTTP TCP/8080 continuou 200.

Os números acima são evidências do teste; os indicadores do painel são consultados **ao vivo** no kernel e não usam dados fictícios.

## Instalação rápida — no HOST EVE-NG
O EVE-NG já tem chave SSH de acesso ao Shield:
`/root/.ssh/turbo_poc_ed25519` → `lab@172.31.253.14` (com `sudo -n nft`).

```bash
git clone https://github.com/rdzanotto/nottina-shield.git /opt/nottina-shield
cd /opt/nottina-shield
python3 -m py_compile app.py
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'  # SESSION_SECRET
python3 -c 'import getpass,hashlib,secrets; p=getpass.getpass("Senha nova: "); s=secrets.token_hex(16); print(s+"$"+hashlib.pbkdf2_hmac("sha256",p.encode(),bytes.fromhex(s),350000).hex())' # PASSWORD_HASH
```

Configure as variáveis `SHIELD_USER`, `SHIELD_HOST`, `SHIELD_KEY`, `PASSWORD_HASH`, `SESSION_SECRET` e `BIND_HOST`. **Não coloque a senha no repositório.**

```bash
export SHIELD_HOST=172.31.253.14 SHIELD_USER=lab SHIELD_KEY=/root/.ssh/turbo_poc_ed25519
export ADMIN_USER=admin
export PASSWORD_HASH='COLE_O_HASH_AQUI'
export SESSION_SECRET='COLE_O_SEGREDO_AQUI'
export BIND_HOST=127.0.0.1 PORT=8787
python3 app.py
```

Acesse por túnel SSH do Windows: `ssh -L 8787:127.0.0.1:8787 root@10.30.5.130` e depois `http://127.0.0.1:8787`.

Para instalar como systemd, veja `deploy/nottina-shield.service` e `deploy/nottina-shield.env.example`; instale com permissões `0600` e não publique o socket sem TLS/reverse proxy.

## Escopo e segurança
- Gerencia **exclusivamente** `table bridge nottina_ui`, cadeia `forward` (prioridade -5, política accept); **não** altera `turbo_poc_test`, `turbo_egress_guard`, BGP, bridges nem outros conjuntos de regras.
- Comandos nftables executados na **VM Shield**, não no host EVE, via SSH autenticado por chave; parâmetros de regra passam por validação estrita.
- Regras: ação **drop**, direção ingress `ens3`, protocolos TCP/UDP/ICMP, IPv4 destino e origem CIDR opcionais, porta destino TCP/UDP opcional, contador de pacotes e bytes. Exclusão por handle; CSRF em mutações; log de auditoria SQLite.
- O painel mostra contadores lidos do `nft -j list table bridge nottina_ui`, sua própria tabela; atualização automática. A série temporal é registrada por sondagens locais enquanto o processo roda.
- Na primeira execução a tabela isolada é criada, mas **nenhuma regra de drop é criada automaticamente**.
- Alterações em nftables são efêmeras até configuração explícita de persistência. A aplicação não reaplica bloqueios após reboot: escolha deliberada para reduzir risco de interrupção.
- O serviço precisa ter privilégios de acesso à chave SSH (host), e `lab` precisa de `sudo -n nft` na VM. Mantenha o serviço local ou em rede de administração.
- PoC / demonstração: não substitui autenticação corporativa, RBAC, SIEM ou mitigação em line-rate.
