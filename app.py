#!/usr/bin/env python3
"""Nottina Shield Console — stdlib-only operational PoC."""
import base64
import hashlib
import hmac
import http.cookies
import http.server
import ipaddress
import json
import os
import re
import secrets
import shlex
import sqlite3
import subprocess
import threading
import time
import urllib.parse
import engineering
from datetime import datetime, timezone
from pathlib import Path

HOST = os.getenv("BIND_HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8787"))
ADMIN = os.getenv("ADMIN_USER", "admin")
PASSWORD_HASH = os.getenv("PASSWORD_HASH", "")
SECRET = os.getenv("SESSION_SECRET", "")
DB = os.getenv("DB_PATH", "/var/lib/nottina-shield/console.sqlite3")
SHIELD = os.getenv("SHIELD_HOST", "172.31.253.14")
USER = os.getenv("SHIELD_USER", "lab")
KEY = os.getenv("SHIELD_KEY", "/root/.ssh/turbo_poc_ed25519")
TABLE = "nottina_ui"
LOCK = threading.RLock()
SESSIONS = {}
STARTED = time.time()

def dbconn():
    Path(DB).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB, timeout=5)
    c.execute("pragma journal_mode=WAL")
    c.execute("create table if not exists rules (handle integer primary key, name text not null, created text not null)")
    c.execute("create table if not exists audit (id integer primary key autoincrement, ts text, actor text, action text, detail text)")
    c.execute("create table if not exists samples (ts integer, drops integer, bytes integer)")
    c.commit()
    return c

def audit(action, detail):
    with dbconn() as c:
        c.execute("insert into audit(ts,actor,action,detail) values (?,?,?,?)",
                  (datetime.now(timezone.utc).isoformat(), ADMIN, action, detail[:500]))

def remote(script, *, timeout=12):
    args = ["ssh", "-i", KEY, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=5", "-o", "ControlMaster=no", "-T",
            f"{USER}@{SHIELD}", "sudo -n sh -c " + shlex.quote(script)]
    p = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if p.returncode:
        raise RuntimeError((p.stderr or p.stdout or "SSH/nft failed")[:400])
    return p.stdout

def nft(script):
    # Allowed calls are generated solely by this application.
    return remote("nft " + script)

def ensure_table():
    # Never overwrite existing tables or chains. Only operate in our namespace.
    if remote("nft list table bridge " + TABLE + " >/dev/null 2>&1; echo $?").strip() == "0":
        return
    remote("nft add table bridge " + TABLE)
    remote("nft 'add chain bridge " + TABLE + " forward { type filter hook forward priority -5; policy accept; }'")

def raw_table(table=TABLE, optional=False):
    command = "nft -j list table bridge " + table
    if optional:
        command += " 2>/dev/null || true"
    output = remote(command)
    return json.loads(output).get("nftables", []) if output.strip() else []

def expressions(rule):
    # Capture nft-generated expression for inspectable rule details.
    return rule.get("expr", [])

def fetch_state():
    with LOCK:
        ensure_table()
        result = []
        with dbconn() as c:
            labels = {h:n for h,n in c.execute("select handle,name from rules")}
        for entry in raw_table() + raw_table("turbo_poc_test", optional=True):
            if "rule" not in entry:
                continue
            r = entry["rule"]
            table_name = r.get("table")
            if table_name not in (TABLE, "turbo_poc_test") or r.get("chain") != "forward":
                continue
            pkts = byt = 0
            for expr in expressions(r):
                if "counter" in expr:
                    counter = expr["counter"]
                    pkts += int(counter.get("packets",0))
                    byt += int(counter.get("bytes",0))
            handle = int(r["handle"])
            managed = table_name == TABLE
            label = labels.get(handle, f"Regra #{handle}") if managed else "Política PoC existente (legado)"
            result.append({"handle":handle, "name":label, "managed":managed,
                           "table":table_name, "packets":pkts, "bytes":byt, "expr":expressions(r)})
        return result

def build_rule(body):
    name = str(body.get("name","")).strip()
    if not 1 <= len(name) <= 65 or not re.fullmatch(r"[\w .:áéíóúâêôãõç-]+",name,re.I):
        raise ValueError("Nome deve ter 1–65 caracteres válidos")
    proto = str(body.get("protocol","")).lower()
    if proto not in ("udp","tcp","icmp"):
        raise ValueError("Protocolo inválido")
    target = str(body.get("dst","")).strip()
    if not target:
        raise ValueError("Destino IPv4 obrigatório")
    dst = ipaddress.IPv4Network(target, strict=False)
    if dst.prefixlen < 24 or not dst.subnet_of(ipaddress.IPv4Network("203.0.113.0/24")):
        raise ValueError("PoC limitada aos destinos em 203.0.113.0/24")
    src = str(body.get("src","")).strip()
    src_clause = ""
    if src:
        ip = ipaddress.IPv4Network(src, strict=False)
        if not ip.subnet_of(ipaddress.IPv4Network("198.18.0.0/24")):
            raise ValueError("Origem permitida apenas em 198.18.0.0/24")
        src_clause = f"ip saddr {ip.with_prefixlen} "
    port = str(body.get("port","")).strip()
    port_clause = ""
    if proto in ("udp","tcp"):
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError("Porta obrigatória entre 1 e 65535")
        port_clause = f"{proto} dport {int(port)} "
    elif port:
        raise ValueError("ICMP não possui porta")
    # bridge family: ens3 towards downstream only. Management ens5 is never matched.
    command = (f"add rule bridge {TABLE} forward iifname ens3 ether type ip "
               f"ip daddr {dst.with_prefixlen} {src_clause}ip protocol {proto} "
               f"{port_clause}counter drop")
    return name,command

def add_rule(body):
    name, cmd = build_rule(body)
    with LOCK:
        ensure_table()
        before = {r["handle"] for r in fetch_state() if r["managed"]}
        nft(cmd)
        after = {r["handle"] for r in fetch_state() if r["managed"]}
        new = after - before
        handle = max(new) if new else max(after)
        with dbconn() as c:
            c.execute("insert or replace into rules(handle,name,created) values(?,?,?)",
                      (handle,name,datetime.now(timezone.utc).isoformat()))
        audit("rule.created",f"{name}: {cmd}")
        return handle

def delete_rule(handle):
    handle = int(handle)
    with LOCK:
        present = {r["handle"] for r in fetch_state() if r["managed"]}
        if handle not in present:
            raise ValueError("Regra não encontrada")
        nft(f"delete rule bridge {TABLE} forward handle {handle}")
        with dbconn() as c:
            c.execute("delete from rules where handle=?",(handle,))
        audit("rule.deleted",f"handle={handle}")

def stats():
    rules=fetch_state()
    total=sum(r["packets"] for r in rules)
    byt=sum(r["bytes"] for r in rules)
    now=int(time.time())
    with dbconn() as c:
        c.execute("insert into samples(ts,drops,bytes) values(?,?,?)",(now,total,byt))
        c.execute("delete from samples where ts < ?",(now-86400,))
        points=[{"ts":t,"drops":p,"bytes":b} for t,p,b in c.execute(
           "select ts,drops,bytes from samples order by ts desc limit 120")]
        activity=[{"ts":t,"action":a,"detail":d} for t,a,d in c.execute(
           "select ts,action,detail from audit order by id desc limit 20")]
    return {"online":True,"host":SHIELD,"rules":rules,"drops":total,"bytes":byt,
            "rule_count":len(rules),"samples":list(reversed(points)),"activity":activity,
            "uptime":int(time.time()-STARTED)}

def password_ok(password):
    try:
        salt,digest=PASSWORD_HASH.split("$",1)
        value=hashlib.pbkdf2_hmac("sha256",password.encode(),bytes.fromhex(salt),350000)
        return hmac.compare_digest(value.hex(),digest)
    except (ValueError,TypeError):
        return False

def cookie_for(token):
    # Signed opaque token; in-memory sessions expire after 8 hours.
    sig=hmac.new(SECRET.encode(),token.encode(),hashlib.sha256).hexdigest()
    return f"{token}.{sig}"

def valid_session(cookie):
    try:
        t,s=cookie.split(".",1)
        expect=hmac.new(SECRET.encode(),t.encode(),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(s,expect):
            return None
        data=SESSIONS.get(t)
        if not data or data["exp"] < time.time():
            return None
        return data
    except (ValueError,TypeError):
        return None

HTML = r'''<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nottina Shield — Control Plane</title>
<style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Arial;background:#070b13;color:#e7eefb}
*{box-sizing:border-box}body{margin:0}button,input,select{font:inherit}button{cursor:pointer}
button:disabled{opacity:.5;cursor:not-allowed} a{color:inherit}
.shell{display:grid;grid-template-columns:248px minmax(0,1fr);min-height:100vh}
aside{background:#0c1320;border-right:1px solid #203047;padding:26px 17px}
.brand{display:flex;align-items:center;gap:12px;font-size:19px;font-weight:800;letter-spacing:-.7px}
.brand-mark{height:35px;width:35px;display:grid;place-items:center;border-radius:10px;background:#215cde;color:#fff}
.small{font-size:11px;color:#7890ac;text-transform:uppercase;letter-spacing:1.3px}
nav{margin-top:45px;display:grid;gap:7px}
nav a{display:block;padding:13px 15px;border-radius:10px;text-decoration:none;color:#8e9fba;font-size:13px}
nav a.active{background:#172a49;color:#78afff;border:1px solid #294669}
.version{position:sticky;top:calc(100vh - 125px);margin-top:50px;padding:16px;color:#8294aa;font-size:12px;border-top:1px solid #203047}
main{padding:30px 36px;max-width:1600px;width:100%}
header{display:flex;justify-content:space-between;align-items:center;gap:15px;border-bottom:1px solid #1d2a3d;padding-bottom:25px}
h1{font-size:25px;letter-spacing:-.6px;margin:2px 0 8px}p{color:#8c9fb9;margin:0;font-size:13px}
.controls{display:flex;align-items:center;gap:12px}
.pill{border:1px solid #285743;color:#78dfa7;background:#10241e;padding:8px 12px;border-radius:20px;font-size:12px}
.pill.bad{color:#ff929b;border-color:#69313b;background:#2c141c}
.action{background:#215cde;border:1px solid #397cf2;border-radius:9px;color:#fff;padding:11px 16px;font-weight:650;font-size:13px}
.ghost{background:#152135;border:1px solid #2a3c58;color:#b5c6e0;border-radius:8px;padding:9px 13px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:17px;margin:26px 0}
.tile,.panel{border:1px solid #233047;background:linear-gradient(145deg,#131e30,#101827);border-radius:13px}
.tile{padding:20px 22px}.tile .num{font-size:29px;font-weight:750;letter-spacing:-1px;margin:12px 0 7px}
.tile .desc{color:#86a0be;font-size:12px}.tile .label{font-size:12px;color:#a4b8d0}
.panels{display:grid;grid-template-columns:1.6fr 1fr;gap:18px}
.panel{padding:23px;margin-bottom:18px;min-width:0}
.panel h2{font-size:15px;margin:0 0 7px}.panel .sub{color:#8294ad;font-size:12px;margin-bottom:22px}
.barhead{display:flex;align-items:center;justify-content:space-between}
svg{max-width:100%;width:100%;height:180px;overflow:visible}
.line{fill:none;stroke:#4b91fb;stroke-width:3;stroke-linecap:round;stroke-linejoin:round}
.fill{fill:#2459a3;opacity:.15}
.baseline{stroke:#2b3a50;stroke-width:1}
.flowline{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.flowbox{padding:10px 13px;border:1px solid #2e4160;background:#182740;border-radius:8px;font-size:12px}
.flowbox.shield{border-color:#487cea;background:#193565;color:#add2ff}
.arrow{color:#7592b7}
table{width:100%;border-collapse:collapse;font-size:12px}
td,th{text-align:left;padding:15px 10px;border-bottom:1px solid #263449}
th{color:#8399b4;font-size:11px;font-weight:500;text-transform:uppercase;letter-spacing:.6px}
td{color:#cedbee;max-width:450px;word-break:break-word}
code{color:#a6c7ff;font-size:11px} .tag{padding:4px 8px;border-radius:6px;background:#163a2e;color:#76d9a7;font-size:11px}
.danger{background:#421d29;border:1px solid #69394b;color:#ffc0c6;padding:7px 11px;border-radius:7px}
.empty{padding:22px;color:#8294ad;text-align:center}
.overlay{position:fixed;inset:0;background:#05070bcc;display:grid;place-items:center;z-index:3}
.login,.modal{background:#121f32;border:1px solid #365071;border-radius:16px;padding:30px;width:min(440px,94vw);box-shadow:0 25px 90px #000a}
.login h2,.modal h2{margin:0 0 6px;font-size:22px}
label{font-size:12px;color:#aec2d9;display:block;margin:15px 0 7px}
input,select{width:100%;background:#0b1422;border:1px solid #2b405a;color:#ecf3fc;border-radius:8px;padding:12px;outline:none}
input:focus,select:focus{border-color:#4585ee}
.modal form .action,.login .action{width:100%;margin-top:23px}
.errors{color:#ff9da5;font-size:12px;margin-top:12px}
.hide{display:none!important}
.status{font-size:12px;color:#8ea7c7}
details{border-top:1px solid #29364a;padding-top:7px}
pre{max-height:230px;overflow:auto;white-space:pre-wrap;font-size:11px;color:#a7bad0}
@media(max-width:1050px){.grid{grid-template-columns:repeat(2,1fr)}.panels{grid-template-columns:1fr}}
@media(max-width:700px){.shell{grid-template-columns:1fr}aside{padding:15px}nav{margin-top:12px;display:flex} .version{display:none}main{padding:20px}.grid{grid-template-columns:1fr 1fr}header{flex-direction:column;align-items:flex-start}.controls{flex-wrap:wrap}}

/* Shield UI refresh — inspirado na hierarquia operacional do Gladius V2 */
:root{--bg:#f5f7fb;--surface:#fff;--surface-alt:#f8fafc;--border:#e1e7f0;--fg:#17243b;--muted:#687a91;--accent:#2563eb;--accent-soft:#edf4ff;--sidebar:#fff;--field:#fff;--shadow:0 5px 24px rgba(30,45,75,.035);color-scheme:light}
html[data-theme="dark"]{--bg:#0d1422;--surface:#141e30;--surface-alt:#101a2b;--border:#293850;--fg:#e7eefb;--muted:#98abc5;--accent:#6ca1ff;--accent-soft:#1b3151;--sidebar:#101a2b;--field:#101827;--shadow:none;color-scheme:dark}
html,body{background:var(--bg);color:var(--fg)}
body{font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;font-size:14px}
aside{background:var(--sidebar);border-color:var(--border);padding:25px 16px;display:flex;flex-direction:column;min-height:100vh}
.shell{grid-template-columns:258px minmax(0,1fr)}
.brand{font-size:18px;letter-spacing:-.5px;color:var(--fg)}
.brand-mark{border-radius:9px;background:#2563eb;box-shadow:none}
.small{color:var(--muted);letter-spacing:.85px;font-size:10px}
nav{margin-top:36px;gap:4px}
nav a{padding:11px 13px;border-radius:8px;color:var(--muted);font-weight:550;font-size:13px;border:1px solid transparent;transition:background .15s ease,color .15s ease}
nav a:hover{background:var(--surface-alt);color:var(--fg)}
nav a.active{background:var(--accent-soft);color:var(--accent);border:1px solid transparent;font-weight:650}
.version{position:static;margin-top:auto;padding:18px 9px 3px;color:var(--muted);border-color:var(--border);line-height:1.9}
.version span,.version p{color:var(--muted)!important}
main{padding:32px 38px;max-width:1700px}
header{border-color:var(--border);padding-bottom:22px}
h1{font-size:25px;font-weight:750;color:var(--fg);letter-spacing:-.8px}
p,.panel .sub,.tile .desc,.tile .label,.status{color:var(--muted)}
.controls{gap:8px;flex-wrap:wrap}
.ghost{background:var(--surface);border:1px solid var(--border);color:var(--fg);border-radius:8px;padding:9px 12px}
.ghost:hover{background:var(--surface-alt)}
.action{border:1px solid #2563eb;background:#2563eb;border-radius:8px;box-shadow:none}
.grid{gap:14px;margin:24px 0}
.tile,.panel{background:var(--surface);border:1px solid var(--border);border-radius:11px;box-shadow:var(--shadow)}
.tile{padding:20px 21px}.tile .num{color:var(--fg);font-size:30px}.tile .label{font-weight:600}
.panel{padding:22px}.panel h2{font-size:15px;color:var(--fg);font-weight:700}
.panels{gap:15px}
.baseline{stroke:var(--border)}
.flowbox{border:1px solid var(--border);background:var(--surface-alt);color:var(--fg)}
.flowbox.shield{background:var(--accent-soft);border-color:var(--accent);color:var(--accent)}
.arrow{color:var(--muted)}
td,th{border-bottom:1px solid var(--border)}
th{color:var(--muted);font-size:10px;font-weight:700}
td{color:var(--fg)}
code{color:var(--accent)}
.login,.modal{background:var(--surface);border:1px solid var(--border);color:var(--fg);border-radius:14px;box-shadow:0 20px 90px rgba(0,0,0,.22)}
.login h2,.modal h2{color:var(--fg)}
label{color:var(--fg);font-weight:600}
input,select{background:var(--field);border:1px solid var(--border);color:var(--fg)}
input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.overlay{background:rgba(5,10,21,.66)}
details,pre{border-color:var(--border);color:var(--muted)}
.pill{background:#e9f7ef;color:#166534;border-color:#bee8cc}
.pill.bad{background:#fff1f2;color:#9f1239;border-color:#fecdd3}
html[data-theme="dark"] .pill{background:#102b23;color:#82deb0;border-color:#285743}
html[data-theme="dark"] .pill.bad{background:#2c141c;color:#ff929b;border-color:#69313b}
.tag{background:#e9f7ef;color:#176c44}
html[data-theme="dark"] .tag{background:#163a2e;color:#76d9a7}
.danger{background:#fff1f2;color:#be123c;border-color:#fecdd3}
html[data-theme="dark"] .danger{background:#421d29;color:#ffc0c6;border-color:#69394b}
.theme-toggle{display:inline-flex;align-items:center;justify-content:center;min-width:108px}
:focus-visible{outline:2px solid var(--accent);outline-offset:3px}
@media(max-width:700px){.shell{grid-template-columns:1fr}aside{min-height:auto;padding:15px}nav{margin-top:12px;flex-wrap:wrap}main{padding:19px}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.tile{padding:14px}.tile .num{font-size:24px}}
@media(max-width:420px){.grid{grid-template-columns:1fr}.controls{width:100%}.controls button{flex:1}}
</style></head>
<body><div class="shell"><aside><div class="brand"><span class="brand-mark">◈</span><span>NOTTINA <span style="color:#5493ff">SHIELD</span></span></div>
<div class="small" style="margin-top:13px">Inline DDoS Control Plane</div>
<nav><a href="#overview" class="active">▦ &nbsp; Visão geral</a><a href="#rules">☷ &nbsp; Políticas &amp; regras</a><a href="#activity">◷ &nbsp; Auditoria</a></nav>
<div class="version">POC ENVIRONMENT<br><span style="color:#b1c5df">Shield · Bridge L2</span><p style="margin-top:12px">AS64510 → AS64520 → AS64530</p></div></aside>
<main><header><div><div class="small">SECURITY OPERATIONS / NETWORK DEFENSE</div><h1>Visão geral de mitigação</h1><p>Controle operacional · inspeção inline · observabilidade de políticas nftables</p></div>
<div class="controls"><span id="status" class="pill bad">● Verificando Shield</span><button class="ghost theme-toggle" id="theme-toggle" type="button" aria-label="Alternar tema">Tema claro</button><button class="ghost" id="refresh">↻ Atualizar</button><button class="ghost" id="logout">Sair</button></div></header>
<section id="overview"><div class="grid">
<div class="tile"><div class="label">Pacotes descartados</div><div class="num" id="drops">—</div><div class="desc">Contadores atuais, incluindo regra PoC legada</div></div>
<div class="tile"><div class="label">Bytes descartados</div><div class="num" id="bytes">—</div><div class="desc">Ação DROP · regras gerenciadas</div></div>
<div class="tile"><div class="label">Políticas ativas</div><div class="num" id="count">—</div><div class="desc">nftables / bridge forward</div></div>
<div class="tile"><div class="label">Plano de controle</div><div class="num" style="font-size:20px" id="health">Verificando</div><div class="desc" id="target">Shield 172.31.253.14</div></div>
</div>
<div class="panels"><div class="panel"><div class="barhead"><div><h2>Telemetria de descarte</h2><div class="sub">Leituras periódicas do kernel · amostras nos últimos minutos</div></div><span class="small">LIVE / 5S</span></div>
<svg viewBox="0 0 640 180" preserveAspectRatio="none" aria-label="Gráfico de pacotes descartados"><path class="baseline" d="M0 148H640 M0 100H640 M0 52H640"/><path class="fill" id="chartfill" d=""/><polyline class="line" id="chart" points=""/></svg></div>
<div class="panel"><h2>Topologia protegida</h2><div class="sub">Caminho de dados · rede isolada da Cloud9</div>
<div class="flowline"><div class="flowbox">Upstream<br>AS64510</div><span class="arrow">→</span><div class="flowbox shield">Shield L2<br>ens3 / ens4</div><span class="arrow">→</span><div class="flowbox">ASBR<br>AS64520</div></div>
<div style="margin-top:24px;border-top:1px solid #263751;padding-top:18px"><div class="small">Destino protegido</div><div style="font-size:21px;margin-top:8px;font-weight:700">203.0.113.10</div><p>CE AS64530 · HTTP :8080</p></div>
</div></div></section>
<section id="rules"><div class="panel"><div class="barhead"><div><h2>Regras de mitigação</h2><div class="sub">Regras do console + tabela experimental existente · entrada ens3</div></div><button class="action" id="add">+ Nova regra</button></div>
<div style="overflow:auto"><table><thead><tr><th>Regra</th><th>Condição nftables</th><th>Pacotes</th><th>Bytes</th><th>Ações</th></tr></thead><tbody id="rules-body"><tr><td colspan="5" class="empty">Consultando regras...</td></tr></tbody></table></div></div></section>
<section id="activity"><div class="panel"><h2>Registro de auditoria</h2><div class="sub">Ações executadas pelo painel nesta instalação</div><div id="audit" class="status">Aguardando dados...</div></div></section>
<footer class="status" style="padding-bottom:25px">Nottina Shield · PoC técnica · alterações aplicadas ao nftables real da VM Shield. Sem regras automáticas.</footer>
</main></div>
<div id="login-overlay" class="overlay"><div class="login"><div class="brand" style="margin-bottom:26px"><span class="brand-mark">◈</span>NOTTINA SHIELD</div><h2>Acesso ao console</h2><p>Autenticação restrita ao plano de controle</p><form id="login-form"><label>Usuário</label><input id="username" autocomplete="username" required value="admin"><label>Senha</label><input type="password" id="password" autocomplete="current-password" required><button class="action">Entrar no console</button><div class="errors" id="login-error"></div></form></div></div>
<div id="modal-overlay" class="overlay hide"><div class="modal"><div class="barhead"><h2>Nova regra de mitigação</h2><button class="ghost" id="close">×</button></div><p>Aplicação imediata no dataplane. Limites de endereçamento da PoC.</p>
<form id="rule-form"><label>Identificação</label><input name="name" placeholder="Ex.: Bloqueio UDP 8080" required maxlength="65">
<label>Protocolo</label><select name="protocol"><option value="udp">UDP</option><option value="tcp">TCP</option><option value="icmp">ICMP</option></select>
<label>Destino IPv4 (203.0.113.0/24)</label><input name="dst" required value="203.0.113.10">
<label>Origem IPv4 (opcional, 198.18.0.0/24)</label><input name="src" placeholder="198.18.0.20/32">
<label>Porta destino (TCP/UDP)</label><input name="port" type="number" min="1" max="65535" value="8080">
<div class="errors" id="rule-error"></div><button class="action">Aplicar regra DROP</button></form></div></div>
<script>
(function(){
 const key='nottina-shield-theme';
 let saved=null;
 try{saved=localStorage.getItem(key)}catch(_){}
 const initial=saved==='light'||saved==='dark'?saved:(window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');
 function setTheme(theme){document.documentElement.setAttribute('data-theme',theme);const b=document.getElementById('theme-toggle');if(b){b.textContent=theme==='dark'?'☀ Tema claro':'☾ Tema escuro';b.setAttribute('aria-label','Ativar tema '+(theme==='dark'?'claro':'escuro'));}}
 setTheme(initial);
 document.getElementById('theme-toggle').addEventListener('click',function(){const next=document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark';setTheme(next);try{localStorage.setItem(key,next)}catch(_){}});
})();
let csrf='',series=[],lastOk=false;
const el=id=>document.getElementById(id);
const fmt=x=>Number(x||0).toLocaleString('pt-BR');
const bytes=x=>{let n=Number(x||0);return n>=1048576?(n/1048576).toFixed(2)+' MB':n>=1024?(n/1024).toFixed(1)+' KB':fmt(n)+' B'};
const escapeHTML=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path,opt={}){
 const cfg={...opt,headers:{'Content-Type':'application/json','X-CSRF-Token':csrf,...opt.headers}};
 const r=await fetch(path,cfg);let data=await r.json().catch(()=>({error:'Resposta inválida'}));
 if(r.status===401){el('login-overlay').classList.remove('hide');throw Error('Autenticação necessária')}
 if(!r.ok)throw Error(data.error||'Falha '+r.status);
 return data;
}
async function session(){let r=await fetch('/api/session');if(r.ok){let d=await r.json();csrf=d.csrf;el('login-overlay').classList.add('hide');await refresh()}else el('login-overlay').classList.remove('hide')}
function graph(points){
 const vals=points.map(p=>p.drops),count=vals.length;
 if(!count){el('chart').setAttribute('points','');el('chartfill').setAttribute('d','');return}
 const lo=Math.min(...vals),hi=Math.max(...vals),dif=Math.max(1,hi-lo);
 let xy=vals.map((v,i)=>[count===1?320:i*640/(count-1),148-(v-lo)/dif*115]);
 el('chart').setAttribute('points',xy.map(p=>p.join(',')).join(' '));
 el('chartfill').setAttribute('d','M'+xy.map(p=>p.join(',')).join(' L')+' L640,148 L0,148 Z');
}
async function refresh(){
 try{const d=await api('/api/state');lastOk=true;
 el('status').className='pill';el('status').textContent='● Shield conectado';
 el('drops').textContent=fmt(d.drops);el('bytes').textContent=bytes(d.bytes);
 el('count').textContent=fmt(d.rule_count);el('health').textContent='Operacional';el('target').textContent=d.host;
 graph(d.samples);
 let body=el('rules-body');body.replaceChildren();
 if(!d.rules.length)body.innerHTML='<tr><td colspan="5" class="empty">Nenhuma regra de mitigação ativa. O tráfego permanece transparente.</td></tr>';
 for(let rule of d.rules){
  let tr=document.createElement('tr'),txt=JSON.stringify(rule.expr);
  tr.innerHTML='<td><b>'+escapeHTML(rule.name)+'</b><div class="small">handle '+rule.handle+'</div></td><td><details><summary><code>Inspecionar condições</code></summary><pre>'+escapeHTML(JSON.stringify(rule.expr,null,2))+'</pre></details></td><td>'+fmt(rule.packets)+'</td><td>'+bytes(rule.bytes)+'</td><td></td>';
  if(rule.managed){let btn=document.createElement('button');btn.className='danger';btn.textContent='Remover';btn.onclick=()=>remove(rule.handle,rule.name);tr.lastElementChild.appendChild(btn)}
  else {tr.lastElementChild.textContent='Somente leitura'}body.appendChild(tr);
 }
 el('audit').innerHTML=d.activity.length?d.activity.map(x=>'<div style="padding:12px;border-bottom:1px solid #263449"><span class="tag">'+escapeHTML(x.action)+'</span> <span style="color:#7c95b2">'+escapeHTML(x.ts)+'</span><div style="margin-top:8px;font-size:12px">'+escapeHTML(x.detail)+'</div></div>').join(''):'Sem eventos registrados.';
 }catch(e){lastOk=false;el('status').className='pill bad';el('status').textContent='● Shield indisponível';el('health').textContent='Sem conexão';}
}
async function remove(handle,name){if(!confirm('Excluir a regra '+name+' (#'+handle+')?'))return;try{await api('/api/rules/'+handle,{method:'DELETE'});await refresh()}catch(e){alert(e.message)}}
el('login-form').onsubmit=async e=>{e.preventDefault();let username=el('username').value,password=el('password').value;try{let d=await api('/api/login',{method:'POST',body:JSON.stringify({username,password})});csrf=d.csrf;el('login-overlay').classList.add('hide');el('password').value='';await refresh()}catch(err){el('login-error').textContent=err.message}};
el('rule-form').onsubmit=async e=>{e.preventDefault();let fields=Object.fromEntries(new FormData(e.currentTarget).entries());try{await api('/api/rules',{method:'POST',body:JSON.stringify(fields)});el('modal-overlay').classList.add('hide');await refresh()}catch(err){el('rule-error').textContent=err.message}};
el('refresh').onclick=refresh;el('add').onclick=()=>el('modal-overlay').classList.remove('hide');el('close').onclick=()=>el('modal-overlay').classList.add('hide');
el('logout').onclick=async()=>{try{await api('/api/logout',{method:'POST'})}catch(e){}location.reload()};
setInterval(()=>{if(el('login-overlay').classList.contains('hide'))refresh()},5000);session();
</script></body></html>'''

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "NottinaShield/0.1"
    def log_message(self, fmt, *args):
        print(datetime.now(timezone.utc).isoformat(), self.address_string(), fmt % args, flush=True)
    def send(self, code, data, content="application/json", extra=None):
        body=(json.dumps(data,ensure_ascii=False).encode() if content=="application/json" else data.encode())
        self.send_response(code)
        self.send_header("Content-Type",content+"; charset=utf-8")
        self.send_header("Content-Length",str(len(body)))
        self.send_header("Cache-Control","no-store")
        self.send_header("X-Frame-Options","DENY")
        self.send_header("X-Content-Type-Options","nosniff")
        self.send_header("Content-Security-Policy","default-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'")
        if extra:
            for k,v in extra.items():self.send_header(k,v)
        self.end_headers()
        self.wfile.write(body)
    def data(self):
        if int(self.headers.get("Content-Length","0")) > 8192:raise ValueError("Body muito grande")
        data=self.rfile.read(int(self.headers.get("Content-Length","0")))
        return json.loads(data or b"{}")
    def session(self):
        c=http.cookies.SimpleCookie()
        try:c.load(self.headers.get("Cookie",""))
        except http.cookies.CookieError:return None
        return valid_session(c["nottina"].value) if "nottina" in c else None
    def auth(self,mutate=False):
        session=self.session()
        if not session:
            self.send(401,{"error":"Autenticação necessária"});return False
        if mutate and not hmac.compare_digest(str(self.headers.get("X-CSRF-Token","")),session["csrf"]):
            self.send(403,{"error":"Token CSRF inválido"});return False
        return True
    def do_GET(self):
        path=urllib.parse.urlsplit(self.path).path
        if path=="/" or path.startswith("/app/"):
            return self.send(200,Path(__file__).with_name("console.html").read_text(encoding="utf-8"),"text/html")
        if path=="/api/session":
            s=self.session()
            return self.send(200,{"csrf":s["csrf"],"user":ADMIN}) if s else self.send(401,{"error":"Login obrigatório"})
        if not self.auth():return
        if path=="/api/state":
            try:return self.send(200,stats())
            except Exception as e:return self.send(503,{"error":str(e)})
        if path.startswith("/api/v2/"):
            try:
                if path=="/api/v2/policies":
                    engineering.reconcile(DB,fetch_state(),delete_rule)
                    return self.send(200,{"data":engineering.policies(DB)})
                if path=="/api/v2/telemetry":
                    errors=engineering.record_interfaces(DB,remote)
                    return self.send(200,{"interfaces":engineering.telemetry(DB),"errors":errors,"source":"real-linux-sysfs","sample_time":int(time.time())})
                if path=="/api/v2/coverage":
                    return self.send(200,{"data":engineering.coverage(DB),"source":"operator-declared-not-probed"})
                m=re.fullmatch(r"/api/v2/policies/(\d+)/history",path)
                if m:return self.send(200,{"data":engineering.history(DB,int(m[1]))})
            except Exception as e:return self.send(503,{"error":str(e)})
        self.send(404,{"error":"Não encontrado"})
    def do_POST(self):
        path=urllib.parse.urlsplit(self.path).path
        try: body=self.data()
        except Exception:return self.send(400,{"error":"JSON inválido"})
        if path=="/api/login":
            if body.get("username")!=ADMIN or not password_ok(str(body.get("password",""))):
                time.sleep(.5)
                return self.send(401,{"error":"Credenciais incorretas"})
            token=secrets.token_urlsafe(36)
            csrf=secrets.token_urlsafe(32)
            SESSIONS[token]={"csrf":csrf,"exp":time.time()+8*3600}
            audit("auth.login","Login no console")
            return self.send(200,{"csrf":csrf},extra={"Set-Cookie":"nottina="+cookie_for(token)+"; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800"})
        if not self.auth(True):return
        if path=="/api/logout":
            c=http.cookies.SimpleCookie()
            c.load(self.headers.get("Cookie",""))
            if "nottina" in c:
                token=c["nottina"].value.split(".")[0]
                SESSIONS.pop(token,None)
            return self.send(200,{"ok":True},extra={"Set-Cookie":"nottina=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"})
        if path=="/api/v2/policies":
            try:
                pid=engineering.create_policy(DB,body,ADMIN,build_rule,add_rule)
                return self.send(201,{"ok":True,"id":pid})
            except (ValueError,TypeError,KeyError) as e:return self.send(400,{"error":str(e)})
            except Exception as e:return self.send(503,{"error":str(e)})
        if path=="/api/v2/coverage":
            try:
                engineering.upsert_coverage(DB,body)
                audit("coverage.updated",json.dumps(body,ensure_ascii=False)[:500])
                return self.send(200,{"ok":True})
            except (ValueError,TypeError,KeyError) as e:return self.send(400,{"error":str(e)})
        m=re.fullmatch(r"/api/v2/policies/(\d+)/restore",path)
        if m:
            try:return self.send(200,{"handle":engineering.restore(DB,int(m[1]),ADMIN,build_rule,add_rule)})
            except ValueError as e:return self.send(400,{"error":str(e)})
            except Exception as e:return self.send(503,{"error":str(e)})
        if path=="/api/rules":
            try:
                handle=add_rule(body)
                return self.send(201,{"ok":True,"handle":handle})
            except ValueError as e:return self.send(400,{"error":str(e)})
            except Exception as e:return self.send(503,{"error":str(e)})
        self.send(404,{"error":"Não encontrado"})
    def do_DELETE(self):
        if not self.auth(True):return
        path=urllib.parse.urlsplit(self.path).path
        m2=re.fullmatch(r"/api/v2/policies/(\d+)",path)
        if m2:
            try:
                engineering.deactivate(DB,int(m2[1]),ADMIN,delete_rule)
                return self.send(200,{"ok":True})
            except ValueError as e:return self.send(400,{"error":str(e)})
            except Exception as e:return self.send(503,{"error":str(e)})
        m=re.fullmatch(r"/api/rules/(\d+)",path)
        if not m:return self.send(404,{"error":"Não encontrado"})
        try:
            delete_rule(int(m[1]))
            return self.send(200,{"ok":True})
        except ValueError as e:return self.send(400,{"error":str(e)})
        except Exception as e:return self.send(503,{"error":str(e)})

if __name__=="__main__":
    if not SECRET or len(SECRET)<24 or not PASSWORD_HASH:
        raise SystemExit("Configure SESSION_SECRET (>=24 chars) e PASSWORD_HASH (PBKDF2 salt$hex).")
    dbconn().close()
    engineering.connect(DB).close()
    def expiry_worker():
        while True:
            try: engineering.reconcile(DB,fetch_state(),delete_rule)
            except Exception as e: print("Reconciliation warning:",str(e),flush=True)
            time.sleep(15)
    threading.Thread(target=expiry_worker,daemon=True,name="policy-expiry").start()
    print(f"Nottina Shield Console — http://{HOST}:{PORT} → {USER}@{SHIELD}",flush=True)
    http.server.ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()
