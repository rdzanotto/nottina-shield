"""Políticas e telemetria da PoC. Sem descoberta automática de POP/BGP ou bypass."""
import ipaddress, json, sqlite3, time
from datetime import datetime, timezone

def now(): return int(time.time())
def connect(path):
 c=sqlite3.connect(path,timeout=10)
 c.row_factory=sqlite3.Row
 c.execute("PRAGMA journal_mode=WAL")
 c.execute("""CREATE TABLE IF NOT EXISTS policies_v2(
  id INTEGER PRIMARY KEY AUTOINCREMENT, handle INTEGER, name TEXT NOT NULL,
  customer TEXT NOT NULL, asn INTEGER NOT NULL, prefix TEXT NOT NULL,
  ingress TEXT NOT NULL, pop TEXT NOT NULL, reason TEXT NOT NULL,
  ticket TEXT NOT NULL, owner TEXT NOT NULL, ttl INTEGER NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  status TEXT NOT NULL, spec TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1
 )""")
 c.execute("""CREATE TABLE IF NOT EXISTS policy_events_v2(
  id INTEGER PRIMARY KEY AUTOINCREMENT, policy_id INTEGER, ts INTEGER,
  actor TEXT, action TEXT, version INTEGER, detail TEXT)""")
 c.execute("""CREATE TABLE IF NOT EXISTS telemetry_v2(
  ts INTEGER NOT NULL, interface TEXT NOT NULL, rx_bytes INTEGER,
  rx_packets INTEGER, tx_bytes INTEGER, tx_packets INTEGER,
  PRIMARY KEY(ts,interface))""")
 c.execute("""CREATE TABLE IF NOT EXISTS coverage_v2(
  id INTEGER PRIMARY KEY AUTOINCREMENT, prefix TEXT NOT NULL, ingress TEXT NOT NULL,
  pop TEXT NOT NULL, mitigator TEXT NOT NULL, bgp TEXT NOT NULL DEFAULT 'unknown',
  bypass TEXT NOT NULL DEFAULT 'unknown', note TEXT NOT NULL DEFAULT '',
  UNIQUE(prefix,ingress,pop))""")
 c.commit()
 return c

def event(c,pid,actor,action,version,detail):
 c.execute("INSERT INTO policy_events_v2(policy_id,ts,actor,action,version,detail) VALUES(?,?,?,?,?,?)",
           (pid,now(),actor,action,version,json.dumps(detail,ensure_ascii=False)))

def policies(path):
 with connect(path) as c:
  return [dict(x) for x in c.execute("SELECT * FROM policies_v2 ORDER BY id DESC")]

def _spec(data):
 required=("name","customer","asn","prefix","ingress","pop","reason","ticket","owner","ttl","protocol","dst")
 for f in required:
  if not str(data.get(f,"")).strip(): raise ValueError("Campo obrigatório: "+f)
 if len(str(data["ticket"]))>100 or len(str(data["reason"]))>500 or len(str(data["owner"]))>100: raise ValueError("Metadados excedem limite")
 asn=int(data["asn"]); ttl=int(data["ttl"])
 if not 1<=asn<=4294967295: raise ValueError("ASN inválido")
 if not 60<=ttl<=86400: raise ValueError("TTL deve estar entre 60s e 24h")
 if data["ingress"] not in ("ens3",): raise ValueError("PoC permite somente ingresso ens3")
 prefix=ipaddress.IPv4Network(str(data["prefix"]),strict=False)
 dst=ipaddress.IPv4Network(str(data["dst"]),strict=False)
 if not dst.subnet_of(prefix): raise ValueError("Destino da regra fora do prefixo protegido")
 if not prefix.subnet_of(ipaddress.IPv4Network("203.0.113.0/24")): raise ValueError("Prefixo fora do laboratório")
 return asn,ttl,str(prefix)

def create_policy(path,data,actor,build_rule,add_rule):
 asn,ttl,prefix=_spec(data)
 # O construtor existente é a autoridade final do filtro nft.
 build_rule(data)
 dst=ipaddress.IPv4Network(str(data["dst"]),strict=False)
 src=str(data.get("src","")).strip()
 with connect(path) as c:
  for p in c.execute("SELECT * FROM policies_v2 WHERE status='active'"):
   spec=json.loads(p["spec"])
   if p["ingress"]!=data["ingress"] or spec["protocol"]!=data["protocol"]: continue
   other=ipaddress.IPv4Network(spec["dst"],strict=False)
   if not dst.overlaps(other): continue
   if str(spec.get("port",""))!=str(data.get("port","")): continue
   a=str(spec.get("src","")).strip()
   if not src or not a or ipaddress.IPv4Network(src,strict=False).overlaps(ipaddress.IPv4Network(a,strict=False)):
    raise ValueError("Conflito: política ativa #"+str(p["id"])+" abrange o mesmo tráfego")
  handle=add_rule(data)
  ts=now()
  payload={k:str(data.get(k,"")) for k in ("name","protocol","dst","src","port")}
  cur=c.execute("""INSERT INTO policies_v2(handle,name,customer,asn,prefix,ingress,pop,reason,ticket,owner,ttl,created_at,expires_at,status,spec)
     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
    (handle,str(data["name"]),str(data["customer"]),asn,prefix,str(data["ingress"]),
     str(data["pop"]),str(data["reason"]),str(data["ticket"]),str(data["owner"]),ttl,ts,ts+ttl,"active",json.dumps(payload)))
  pid=cur.lastrowid;event(c,pid,actor,"created",1,{"handle":handle,"expires_at":ts+ttl,"spec":payload})
  c.commit()
  return pid

def deactivate(path,pid,actor,delete_rule,reason="revoked"):
 with connect(path) as c:
  p=c.execute("SELECT * FROM policies_v2 WHERE id=?",(pid,)).fetchone()
  if not p: raise ValueError("Política não encontrada")
  if p["status"] not in ("active","missing"): raise ValueError("Política já encerrada")
  if p["status"]=="active": delete_rule(p["handle"])
  version=p["version"]+1
  c.execute("UPDATE policies_v2 SET status=?,version=? WHERE id=?",(reason,version,pid))
  event(c,pid,actor,reason,version,{"previous_handle":p["handle"]})
  c.commit()

def reconcile(path,live,delete_rule=None):
 """Detecta perda de regra. Expiração remove DROP apenas se handle gerenciado existir."""
 active={int(x["handle"]) for x in live if x.get("managed")}
 changed=[]
 with connect(path) as c:
  rows=list(c.execute("SELECT * FROM policies_v2 WHERE status='active'"))
  for p in rows:
   if p["expires_at"]<=now():
    if p["handle"] in active and delete_rule:
     try: delete_rule(p["handle"])
     except Exception as e:
      changed.append({"id":p["id"],"error":str(e)})
      continue
    new="expired"
   elif p["handle"] not in active: new="missing"
   else: continue
   ver=p["version"]+1
   c.execute("UPDATE policies_v2 SET status=?,version=? WHERE id=?",(new,ver,p["id"]))
   event(c,p["id"],"system",new,ver,{"previous_handle":p["handle"]})
   changed.append({"id":p["id"],"status":new})
  c.commit()
 return changed

def restore(path,pid,actor,build_rule,add_rule):
 with connect(path) as c:
  p=c.execute("SELECT * FROM policies_v2 WHERE id=?",(pid,)).fetchone()
  if not p or p["status"]!="missing": raise ValueError("Somente políticas ausentes podem ser reconstruídas")
  if p["expires_at"]<=now(): raise ValueError("TTL expirado; crie uma nova política")
  spec=json.loads(p["spec"])
  build_rule(spec)
  handle=add_rule(spec)
  ver=p["version"]+1
  c.execute("UPDATE policies_v2 SET status='active',handle=?,version=? WHERE id=?",(handle,ver,pid))
  event(c,pid,actor,"restored",ver,{"handle":handle})
  c.commit()
  return handle

def history(path,pid):
 with connect(path) as c:
  return [dict(x) for x in c.execute("SELECT * FROM policy_events_v2 WHERE policy_id=? ORDER BY id DESC",(pid,))]

def coverage(path):
 with connect(path) as c:
  return [dict(x) for x in c.execute("SELECT * FROM coverage_v2 ORDER BY prefix,pop,ingress")]

def upsert_coverage(path,data):
 prefix=str(ipaddress.IPv4Network(str(data["prefix"]),strict=False))
 if not ipaddress.IPv4Network(prefix).subnet_of(ipaddress.IPv4Network("203.0.113.0/24")): raise ValueError("Cobertura limitada à PoC")
 ingress=str(data.get("ingress","")).strip();pop=str(data.get("pop","")).strip()
 mitigator=str(data.get("mitigator","")).strip()
 if not ingress or not pop or not mitigator: raise ValueError("Ingresso, POP e mitigador obrigatórios")
 # Estados declaratórios nunca são tratados como provas de disponibilidade.
 bgp=str(data.get("bgp","unknown"));bypass=str(data.get("bypass","unknown"))
 if bgp not in ("unknown","up","down") or bypass not in ("unknown","inline","bypass"): raise ValueError("Estado inválido")
 with connect(path) as c:
  c.execute("""INSERT INTO coverage_v2(prefix,ingress,pop,mitigator,bgp,bypass,note) VALUES(?,?,?,?,?,?,?)
   ON CONFLICT(prefix,ingress,pop) DO UPDATE SET mitigator=excluded.mitigator,bgp=excluded.bgp,
   bypass=excluded.bypass,note=excluded.note""",(prefix,ingress,pop,mitigator,bgp,bypass,str(data.get("note",""))[:300]))
  c.commit()

def record_interfaces(path,remote):
 """Counters reais do Linux remoto; interface não disponível fica explicitamente indisponível."""
 ts=now(); samples=[]; errors=[]
 for iface in ("ens3","ens4"):
  try:
   raw=remote("for f in rx_bytes rx_packets tx_bytes tx_packets; do cat /sys/class/net/"+iface+"/statistics/$f; done")
   vals=[int(v.strip()) for v in raw.splitlines()]
   if len(vals)!=4: raise ValueError("Contadores insuficientes")
   samples.append({"ts":ts,"interface":iface,"rx_bytes":vals[0],"rx_packets":vals[1],"tx_bytes":vals[2],"tx_packets":vals[3]})
  except Exception as e: errors.append(iface+": "+str(e)[:160])
 with connect(path) as c:
  for p in samples:
   c.execute("INSERT OR REPLACE INTO telemetry_v2(ts,interface,rx_bytes,rx_packets,tx_bytes,tx_packets) VALUES(?,?,?,?,?,?)",
             (ts,p["interface"],p["rx_bytes"],p["rx_packets"],p["tx_bytes"],p["tx_packets"]))
  c.execute("DELETE FROM telemetry_v2 WHERE ts < ?",(ts-86400,))
  c.commit()
 return errors

def telemetry(path):
 with connect(path) as c:
  rows=[dict(x) for x in c.execute("SELECT * FROM telemetry_v2 WHERE ts>=? ORDER BY ts DESC LIMIT 480",(now()-86400,))]
 result={}
 for iface in ("ens3","ens4"):
  pts=sorted((x for x in rows if x["interface"]==iface),key=lambda x:x["ts"])
  latest=pts[-1] if pts else None
  rates=None
  if len(pts)>1:
   a,b=pts[-2:]; dt=b["ts"]-a["ts"]
   if dt>0 and all(b[k]>=a[k] for k in ("rx_bytes","rx_packets","tx_bytes","tx_packets")):
    rates={k+"_rate":(b[k]-a[k])/dt for k in ("rx_bytes","rx_packets","tx_bytes","tx_packets")}
  result[iface]={"latest":latest,"rates":rates,"series":pts[-120:]}
 return result
