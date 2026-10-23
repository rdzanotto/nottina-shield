import importlib.util
import os
import tempfile
import unittest
from unittest.mock import patch
import engineering

class EngineeringTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory()
  self.db=os.path.join(self.tmp.name,"shield.sqlite")
  self.handles=[]
 def tearDown(self): self.tmp.cleanup()
 def data(self,**extra):
  d=dict(name="Teste UDP",customer="Teste",asn=64530,prefix="203.0.113.0/24",
   ingress="ens3",pop="LAB-EVE",reason="Teste autorizado",ticket="INC-1",
   owner="NOC",ttl=3600,protocol="udp",dst="203.0.113.10",port="8080",src="")
  d.update(extra);return d
 def add(self,spec):
  h=len(self.handles)+1;self.handles.append(h);return h
 def delete(self,handle): self.handles.remove(handle)
 def test_policy_lifecycle_and_version(self):
  pid=engineering.create_policy(self.db,self.data(),"operator",lambda _:True,self.add)
  self.assertEqual(engineering.policies(self.db)[0]["status"],"active")
  self.assertEqual(1,len(engineering.history(self.db,pid)))
  engineering.deactivate(self.db,pid,"operator",self.delete)
  self.assertEqual("revoked",engineering.policies(self.db)[0]["status"])
  self.assertEqual(2,engineering.policies(self.db)[0]["version"])
  self.assertEqual(2,len(engineering.history(self.db,pid)))
 def test_overlap_rejected_before_kernel_write(self):
  engineering.create_policy(self.db,self.data(),"operator",lambda _:True,self.add)
  with self.assertRaisesRegex(ValueError,"Conflito"):
   engineering.create_policy(self.db,self.data(name="Duplicada"),"operator",lambda _:True,self.add)
  self.assertEqual(1,len(self.handles))
 def test_prefix_and_ingress_guard(self):
  for kw in (dict(prefix="0.0.0.0/0"),dict(ingress="ens5"),dict(dst="203.0.114.1"),dict(ttl=3)):
   with self.subTest(kw=kw):
    with self.assertRaises(ValueError):
     engineering.create_policy(self.db,self.data(**kw),"operator",lambda _:True,self.add)
 def test_missing_then_explicit_rebuild(self):
  pid=engineering.create_policy(self.db,self.data(),"operator",lambda _:True,self.add)
  engineering.reconcile(self.db,[])
  self.assertEqual("missing",engineering.policies(self.db)[0]["status"])
  engineering.restore(self.db,pid,"operator",lambda _:True,self.add)
  self.assertEqual("active",engineering.policies(self.db)[0]["status"])
 def test_expiration_removes_present_rule(self):
  pid=engineering.create_policy(self.db,self.data(ttl=60),"operator",lambda _:True,self.add)
  with patch.object(engineering,"now",return_value=engineering.policies(self.db)[0]["expires_at"]+1):
   engineering.reconcile(self.db,[{"managed":True,"handle":1}],self.delete)
  self.assertEqual("expired",engineering.policies(self.db)[0]["status"])
  self.assertFalse(self.handles)
 def test_coverage_is_declarative(self):
  engineering.upsert_coverage(self.db,dict(prefix="203.0.113.0/24",ingress="POP-A/ens3",pop="POP-A",mitigator="shield-01",bgp="unknown",bypass="unknown"))
  self.assertEqual("unknown",engineering.coverage(self.db)[0]["bgp"])
 def test_interface_rates_from_delta(self):
  values=iter(["1000\n10\n500\n5\n","3000\n30\n1500\n15\n"])
  def fake_remote(cmd):return next(values)
  with patch.object(engineering,"now",return_value=1000):
   errors=engineering.record_interfaces(self.db,fake_remote)
  self.assertEqual([],errors)
  # O segundo conjunto está associado à ens4, sem inventar taxa antes da segunda amostra.
  self.assertIsNone(engineering.telemetry(self.db)["ens3"]["rates"])

if __name__=="__main__":unittest.main()
