"""Smoke tests for rule generation and auth. Run: python3 -m unittest discover -s tests -v"""
import os
import sys
import unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import app

class RuleTests(unittest.TestCase):
    def test_udp(self):
        name, rule = app.build_rule(dict(name="Teste UDP", protocol="udp",
                                        dst="203.0.113.10", port="8080", src="198.18.0.20"))
        self.assertEqual(name, "Teste UDP")
        self.assertIn("iifname ens3", rule)
        self.assertIn("ip daddr 203.0.113.10/32",rule)
        self.assertIn("ip saddr 198.18.0.20/32",rule)
        self.assertIn("udp dport 8080",rule)
    def test_restricted_network(self):
        for addr in ("8.8.8.8","10.0.0.0/8","203.0.112.0/23"):
            with self.assertRaises(ValueError):
                app.build_rule(dict(name="reject",protocol="udp",dst=addr,port="80"))
    def test_restricted_source(self):
        with self.assertRaises(ValueError):
            app.build_rule(dict(name="reject",protocol="tcp",dst="203.0.113.10",src="0.0.0.0/0",port="443"))
    def test_icmp_port(self):
        with self.assertRaises(ValueError):
            app.build_rule(dict(name="reject",protocol="icmp",dst="203.0.113.10",port="8080"))
    def test_injection(self):
        with self.assertRaises(ValueError):
            app.build_rule(dict(name="x; delete table",protocol="udp",dst="203.0.113.10",port="8080"))
    def test_password(self):
        import hashlib,secrets
        salt=secrets.token_bytes(16)
        app.PASSWORD_HASH=salt.hex()+"$"+hashlib.pbkdf2_hmac("sha256",b"example-pass",salt,350000).hex()
        self.assertTrue(app.password_ok("example-pass"))
        self.assertFalse(app.password_ok("bad"))
if __name__=="__main__":unittest.main()
