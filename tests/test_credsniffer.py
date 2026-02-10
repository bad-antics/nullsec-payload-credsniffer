import unittest,sys,os
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"..","src"))
from nullsec_payload_credsniffer.core import CredSniffer

class TestCred(unittest.TestCase):
    def test_scan(self):
        c=CredSniffer()
        r=c.scan_text("USER admin\nPASS secret123")
        self.assertTrue(r["has_credentials"])
    def test_protocol(self):
        c=CredSniffer()
        r=c.assess_protocol_risk("http")
        self.assertIn("HIGH",r["risk"])

if __name__=="__main__": unittest.main()
