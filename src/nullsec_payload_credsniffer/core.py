"""CredSniffer Engine"""
import json,re

class CredSniffer:
    PATTERNS={
        "http_basic":re.compile(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)"),
        "http_form":re.compile(r"(?:user|login|email|pass|pwd)[=:]([^&\s]+)",re.I),
        "ftp_user":re.compile(r"USER\s+(\S+)"),
        "ftp_pass":re.compile(r"PASS\s+(\S+)"),
        "smtp_auth":re.compile(r"AUTH\s+(LOGIN|PLAIN)\s*(.*)"),
    }
    
    def scan_text(self,text):
        findings=[]
        for name,pattern in self.PATTERNS.items():
            matches=pattern.findall(text)
            for m in matches:
                findings.append({"type":name,"match":m if isinstance(m,str) else m[0],"severity":"HIGH"})
        return {"findings":findings,"count":len(findings),"has_credentials":len(findings)>0}
    
    def assess_protocol_risk(self,protocol):
        risks={"http":"HIGH - Credentials sent in cleartext","ftp":"HIGH - No encryption",
               "telnet":"CRITICAL - Everything in cleartext","smtp":"MEDIUM - Depends on STARTTLS",
               "https":"LOW - Encrypted","ssh":"LOW - Encrypted","sftp":"LOW - Encrypted"}
        return {"protocol":protocol,"risk":risks.get(protocol.lower(),"UNKNOWN")}
