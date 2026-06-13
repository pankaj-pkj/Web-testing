# 🔐 Advanced Web Vulnerability Scanner v2.0

**Portfolio Project | IIT Kanpur B.Cyber Admission**

> ⚠️ **LEGAL NOTICE:** Only scan websites you **own** or have **explicit written permission** to test.  
> Unauthorized scanning is illegal under IT Act 2000, Section 66.

---

## What This Tool Does

A comprehensive web security scanner that replicates what a professional penetration tester does manually — in an automated, systematic way. What would take a human ethical hacker **3–4 hours** manually, this tool does in **minutes**.

---

## Scan Modules (10 total)

| # | Module | What It Checks |
|---|--------|----------------|
| 1 | **Reconnaissance** | IP, DNS records, WHOIS, technology fingerprint, cookie flags |
| 2 | **Security Headers** | X-Frame-Options, CSP, HSTS, X-XSS-Protection, etc. |
| 3 | **SSL/TLS Analysis** | HTTPS, cert expiry, TLS version, HTTP redirect |
| 4 | **Sensitive Files** | `.env`, `.git/config`, `backup.sql`, `phpinfo.php`, admin panels |
| 5 | **SQL Injection** | Error-based, Boolean-based, Time-based, in URL params & forms |
| 6 | **XSS** | Reflected XSS + SSTI in URL params and HTML forms |
| 7 | **CORS Misconfiguration** | Arbitrary origin reflection, credentials leakage |
| 8 | **HTTP Methods** | PUT, DELETE, TRACE (XST), CONNECT |
| 9 | **LFI / CMD / CSRF / Redirect** | File inclusion, command injection, CSRF tokens, open redirect |
| 10 | **Gemini AI Analysis** | Attack scenarios, fix guide, risk score, hackathon tips |

---

## Installation

```bash
# 1. Clone / download this project
git clone https://github.com/yourname/web-vuln-scanner
cd web-vuln-scanner

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Add Gemini API key
# Edit scanner.py line 40:
# GEMINI_API_KEY = "your_key_here"
# Get free key: https://aistudio.google.com/app/apikey
```

---

## Usage

```bash
# Basic scan
python scanner.py http://testphp.vulnweb.com/

# With URL parameters (tests SQLi, XSS on params)
python scanner.py "http://testphp.vulnweb.com/listproducts.php?cat=1"

# With Gemini AI analysis
python scanner.py http://testphp.vulnweb.com/ YOUR_GEMINI_KEY
```

---

## Legal Practice Targets

These sites are **intentionally vulnerable** and safe to scan:

| Site | What to Practice |
|------|-----------------|
| `http://testphp.vulnweb.com/` | SQLi, XSS, file exposure |
| `http://demo.testfire.net/` | Auth bypass, XSS |
| `http://hackthissite.org/` | Various challenges |
| `localhost/dvwa/` | Full OWASP Top 10 (install DVWA) |
| `localhost/webgoat/` | Java-based vulns (OWASP WebGoat) |

---

## Output

The scanner generates two report files:
- `report_TIMESTAMP.json` — Machine-readable full results
- `report_TIMESTAMP.txt` — Human-readable summary + AI analysis

---

## Tech Stack

- **Python 3.8+**
- `requests` — HTTP requests
- `BeautifulSoup4` — HTML parsing / form extraction
- `colorama` — Colored terminal output
- `dnspython` — DNS record enumeration
- `python-whois` — Domain WHOIS lookup
- `google-generativeai` — Gemini AI integration
- `concurrent.futures` — Multi-threaded file scanning

---

## Vulnerability Coverage (OWASP Top 10)

| OWASP Category | Coverage |
|----------------|----------|
| A01 Broken Access Control | ✅ Admin panel discovery |
| A02 Cryptographic Failures | ✅ SSL/TLS, HTTPS check |
| A03 Injection | ✅ SQLi, Command Injection |
| A04 Insecure Design | ✅ CSRF, CORS |
| A05 Security Misconfiguration | ✅ Headers, HTTP methods, sensitive files |
| A06 Vulnerable Components | ✅ Technology fingerprinting |
| A07 Authentication Failures | ✅ Admin panel, cookie flags |
| A09 Security Logging | ✅ robots.txt, .git exposure |
| A10 SSRF | 🔄 Partial (open redirect) |

---

## Author

Built as a portfolio project demonstrating ethical hacking skills for  
**IIT Kanpur B.Cyber (Bachelor of Cybersecurity) Admission 2026**

**Skills demonstrated:** Python, Network Security, OWASP Top 10,  
Ethical Hacking, API Integration, Multi-threaded Programming
