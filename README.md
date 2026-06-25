# PHANTOM v5.0 — Web Vulnerability Scanner

● Live Scanning Web Interface (Render Deployment): https://web-testing-ybe5.onrender.com/

An autonomous, single-file web application security scanner with a live Flask UI.
It runs autonomous phases — **OSINT/Recon → Port Scan → Spider + Headless DOM →
54 Vulnerability Modules** — assigns a **CVSS v3.1** score to every finding, runs a
**false-positive verification** pass, and correlates issues into **multi-step attack
chains**. **No paid API or LLM required — pure Python.**

## Highlights
- **54 vulnerability detection modules** (OWASP Top 10 + modern + legacy techniques)
- **Out-of-Band (OOB) engine** — the scanner's own public URL is the interaction
  listener, so blind SSRF / RCE / XXE are *confirmed* via real call-backs (no
  third-party collaborator service needed)
- **Reinforcement-learning payload mutation** — an epsilon-greedy multi-armed
  bandit learns which mutation slips past *this* target's WAF/filters, then reuses it
- **Stateful business-logic testing** — drives multi-step flows with a live session
  to find sequence bypass, coupon replay and quantity tampering
- **API & mobile-backend fuzzing** — mass assignment, excessive data exposure,
  method-override smuggling, broken object/function-level access
- **Headless browser (Playwright)** — renders SPAs in real Chromium for dynamic
  DOM-XSS confirmation and client-side route discovery (degrades gracefully)
- **Speed-first**: URL-shape de-duplication, 24 worker threads, time budget — a
  typical scan finishes in well under a minute
- **CVSS v3.1** auto-scoring, **WAF fingerprinting** (15+ WAFs), recon-driven
  **hypothesis engine**, a **verification layer** for false-positive reduction,
  and an **attack-chain analyzer** that shows how findings compound

## Analyst workflow (5 reasoning stages)
1. **Form Hypotheses** — recon-driven hypothesis engine *and* a static code-pattern
   review of the site's own HTML/JS (innerHTML, eval, hard-coded keys, http:// …).
2. **Test & Verify** — every finding is confidence-scored from its evidence; blind/
   weak results are flagged for manual review (false-positive reduction).
3. **Chain Attacks** — correlates findings into multi-step attack paths and shows
   the escalated, combined impact.
4. **Generate Exploits (PoC)** — produces a safe, reproduction-only Proof-of-Concept
   (the exact request/payload that demonstrated the issue) plus CVE references, for
   verification and remediation.
5. **Reverse Engineer** — static analysis of shipped artifacts (JS bundles, source
   maps, wasm, apk, jar, exe…): string/secret extraction and dangerous-call detection.

Every finding now also shows **WHERE IN CODE** — the exact source line/snippet that
contains the issue — so you can see *what* is wrong and *where* to fix it.

### Configuration (environment variables)
| Var | Default | Purpose |
|-----|---------|---------|
| `OOB_URL` / `RENDER_EXTERNAL_URL` | (Render sets it) | Public base for the OOB listener |
| `PHANTOM_FAST` | `1` | Speed-first mode |
| `PHANTOM_BUDGET` | `300` | Hard per-scan time budget (seconds) |
| `PHANTOM_THREADS` | `24` | Concurrent workers |

## Detection coverage (48 modules)

**Injection:** SQL Injection (error/boolean/time/UNION), SQLi via forms, NoSQL
Injection, Command Injection, LFI / `php://filter`, SSRF (cloud metadata), XXE,
XPath Injection, LDAP Injection, SSTI (multi-engine, `1337*1337` marker),
Expression Language / OGNL / SpEL injection, CRLF / HTTP response splitting,
HTTP Parameter Pollution, Prototype Pollution, Log4Shell (JNDI).

**Cross-Site & client-side:** Reflected XSS, Reflected XSS via forms, Stored XSS,
DOM-based XSS (source→sink analysis), Clickjacking, CSRF token absence,
Reverse Tabnabbing, Mixed Content.

**Auth / access control:** IDOR, Forced Browsing / access-control bypass, OAuth
misconfiguration, Open Redirect, User Enumeration, Weak/none JWT secret (HMAC
cracking), Session/cookie security, Default credentials.

**Info disclosure:** Sensitive files, Backup & source-code disclosure, Verbose
error / stack-trace leaks, Directory listing, API key / secret scanning (45+
patterns), Hidden parameter mining, Subdomain enumeration & takeover, Cloud
storage buckets (S3/GCS/Azure), Email security (SPF/DMARC), `security.txt`.

**Infra / transport / config:** Open dangerous ports & service CVEs,
Unauthenticated datastores (Redis/Mongo/Elasticsearch/Memcached), FTP anonymous
login, SSL/TLS weaknesses, Security headers, CSP/CORS analysis, Host Header
Injection, Web Cache Poisoning, Web Cache Deception, Dangerous HTTP methods /
XST (TRACE), HTTP request smuggling, Rate limiting, GraphQL introspection/DoS,
WebSocket exposure, Insecure deserialization, CMS deep scan (WordPress/Joomla/
Drupal), Unrestricted file upload, Business-logic flaws.

> Educational / authorized-testing tool. Only scan systems you own or have
> explicit permission to test.

## Run locally
```bash
pip install -r requirements.txt
python phantom.py
# open http://localhost:5000
```
