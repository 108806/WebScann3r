# WebScann3r

```
 __        __   _     ____                       _____      
 \ \      / /__| |__ / ___|  ___ __ _ _ __  _ __|___ / _ __ 
  \ \ /\ / / _ \ '_ \\___ \ / __/ _` | '_ \| '_ \ |_ \| '__|
   \ V  V /  __/ |_) |___) | (_| (_| | | | | | | |__) | |   
    \_/\_/ \___|_.__/|____/ \___\__,_|_| |_|_| |_|____/|_|   
                                                             
```

A web reconnaissance and static analysis tool for red team assessments. Crawls a target, downloads code files, runs 40 vulnerability pattern categories against them, and produces a suite of pentester-ready reports.

## Features

### Crawling & Discovery
- **Recursive web crawler** with configurable depth and thread count
- **Multi-domain scope control** — stay on target or follow external links
- **User-Agent rotation** — picks a random current browser string (Chrome, Firefox, Safari, Edge across Windows/macOS/Linux) per scan so consecutive runs don't share an identical fingerprint
- **Form extraction** — collects every HTML form (action, method, inputs) during crawl
- **JavaScript redirect following** — detects and queues `window.location` redirects
- **Automatic code beautification** — minified JS/HTML/CSS is pretty-printed before analysis, making findings readable
- **Version fingerprinting** — detects server software from HTTP headers and library versions (jQuery, React, Bootstrap, Swagger UI, etc.) from JS file content

### Security Analysis
- **40 vulnerability pattern categories** covering OWASP Top 10 and beyond:
  SQLi, XSS, Open Redirect, CSRF, RCE, File Inclusion, Path Traversal, XXE,
  GraphQL Injection, WebSocket Security, Business Logic Flaws, Prototype Pollution,
  Insecure Crypto, Hardcoded Credentials, SSRF, SSTI, Deserialization, and more
- **Dangerous sink detection** — identifies taint sinks (eval, exec, innerHTML, SQL queries, file ops, LDAP, JWT, etc.) with priority scoring for fuzzing
- **False-positive reduction** — word boundaries, negative lookaheads, and quote requirements baked into every pattern to minimise noise
- **Finding deduplication** — identical matches in minified bundles are reported once, not hundreds of times

### Reporting
- **10 reports per scan** — see full list below
- **URL annotations** — every security finding shows the live URL alongside the local file name
- **Dynamic recommendations** — final report recommendations are derived from actual finding types, not boilerplate
- **Severity-sorted header audit** — HTTP security headers checked across every crawled URL

## Reports

Each scan produces a timestamped directory under `targets/`. All reports are inside `reports/`.

| Report | Format | Description |
|--------|--------|-------------|
| `security_report.md` | Markdown | Numbered findings with code snippets, line numbers, and live URLs |
| `sinks.md` | Markdown | Prioritised fuzzing target list — dangerous sinks sorted by severity score |
| `http_headers_report.md` | Markdown | Missing/weak HTTP security headers (HSTS, CSP, X-Frame-Options, cookie flags…) per URL |
| `forms_inventory.md` | Markdown | All HTML forms deduplicated by signature — direct attack surface for SQLi, XSS, CSRF |
| `function_usage_report.md` | Markdown | Real function call counts (minified single-char names and JS keywords filtered out) |
| `final_report.md` | Markdown | Executive summary: site tree, sinks, issue counts, dynamic recommendations, report index |
| `discovered_files_dirs.json` | JSON | All visited URLs and downloaded files |
| `discovered_endpoints.json` | JSON | Detected API/Swagger endpoints |
| `discovered_versions.json` | JSON | Server headers + JS library versions |
| `discovered_sensitive_data.json` | JSON | Crypto addresses, validated phone numbers, IPs, internal link map |

### Output structure

```
targets/
└── example.com_2026-06-07_15-30-00/
    ├── downloads/
    │   └── (beautified source files)
    └── reports/
        ├── security_report.md
        ├── sinks.md
        ├── http_headers_report.md
        ├── forms_inventory.md
        ├── function_usage_report.md
        ├── final_report.md
        ├── discovered_files_dirs.json
        ├── discovered_endpoints.json
        ├── discovered_versions.json
        └── discovered_sensitive_data.json
```

## Installation

```bash
git clone https://github.com/108806/webscann3r.git
cd webscann3r
pip install -r requirements.txt
```

## Usage

```bash
python webscann3r.py https://example.com
```

### Options

```
positional arguments:
  url                         Target URL to scan

options:
  -h, --help                  Show this help message and exit
  -d DIR, --downloads DIR     Base directory for downloads (default: ./targets)
  -r DIR, --reports DIR       Base directory for reports (default: ./targets)
  -a [DEPTH], --all-domains   Scan all linked domains (optional depth limit)
  --depth DEPTH               Crawl depth limit (default: 3)
  -m, --media                 Download media files (images, videos, etc.)
  -z, --archives              Download archive files (zip, tar, etc.)
  -t, --text                  Download text files (txt, md, csv, json, xml)
  -j N, --threads N           Concurrent threads (default: 15)
  --timeout N                 Request timeout in seconds (default: 20)
  -v, --verbose               Enable verbose output
  -q, --quiet                 Suppress all output except errors
```

### Examples

```bash
# Basic scan
python webscann3r.py https://example.com

# Faster scan with more threads
python webscann3r.py https://example.com -j 30

# Shallow crawl (depth 1) — fast recon
python webscann3r.py https://example.com --depth 1

# Full scan including media and archives
python webscann3r.py https://example.com -m -z -t

# Follow external links (use with care)
python webscann3r.py https://example.com -a

# Follow external links, max depth 2
python webscann3r.py https://example.com -a 2
```

## Understanding the Reports

### Start here: `security_report.md`

Each finding shows the file, the **live URL**, the issue type, line number, the regex that triggered, and the code snippet with the match highlighted. Address findings here first — these are patterns known to indicate real vulnerabilities.

### Fuzzing targets: `sinks.md`

Lists every call to a dangerous function (eval, exec, innerHTML, SQL query APIs, file ops, JWT signing, etc.) sorted by a risk score. Not every sink is a vulnerability — a sink is where user input *could* cause damage. Use this list to guide manual review and dynamic testing.

### Attack surface: `forms_inventory.md`

Every unique HTML form the crawler found, deduplicated by (action, method, parameter names). This is your starting point for SQLi, XSS, and CSRF testing — the complete list of endpoints that accept user input.

### Header hardening: `http_headers_report.md`

Checks every crawled URL for missing or misconfigured security headers:
- `Strict-Transport-Security` — HSTS
- `Content-Security-Policy` — XSS mitigation
- `X-Frame-Options` / `frame-ancestors` — clickjacking
- `X-Content-Type-Options` — MIME sniffing
- `Referrer-Policy` — data leakage
- `Set-Cookie` — `Secure`, `HttpOnly`, `SameSite` flags
- `Server` / `X-Powered-By` — tech stack disclosure

### Summary: `final_report.md`

Site structure tree, sink sample, issue type breakdown, and recommendations derived from what was actually found (not generic advice). Includes a report index with links to all other files.

## Sinks vs. Vulnerabilities

**Sinks** (`sinks.md`) are places where dangerous functions are called. They are fuzzing candidates, not confirmed vulnerabilities — the function might receive only trusted input.

**Vulnerabilities** (`security_report.md`) match patterns that indicate likely exploitability: user-controlled data flowing into a dangerous operation, weak cryptographic choices, hardcoded credentials, etc.

Start with `security_report.md` for confirmed signals. Use `sinks.md` to guide manual review and dynamic fuzzing.

## Disclaimer

Use only on systems you own or have explicit written permission to test. Unauthorised scanning may be illegal in your jurisdiction.

## License

MIT License — see the LICENSE file for details.
