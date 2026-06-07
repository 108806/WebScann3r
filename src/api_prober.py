#!/usr/bin/env python3
"""
API Prober — post-crawl active probing of discovered API endpoints.

Only makes GET and OPTIONS requests (no mutation). Orchestrates six checks:
  1. Swagger / OpenAPI spec discovery + parsing
  2. Auth boundary detection (200 without credentials)
  3. CORS misconfiguration (origin reflection + credentials)
  4. Version disclosure via diagnostic endpoints
  5. Dangerous HTTP method enumeration (OPTIONS -> Allow)
  6. API intelligence extracted from downloaded JS (base URLs, auth patterns)

Produces api_report.md and api_details.json in the report directory.
"""

import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin

logger = logging.getLogger('WebScann3r.ApiProber')

# ── Constants ─────────────────────────────────────────────────────────────────

SWAGGER_PATHS = [
    '/swagger.json', '/swagger.yaml', '/swagger.yml',
    '/openapi.json', '/openapi.yaml', '/openapi.yml',
    '/api-docs', '/api-docs.json', '/api/swagger.json',
    '/api/openapi.json', '/v1/api-docs', '/v2/api-docs', '/v3/api-docs',
    '/swagger/index.html', '/swagger-ui.html', '/swagger-ui/index.html',
    '/api/swagger-ui.html', '/docs/swagger.json', '/api/v1/swagger.json',
    '/.well-known/openapi.json', '/redoc', '/api/redoc',
]

VERSION_PATHS = [
    '/version', '/health', '/status', '/ping', '/info',
    '/actuator', '/actuator/info', '/actuator/health', '/actuator/env',
    '/actuator/mappings', '/actuator/beans', '/actuator/metrics',
    '/__version__', '/build-info', '/buildinfo', '/build_info',
    '/api/version', '/api/health', '/api/status', '/api/info',
    '/metrics', '/healthz', '/readyz', '/livez',
    '/debug/vars', '/server-status', '/_cluster/health',
    '/admin/status', '/admin/info',
]

DANGEROUS_METHODS = {'PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH'}

_CORS_EVIL = 'https://evil-attacker.com'
_CORS_NULL = 'null'

# Extract version strings from JSON/YAML response bodies
_VERSION_RE = re.compile(
    r'(?:'
    r'"(?:version|build|buildVersion|serverVersion|appVersion|revision|tag)"\s*:\s*"([^"]{2,40})"|'
    r"'(?:version|build)'\s*:\s*'([^']{2,40})'|"
    r'\bversion:\s+([^\s\n,{}\[\]]{2,30})'
    r')',
    re.IGNORECASE,
)

# Extract API base URL constants from JS source
_BASE_URL_PATTERNS = [
    re.compile(
        r'(?:API_BASE_URL|API_URL|BASE_URL|baseURL|baseUrl|apiUrl|'
        r'apiEndpoint|API_ENDPOINT|REACT_APP_API|VUE_APP_API)\s*[=:]\s*["\']([^"\']{8,})["\']'
    ),
    re.compile(r'axios\.defaults\.baseURL\s*=\s*["\']([^"\']{8,})["\']'),
    re.compile(r'(?:createClient|ApolloClient|new\s+Apollo)\s*\([^)]*url\s*:\s*["\']([^"\']{8,})["\']'),
    re.compile(r'fetch\s*\(\s*["\']([^"\']{12,}/api[^"\']*)["\']'),
]

# Auth header patterns in JS
_AUTH_HEADER_PATTERNS = [
    re.compile(r'["\']Authorization["\']'),
    re.compile(r'Authorization\s*:\s*`?["\']?(Bearer|Basic|Token)\s+'),
    re.compile(r'["\'](?:x-api-key|x-auth-token|x-access-token|x-csrf-token)["\']'),
    re.compile(r'(?:apiKey|api_key|authToken|auth_token)\s*[=:]\s*["\'][^"\']{8,}["\']'),
]

# Version disclosure HTTP headers to check per endpoint
_VERSION_HEADERS = (
    'X-API-Version', 'X-App-Version', 'X-Build-ID', 'X-Revision',
    'X-Powered-By', 'Server', 'X-Runtime', 'X-Version',
    'X-Application-Version', 'X-Generator', 'X-AspNet-Version',
    'X-AspNetMvc-Version',
)


class ApiProber:
    def __init__(self, target_url, api_endpoints, session, timeout=20, threads=10):
        self.target_url = target_url
        parsed = urlparse(target_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.api_endpoints = set(api_endpoints)
        self.session = session
        self.timeout = timeout
        self.threads = threads

        self.endpoint_results = {}  # url -> {auth_status, allowed_methods, response_headers, ...}
        self.swagger_specs = {}     # url -> parsed spec dict
        self.version_findings = {}  # url -> {body_versions, header_versions, snippet}
        self.cors_findings = []
        self.method_findings = []
        self.auth_findings = []
        self.js_intel = {'base_urls': [], 'auth_headers': []}

    # ── Feature 6: JS static analysis ────────────────────────────────────────

    def enrich_from_js(self, code_files):
        """Extract API base URLs and auth patterns from already-downloaded JS."""
        seen_urls = set()
        seen_hdrs = set()
        for file_path, content in code_files.items():
            ext = file_path.rsplit('.', 1)[-1].lower() if '.' in file_path else ''
            if ext not in ('js', 'ts', 'html'):
                continue
            for pat in _BASE_URL_PATTERNS:
                for m in pat.finditer(content):
                    candidate = m.group(1).strip().rstrip('/')
                    if not candidate or candidate in seen_urls:
                        continue
                    seen_urls.add(candidate)
                    self.js_intel['base_urls'].append({
                        'url': candidate,
                        'source_file': os.path.basename(file_path),
                    })
                    if candidate.startswith('http'):
                        self.api_endpoints.add(candidate)
            for pat in _AUTH_HEADER_PATTERNS:
                for m in pat.finditer(content):
                    hdr = m.group(0).strip()
                    if hdr not in seen_hdrs:
                        seen_hdrs.add(hdr)
                        self.js_intel['auth_headers'].append(hdr)

        if seen_urls:
            logger.info(f"[API] JS enrichment: {len(seen_urls)} API base URL(s) found")

    # ── Feature 1: Swagger / OpenAPI discovery ────────────────────────────────

    def probe_swagger(self):
        """Try well-known spec paths; parse any found Swagger/OpenAPI spec."""
        print(f"[API]      Probing {len(SWAGGER_PATHS)} Swagger/OpenAPI path(s)...")
        found = 0
        for path in SWAGGER_PATHS:
            url = self.base_url + path
            try:
                r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if r.status_code != 200:
                    continue
                ct = r.headers.get('Content-Type', '')
                body = r.text

                if 'json' in ct or body.lstrip().startswith('{'):
                    try:
                        spec = json.loads(body)
                        if any(k in spec for k in ('openapi', 'swagger', 'paths', 'definitions')):
                            self.swagger_specs[url] = self._parse_spec(spec, url)
                            found += 1
                            logger.info(f"[API] Spec found: {url}")
                            continue
                    except (json.JSONDecodeError, ValueError):
                        pass

                if 'yaml' in ct or path.endswith(('.yaml', '.yml')):
                    try:
                        import yaml
                        spec = yaml.safe_load(body)
                        if isinstance(spec, dict) and any(k in spec for k in ('openapi', 'swagger', 'paths')):
                            self.swagger_specs[url] = self._parse_spec(spec, url)
                            found += 1
                            continue
                    except Exception:
                        pass

                if 'html' in ct and any(kw in body.lower() for kw in ('swagger', 'openapi', 'redoc')):
                    self.swagger_specs[url] = {
                        'type': 'swagger_ui', 'url': url, 'endpoints': [],
                        'auth_schemes': [],
                        'note': 'Swagger UI / ReDoc HTML interface — spec JSON URL may be embedded',
                    }
                    found += 1

            except Exception as e:
                logger.debug(f"[API] spec probe {url}: {e}")

        print(f"[API]      Swagger/OpenAPI: {found} spec(s) found")

    def _parse_spec(self, spec, source_url):
        result = {
            'type': 'openapi' if 'openapi' in spec else 'swagger',
            'url': source_url,
            'version': spec.get('openapi') or spec.get('swagger', '?'),
            'title': spec.get('info', {}).get('title', ''),
            'api_version': spec.get('info', {}).get('version', ''),
            'endpoints': [],
            'auth_schemes': [],
            'servers': [],
        }
        for srv in spec.get('servers', []):
            if isinstance(srv, dict) and srv.get('url'):
                result['servers'].append(srv['url'])
        sec_defs = spec.get('securityDefinitions') or spec.get('components', {}).get('securitySchemes', {}) or {}
        for name, defn in sec_defs.items():
            if not isinstance(defn, dict):
                continue
            result['auth_schemes'].append({
                'name': name, 'type': defn.get('type', ''),
                'scheme': defn.get('scheme', ''),
            })
            for token_key in ('tokenUrl', 'authorizationUrl', 'refreshUrl'):
                turl = defn.get(token_key, '')
                if turl:
                    self.api_endpoints.add(urljoin(source_url, turl))
        for path, path_item in (spec.get('paths') or {}).items():
            if not isinstance(path_item, dict):
                continue
            for method, op in path_item.items():
                if method.upper() not in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'):
                    continue
                if not isinstance(op, dict):
                    continue
                self.api_endpoints.add(self.base_url + path)
                params = [
                    {'name': p.get('name', ''), 'in': p.get('in', ''), 'required': p.get('required', False)}
                    for p in op.get('parameters', []) if isinstance(p, dict)
                ]
                result['endpoints'].append({
                    'path': path, 'method': method.upper(),
                    'summary': (op.get('summary') or '')[:80],
                    'parameters': params,
                    'security': op.get('security', []),
                })
        return result

    # ── Feature 2: Auth boundary ──────────────────────────────────────────────

    def probe_auth(self):
        """GET each endpoint without auth; flag any that return HTTP 200."""
        endpoints = list(self.api_endpoints)[:60]
        print(f"[API]      Auth boundary probe: {len(endpoints)} endpoint(s)...")
        unauth = 0

        def _probe(url):
            try:
                r = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                return url, r.status_code, dict(r.headers), r.text[:400]
            except Exception as e:
                return url, None, {}, str(e)

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(_probe, url): url for url in endpoints}
            for fut in as_completed(futures):
                url, status, headers, snippet = fut.result()
                entry = self.endpoint_results.setdefault(url, {})
                entry['auth_status'] = status
                entry['response_headers'] = {k: v for k, v in headers.items()
                                              if k.lower() in ('content-type', 'server', 'x-powered-by',
                                                               'access-control-allow-origin', 'www-authenticate')}
                entry['response_snippet'] = snippet
                if status == 200:
                    unauth += 1
                    self.auth_findings.append({
                        'url': url, 'status': 200, 'severity': 'Medium',
                        'note': 'Returns HTTP 200 without credentials — verify if this should be public',
                    })
                elif status == 401:
                    entry['auth_note'] = 'Auth required (401)'
                elif status == 403:
                    entry['auth_note'] = 'Forbidden (403)'

        print(f"[API]      Auth probe done — {unauth} endpoint(s) respond 200 without auth")

    # ── Feature 3: CORS ───────────────────────────────────────────────────────

    def probe_cors(self):
        """Test origin reflection and credentials for CORS misconfiguration."""
        endpoints = list(self.api_endpoints)[:40]
        print(f"[API]      CORS probe: {len(endpoints)} endpoint(s)...")
        issues = 0

        def _check(url):
            found = []
            for origin in (_CORS_EVIL, _CORS_NULL):
                try:
                    r = self.session.get(
                        url, timeout=self.timeout, allow_redirects=False,
                        headers={'Origin': origin},
                    )
                    acao = r.headers.get('Access-Control-Allow-Origin', '')
                    acac = r.headers.get('Access-Control-Allow-Credentials', '').lower()
                    acam = r.headers.get('Access-Control-Allow-Methods', '')
                    if not acao:
                        continue
                    if acao == '*':
                        found.append({
                            'url': url, 'origin_sent': origin, 'acao': acao, 'acac': acac,
                            'acam': acam, 'severity': 'Medium',
                            'note': 'Wildcard ACAO — any origin may read unauthenticated responses',
                        })
                    elif acao == origin or (origin == _CORS_NULL and acao == 'null'):
                        sev = 'High' if acac == 'true' else 'Medium'
                        found.append({
                            'url': url, 'origin_sent': origin, 'acao': acao, 'acac': acac,
                            'acam': acam, 'severity': sev,
                            'note': (
                                'Origin reflected + credentials=true — cross-site authenticated reads possible'
                                if acac == 'true' else 'Arbitrary origin reflected by server'
                            ),
                        })
                except Exception:
                    pass
            return found

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(_check, url): url for url in endpoints}
            for fut in as_completed(futures):
                batch = fut.result()
                self.cors_findings.extend(batch)
                issues += len(batch)

        print(f"[API]      CORS probe done — {issues} CORS issue(s) found")

    # ── Feature 4: Version disclosure ─────────────────────────────────────────

    def probe_versions(self):
        """Probe /health, /actuator and similar paths for version disclosure."""
        print(f"[API]      Version disclosure: {len(VERSION_PATHS)} path(s)...")
        found = 0

        def _probe(path):
            url = self.base_url + path
            try:
                r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if r.status_code != 200:
                    return None
                body_versions = {}
                for m in _VERSION_RE.finditer(r.text[:8000]):
                    val = next((g for g in m.groups() if g), None)
                    if val:
                        key = m.group(0).split(':')[0].strip('"\'').strip()
                        body_versions[key] = val
                hdr_versions = {h: r.headers[h] for h in _VERSION_HEADERS if h in r.headers}
                if body_versions or hdr_versions:
                    return url, body_versions, hdr_versions, r.text[:800]
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(_probe, p): p for p in VERSION_PATHS}
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    url, bv, hv, snippet = result
                    self.version_findings[url] = {
                        'body_versions': bv, 'header_versions': hv, 'snippet': snippet,
                    }
                    found += 1
                    logger.info(f"[API] Version disclosure at {url}")

        print(f"[API]      Version probe done — {found} disclosure endpoint(s) found")

    # ── Feature 5: HTTP method enumeration ────────────────────────────────────

    def probe_methods(self):
        """OPTIONS each endpoint; flag dangerous methods in the Allow header."""
        endpoints = list(self.api_endpoints)[:60]
        print(f"[API]      Method enumeration: {len(endpoints)} endpoint(s)...")
        dangerous_total = 0

        def _options(url):
            try:
                r = self.session.options(url, timeout=self.timeout, allow_redirects=False)
                allow = r.headers.get('Allow', '') or r.headers.get('Access-Control-Allow-Methods', '')
                if not allow:
                    return None
                methods = {m.strip().upper() for m in allow.split(',') if m.strip()}
                dangerous = methods & DANGEROUS_METHODS
                return url, sorted(methods), sorted(dangerous)
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(_options, url): url for url in endpoints}
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    url, methods, dangerous = result
                    self.endpoint_results.setdefault(url, {})['allowed_methods'] = methods
                    if dangerous:
                        dangerous_total += 1
                        sev = 'High' if any(m in dangerous for m in ('DELETE', 'TRACE')) else 'Medium'
                        self.method_findings.append({
                            'url': url, 'allowed_methods': methods,
                            'dangerous_methods': dangerous, 'severity': sev,
                            'note': f"Accepts: {', '.join(dangerous)}",
                        })

        print(f"[API]      Method probe done — {dangerous_total} endpoint(s) with dangerous methods")

    # ── Orchestration ─────────────────────────────────────────────────────────

    def run(self):
        print(f"\n[API]      Starting API probe ({len(self.api_endpoints)} endpoint(s) discovered)")
        print(f"{'-' * 60}")
        self.probe_swagger()
        self.probe_auth()
        self.probe_cors()
        self.probe_versions()
        self.probe_methods()
        print(f"{'-' * 60}")
        total = (len(self.auth_findings) + len(self.cors_findings) +
                 len(self.method_findings) + len(self.version_findings) + len(self.swagger_specs))
        print(f"[API]      Probe complete — {total} finding(s)\n")

    # ── Report generation ─────────────────────────────────────────────────────

    def generate_report(self, report_dir):
        try:
            import pytz
            from datetime import datetime
            berlin = pytz.timezone('Europe/Berlin')
            now = datetime.now(berlin).strftime('%Y-%m-%d %H:%M:%S %Z')
        except Exception:
            now = time.strftime('%Y-%m-%d %H:%M:%S')

        # api_details.json
        details = {
            'target_url': self.target_url,
            'scan_time': now,
            'swagger_specs': self.swagger_specs,
            'version_findings': self.version_findings,
            'cors_findings': self.cors_findings,
            'method_findings': self.method_findings,
            'auth_findings': self.auth_findings,
            'endpoint_details': self.endpoint_results,
            'js_intel': self.js_intel,
        }
        json_path = os.path.join(report_dir, 'api_details.json')
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(details, f, indent=2, default=str)

        # api_report.md
        md_path = os.path.join(report_dir, 'api_report.md')
        total_issues = (len(self.auth_findings) + len(self.cors_findings) +
                        len(self.method_findings) + len(self.version_findings))

        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(f"# API Security Report\n\n")
            f.write(f"**Target:** {self.target_url}  \n")
            f.write(f"**Date:** {now}  \n")
            f.write(f"**Endpoints probed:** {len(self.api_endpoints)}  \n")
            f.write(f"**Total findings:** {total_issues}  \n\n")

            # 1. Swagger / OpenAPI
            f.write("---\n\n## 1. Swagger / OpenAPI Spec Exposure\n\n")
            if self.swagger_specs:
                f.write(f"**{len(self.swagger_specs)} spec(s) found at public paths:**\n\n")
                for spec_url, spec in self.swagger_specs.items():
                    f.write(f"### `{spec_url}`\n\n")
                    if spec.get('type') == 'swagger_ui':
                        f.write(f"- **Type:** Swagger UI / ReDoc (HTML interface)\n")
                        f.write(f"- **Note:** {spec.get('note', '')}\n\n")
                    else:
                        f.write(f"- **Spec type:** {spec.get('type','').upper()} {spec.get('version','')}\n")
                        f.write(f"- **API title:** {spec.get('title') or 'N/A'}\n")
                        f.write(f"- **API version:** {spec.get('api_version') or 'N/A'}\n")
                        if spec.get('servers'):
                            f.write(f"- **Servers:** {', '.join(spec['servers'])}\n")
                        for s in spec.get('auth_schemes', []):
                            f.write(f"- **Auth scheme:** `{s['name']}` ({s['type']} {s.get('scheme','')})\n")
                        eps = spec.get('endpoints', [])
                        if eps:
                            f.write(f"- **Endpoints in spec:** {len(eps)}\n\n")
                            f.write("| Method | Path | Summary | Auth |\n")
                            f.write("|--------|------|---------|------|\n")
                            for ep in eps[:60]:
                                auth = 'Yes' if ep.get('security') else '?'
                                summary = (ep.get('summary') or '')[:55]
                                f.write(f"| `{ep['method']}` | `{ep['path']}` | {summary} | {auth} |\n")
                            if len(eps) > 60:
                                f.write(f"\n_...and {len(eps)-60} more — full list in api_details.json_\n")
                            f.write("\n")
            else:
                f.write("No Swagger/OpenAPI specs found at common paths.\n\n")

            # 2. Unauthenticated endpoints
            f.write("---\n\n## 2. Unauthenticated Endpoints (HTTP 200 Without Credentials)\n\n")
            if self.auth_findings:
                f.write(f"**{len(self.auth_findings)} endpoint(s)** returned HTTP 200 without credentials:\n\n")
                f.write("| URL | Severity |\n|-----|----------|\n")
                for item in sorted(self.auth_findings, key=lambda x: x['url']):
                    f.write(f"| `{item['url']}` | {item['severity']} |\n")
                f.write("\n> These may be intentionally public. Verify manually that sensitive data or "
                        "state-changing operations are not exposed.\n\n")
            else:
                f.write("All probed endpoints returned 401/403 — no unauthenticated 200 responses detected.\n\n")

            # 3. CORS
            f.write("---\n\n## 3. CORS Misconfigurations\n\n")
            if self.cors_findings:
                high = [x for x in self.cors_findings if x['severity'] == 'High']
                med  = [x for x in self.cors_findings if x['severity'] == 'Medium']
                f.write(f"**{len(self.cors_findings)} CORS issue(s)** — {len(high)} High, {len(med)} Medium:\n\n")
                f.write("| URL | Origin Sent | ACAO | Credentials | Severity | Finding |\n")
                f.write("|-----|-------------|------|-------------|----------|---------|\n")
                for item in sorted(self.cors_findings, key=lambda x: (x['severity'] != 'High', x['url'])):
                    note = item['note'][:70]
                    f.write(f"| `{item['url']}` | `{item['origin_sent']}` | `{item['acao']}` "
                            f"| {item.get('acac','—')} | **{item['severity']}** | {note} |\n")
                f.write("\n")
            else:
                f.write("No CORS misconfigurations detected on probed endpoints.\n\n")

            # 4. Version disclosure
            f.write("---\n\n## 4. Version Disclosure via API Endpoints\n\n")
            if self.version_findings:
                f.write(f"**{len(self.version_findings)} endpoint(s)** disclosed version/build info:\n\n")
                for url, data in sorted(self.version_findings.items()):
                    f.write(f"### `{url}`\n\n")
                    if data.get('body_versions'):
                        f.write("**Response body fields:**\n\n")
                        for k, v in data['body_versions'].items():
                            f.write(f"- `{k}`: `{v}`\n")
                        f.write("\n")
                    if data.get('header_versions'):
                        f.write("**Response headers:**\n\n")
                        for k, v in data['header_versions'].items():
                            f.write(f"- `{k}`: `{v}`\n")
                        f.write("\n")
                    if data.get('snippet'):
                        snip = data['snippet'][:500].replace('`', "'")
                        f.write(f"<details><summary>Response snippet</summary>\n\n```\n{snip}\n```\n\n</details>\n\n")
            else:
                f.write("No version disclosure found at common diagnostic endpoints.\n\n")

            # 5. HTTP methods
            f.write("---\n\n## 5. Dangerous HTTP Methods Enabled\n\n")
            if self.method_findings:
                f.write(f"**{len(self.method_findings)} endpoint(s)** with dangerous HTTP methods:\n\n")
                f.write("| URL | Dangerous | All Allowed | Severity |\n")
                f.write("|-----|-----------|-------------|----------|\n")
                for item in sorted(self.method_findings, key=lambda x: (x['severity'] != 'High', x['url'])):
                    dm = ', '.join(f'`{m}`' for m in item['dangerous_methods'])
                    am = ', '.join(f'`{m}`' for m in item['allowed_methods'])
                    f.write(f"| `{item['url']}` | {dm} | {am} | **{item['severity']}** |\n")
                f.write("\n")
            else:
                f.write("No dangerous HTTP methods detected (PUT/DELETE/TRACE/PATCH not reported by OPTIONS).\n\n")

            # 6. JS intel
            f.write("---\n\n## 6. API Intelligence from Static JS Analysis\n\n")
            if self.js_intel['base_urls'] or self.js_intel['auth_headers']:
                if self.js_intel['base_urls']:
                    f.write("### API Base URLs Hardcoded in JS\n\n")
                    f.write("| URL | Source File |\n|-----|-------------|\n")
                    for entry in self.js_intel['base_urls']:
                        f.write(f"| `{entry['url']}` | `{entry['source_file']}` |\n")
                    f.write("\n")
                if self.js_intel['auth_headers']:
                    f.write("### Authentication Patterns Found in JS\n\n")
                    for h in sorted(set(self.js_intel['auth_headers'])):
                        f.write(f"- `{h}`\n")
                    f.write("\n")
            else:
                f.write("No additional API intelligence extracted from static JS analysis.\n\n")

            # Summary table
            f.write("---\n\n## Summary\n\n")
            f.write("| Check | Count |\n|-------|-------|\n")
            f.write(f"| Swagger/OpenAPI specs exposed | {len(self.swagger_specs)} |\n")
            f.write(f"| Unauthenticated endpoints (HTTP 200) | {len(self.auth_findings)} |\n")
            f.write(f"| CORS misconfigurations | {len(self.cors_findings)} |\n")
            f.write(f"| Version disclosure endpoints | {len(self.version_findings)} |\n")
            f.write(f"| Dangerous HTTP methods | {len(self.method_findings)} |\n")
            f.write(f"| API base URLs from JS | {len(self.js_intel['base_urls'])} |\n")
            f.write(f"\nFull raw data: [api_details.json](api_details.json)\n")

        print(f"           api_report.md  done")
        logger.info(f"[API] Report written: {md_path}")
        return md_path
