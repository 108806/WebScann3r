# Patterns for Host Header Injection
# Expanded to cover more languages, frameworks, and proxy headers
host_header_injection_patterns = [
    # Python/Flask/Django: direct use of Host header
    r'request\.headers\s*\[\s*["\']Host["\']\s*\]',
    r'request\.META\s*\[\s*["\']HTTP_HOST["\']\s*\]',
    r'request\.get_host\s*\(',
    # PHP: $_SERVER['HTTP_HOST'] or $_SERVER['HOST']
    r'\$_SERVER\s*\[\s*["\']HTTP_HOST["\']\s*\]',
    r'\$_SERVER\s*\[\s*["\']HOST["\']\s*\]',
    # Node.js/Express: req.headers['host']
    r'req\.headers\s*\[\s*["\']host["\']\s*\]',
    r'req\.get\s*\(\s*["\']host["\']\s*\)',
    # Java: request.getHeader("Host")
    r'request\.getHeader\s*\(\s*["\']Host["\']\s*\)',
    # Ruby on Rails: request.headers['Host']
    r'request\.headers\s*\[\s*["\']Host["\']\s*\]',
    # Go: r.Header.Get("Host")
    r'r\.Header\.Get\s*\(\s*["\']Host["\']\s*\)',
    # Common proxy headers (may be trusted unsafely)
    r'X-Forwarded-Host',
    r'X-Host',
    r'Forwarded',
    # Generic: HTTP_HOST (any language)
    r'HTTP_HOST',
    # Generic: Host header in any context
    r'Host:',
]
