# Patterns for Clickjacking (expanded and commented)
clickjacking_patterns = [
    # X-Frame-Options header missing or not set to DENY/SAMEORIGIN (case-insensitive)
    r'(?i)X-Frame-Options\s*[:=]\s*(?!DENY|SAMEORIGIN)',
    # Setting X-Frame-Options header in code (may be misconfigured)
    r'response\.headers\s*\[\s*["\']X-Frame-Options["\']\s*\]\s*=\s*["\']?[^\'\"]*',
    # Content-Security-Policy header missing frame-ancestors directive
    r'(?i)Content-Security-Policy\s*[:=]\s*(?!.*frame-ancestors)',
    # HTML <iframe> tag without sandbox or allow attributes (potential clickjacking vector)
    r'<iframe(?![^>]*(sandbox|allow))',
    # Usage of window.open with untrusted URLs (can be abused for UI redress)
    r'window\.open\s*\(',
    # Usage of document.domain (can be abused for frame busting bypass)
    r'document\.domain',
]
