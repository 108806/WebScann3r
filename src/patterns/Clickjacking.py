# Patterns for Clickjacking (expanded and commented)
clickjacking_patterns = [
    # X-Frame-Options header missing or not set to DENY/SAMEORIGIN (case-insensitive)
    r'(?i)X-Frame-Options\s*[:=]\s*(?!DENY|SAMEORIGIN)',
    # Setting X-Frame-Options header in code (may be misconfigured)
    r'response\.headers\s*\[\s*["\']X-Frame-Options["\']\s*\]\s*=\s*["\']?[^\'\"]*',
    # Content-Security-Policy header missing frame-ancestors directive
    r'(?i)Content-Security-Policy\s*[:=]\s*(?!.*frame-ancestors)',
    # document.domain assignment — can be used to bypass frame-busting checks
    r'document\.domain\s*=',
]
