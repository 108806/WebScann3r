# Patterns for Clickjacking
patterns = [
    # Look for missing or misconfigured X-Frame-Options headers
    r'X-Frame-Options\s*[:=]\s*(?!DENY|SAMEORIGIN)', # X-Frame-Options not DENY/SAMEORIGIN
    r'response\.headers\s*\[\s*["\'X-Frame-Options\'\"]\s*\]\s*=\s*["\'\"]?[^\'\"]*', # Setting X-Frame-Options header
    # Look for missing or misconfigured Content-Security-Policy frame-ancestors directives
    r'Content-Security-Policy\s*[:=]\s*(?!.*frame-ancestors)', # CSP missing frame-ancestors
]
