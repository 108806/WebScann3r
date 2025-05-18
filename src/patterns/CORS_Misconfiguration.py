# Patterns for CORS Misconfiguration (expanded and commented)
cors_misconfiguration_patterns = [
    # Wildcard origin allows any site to access resources
    r'(?i)Access-Control-Allow-Origin:\s*\*',
    # Credentials allowed with wildcard origin is insecure
    r'(?i)Access-Control-Allow-Credentials:\s*true',
    # Overly permissive methods (all methods allowed)
    r'(?i)Access-Control-Allow-Methods:\s*(GET,\s*POST,\s*PUT,\s*DELETE,\s*OPTIONS|\*)',
    # Overly permissive headers (all headers allowed)
    r'(?i)Access-Control-Allow-Headers:\s*\*',
    r'(?i)Access-Control-Allow-Headers:\s*.*',
    # Exposing sensitive headers
    r'(?i)Access-Control-Expose-Headers:\s*Set-Cookie',
    # Allowing private network access (newer CORS spec)
    r'(?i)Access-Control-Allow-Private-Network:\s*true',
    # CORS debug or test headers
    r'(?i)\bCORS\b',
    # Null origin allowed (can be abused by sandboxed iframes)
    r'(?i)Access-Control-Allow-Origin:\s*null',
    # Allowing origins with http (not https)
    r'(?i)Access-Control-Allow-Origin:\s*http://',
    # Allowing multiple origins (may be misconfigured)
    r'(?i)Access-Control-Allow-Origin:\s*[^,]+,[^,]+',
]
