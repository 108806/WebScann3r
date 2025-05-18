# Insecure HTTP header patterns for detection in WebScann3r
# Each pattern is commented with the reason it is considered insecure or risky
insecure_http_header_patterns = [
    # X-Frame-Options: ALLOWALL disables clickjacking protection
    r'(?i)X-Frame-Options:\s*ALLOWALL',
    # X-Frame-Options missing or set to ALLOWALL is insecure (no protection)
    r'(?i)X-Frame-Options:\s*$',
    # X-Content-Type-Options: none disables MIME sniffing protection
    r'(?i)X-Content-Type-Options:\s*none',
    # X-Content-Type-Options missing is insecure (no protection)
    r'(?i)X-Content-Type-Options:\s*$',
    # Strict-Transport-Security missing or empty disables HSTS
    r'(?i)Strict-Transport-Security:\s*$',
    # X-XSS-Protection: 0 disables browser XSS filter
    r'(?i)X-XSS-Protection:\s*0',
    # X-XSS-Protection missing is insecure (no browser XSS filter)
    r'(?i)X-XSS-Protection:\s*$',
    # X-Powered-By reveals technology stack (information disclosure)
    #r'(?i)X-Powered-By:\s*.*',
    # Server header reveals server software (information disclosure)
    #r'(?i)Server:\s*.*',
    # Content-Security-Policy missing or empty disables CSP protection
    r'(?i)Content-Security-Policy:\s*$',
    # Access-Control-Allow-Origin: * allows any origin (CORS misconfiguration)
    r'(?i)Access-Control-Allow-Origin:\s*\*',
    # Access-Control-Allow-Credentials: true with wildcard origin is insecure
    r'(?i)Access-Control-Allow-Credentials:\s*true',
    # Public-Key-Pins header is deprecated and should not be used
    r'(?i)Public-Key-Pins:',
    # Referrer-Policy missing or set to unsafe value
    r'(?i)Referrer-Policy:\s*$',
    r'(?i)Referrer-Policy:\s*unsafe-url',
    # Permissions-Policy missing disables feature policy protection
    r'(?i)Permissions-Policy:\s*$',
    # Feature-Policy missing disables feature policy protection (legacy)
    r'(?i)Feature-Policy:\s*$',
    # Pragma: no-cache missing may allow caching of sensitive data
    r'(?i)Pragma:\s*$',
    # Cache-Control missing may allow caching of sensitive data
    r'(?i)Cache-Control:\s*$',
    # Set-Cookie without Secure or HttpOnly flags is insecure
    r'(?i)Set-Cookie:[^;]*$',
    r'(?i)Set-Cookie:[^;]*;\s*path=[^;]*$',
    r'(?i)Set-Cookie:[^;]*;\s*domain=[^;]*$',
    # X-Permitted-Cross-Domain-Policies: none missing may allow Flash cross-domain attacks
    r'(?i)X-Permitted-Cross-Domain-Policies:\s*$',
]
