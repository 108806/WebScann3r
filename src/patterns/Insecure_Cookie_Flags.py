# Patterns for insecure cookie flags (expanded and commented)
insecure_cookie_flag_patterns = [
    # Set-Cookie without Secure flag (insecure over HTTP)
    r'(?i)Set-Cookie:[^;\n]*(;\s*Secure)?[^;\n]*$',
    # Set-Cookie without HttpOnly flag (accessible to JS)
    r'(?i)Set-Cookie:[^;\n]*(;\s*HttpOnly)?[^;\n]*$',
    # Set-Cookie with SameSite=None but missing Secure (insecure, required by modern browsers)
    r'(?i)Set-Cookie:[^;\n]*SameSite=None(?!.*;\s*Secure)',
    # Set-Cookie with SameSite missing (defaults to None, can be risky)
    r'(?i)Set-Cookie:(?!.*SameSite)[^\n]*$',
    # Set-Cookie with SameSite=none (should always be Secure)
    r'(?i)Set-Cookie:[^;\n]*SameSite=None(?!.*;\s*Secure)',
    # Set-Cookie with overly broad Domain attribute (e.g., Domain=example.com)
    r'(?i)Set-Cookie:[^;\n]*;\s*Domain=[^;\n]*',
    # Set-Cookie with overly broad Path attribute (e.g., Path=/)
    r'(?i)Set-Cookie:[^;\n]*;\s*Path=/[^;\n]*',
    # Set-Cookie with Max-Age or Expires far in the future (persistent cookies)
    r'(?i)Set-Cookie:[^;\n]*;\s*(Max-Age|Expires)=([1-9][0-9]{6,}|[A-Za-z]{3},\s*\d{2}-[A-Za-z]{3}-\d{4}\s*\d{2}:\d{2}:\d{2}\s*GMT)',
    # Set-Cookie with public/private key material (possible secret leakage)
    r'(?i)Set-Cookie:[^;\n]*(key|token|secret|auth|sessionid|sid|jwt|password)[^;\n]*=',
]
