# Patterns for Misconfigured Caching
# These patterns detect missing, insecure, or overly permissive cache headers that may allow sensitive data to be cached by browsers, proxies, or CDNs.
# Risks include: exposure of authenticated content to other users, caching of sensitive data, and bypass of access controls.
misconfigured_caching_patterns = [
    # Cache-Control header missing or set to public (allows caching by any cache)
    r'(?i)Cache-Control\s*[:=]\s*public',
    # Cache-Control header missing or set to no-cache/no-store/must-revalidate (should be present for sensitive data)
    r'(?i)Cache-Control\s*[:=]\s*(no-cache|no-store|must-revalidate)?',
    # Setting Cache-Control header in code (may be misconfigured)
    r'response\.headers\s*\[.*Cache-Control.*\]\s*=',
    # Pragma: no-cache header (legacy, should be used with Cache-Control)
    r'(?i)Pragma:\s*no-cache',
    # Expires: 0 header (legacy, may be ignored by some caches)
    r'(?i)Expires:\s*0',
    # Expires header set far in the future (persistent caching)
    r'(?i)Expires:\s*[A-Za-z]{3},\s*\d{2}-[A-Za-z]{3}-\d{4}\s*\d{2}:\d{2}:\d{2}\s*GMT',
    # Surrogate-Control header missing or set to public (CDN/proxy caching)
    r'(?i)Surrogate-Control:\s*public',
    r'(?i)Surrogate-Control:\s*$',
    # Vary header missing (may cause cache poisoning)
    r'(?i)Vary:\s*$',
    # X-Accel-Expires (Nginx) set to a high value
    r'(?i)X-Accel-Expires:\s*\d{5,}',
    # X-ProxyCache (custom/proxy cache headers)
    r'(?i)X-ProxyCache:\s*HIT',
]
