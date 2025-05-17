# Patterns for Misconfigured Caching
patterns = [
    # Look for missing or insecure Cache-Control headers
    r'Cache-Control\s*[:=]\s*(public|no-cache|no-store|must-revalidate)?', # Cache-Control header
    r'response\.headers\s*\[.*Cache-Control.*\]\s*=\s*', # Setting Cache-Control header
    r'Pragma:\s*no-cache', # Pragma no-cache header
    r'Expires:\s*0', # Expires 0 header
]
