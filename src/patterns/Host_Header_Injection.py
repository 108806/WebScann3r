# Patterns for Host Header Injection
patterns = [
    # Look for usage of unvalidated Host headers
    r'request\.headers\s*\[\s*["\'Host\'\"]\s*\]',
    r'HTTP_HOST',
]
