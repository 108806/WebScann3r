# Patterns for HTTP Parameter Pollution
patterns = [
    # Look for code that parses query parameters without deduplication
    r'get\s*\([^)]+\)\s*\+\s*get\s*\([^)]+\)',
    r'request\.args\.getlist\(',
]
