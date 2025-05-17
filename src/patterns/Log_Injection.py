# Patterns for Log Injection
patterns = [
    # Look for direct logging of user input
    r'logger\.info\s*\(.*request',
    r'log\s*\(.*request',
]
