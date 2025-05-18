# Patterns for Log Injection (expanded and commented)
log_injection_patterns = [
    # Direct logging of user input (Python, Flask, Django, etc.)
    r'logger\.info\s*\(.*request',
    r'logger\.warn\s*\(.*request',
    r'logger\.warning\s*\(.*request',
    r'logger\.error\s*\(.*request',
    r'logger\.debug\s*\(.*request',
    r'log\s*\(.*request',
    # Logging of raw input, params, or headers (generic)
    r'logger\.(info|warn|warning|error|debug)\s*\(.*(input|param|header|cookie|body)',
    r'log\s*\(.*(input|param|header|cookie|body)',
    # Java: Logging user input
    r'log\.info\s*\(.*request',
    r'log\.warn\s*\(.*request',
    r'log\.error\s*\(.*request',
    # C#: Logging user input
    r'Log\.Information\s*\(.*Request',
    r'Log\.Warning\s*\(.*Request',
    r'Log\.Error\s*\(.*Request',
    # Logging concatenated or formatted user input
    r'logger\.(info|warn|warning|error|debug)\s*\(.*%s',
    r'logger\.(info|warn|warning|error|debug)\s*\(.*\{.*\}',
    # Logging exceptions with user input
    r'logger\.(info|warn|warning|error|debug)\s*\(.*exception.*request',
    # Logging without sanitization (generic)
    r'log\s*\(.*unsanitized',
]
