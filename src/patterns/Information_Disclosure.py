# All patterns for Information Disclosure
patterns = [
    r'(?i)console\.log\s*\(',
    r'(?i)alert\s*\(',
    r'(?i)print_r\s*\(',
    r'(?i)var_dump\s*\(',
    r'(?i)phpinfo\s*\(',
    r'(?i)<!--\s*DEBUG',
    r'(?i)//\s*DEBUG',
    r'(?i)^\s*echo\s+.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)\.debug\s*\(',
    r'(?i)System\.out\.print',
    r'(?i)print\(\s*traceback',
    r'(?i)\.printStackTrace\(\)',
]
