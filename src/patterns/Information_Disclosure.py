# All patterns for Information Disclosure
patterns = [
    r'(?i)console\.log\s*\(', # JS console.log
    r'(?i)alert\s*\(', # JS alert
    r'(?i)print_r\s*\(', # PHP print_r
    r'(?i)var_dump\s*\(', # PHP var_dump
    r'(?i)phpinfo\s*\(', # PHP phpinfo
    r'(?i)<!--\s*DEBUG', # HTML debug comment
    r'(?i)//\s*DEBUG', # JS debug comment
    r'(?i)^\s*echo\s+.*\$_(?:GET|POST|REQUEST|COOKIE)', # PHP echo with user input
    r'(?i)\.debug\s*\(', # .debug() call
    r'(?i)System\.out\.print', # Java System.out.print
    r'(?i)print\(\s*traceback', # Python print(traceback)
    r'(?i)\.printStackTrace\(\)', # Java .printStackTrace()
    r'(?i)\.env', # .env file
    r'(?i)\.bak$', # .bak backup file
    r'(?i)~$', # Editor backup file
    r'(?i)\.swp$', # Swap file
]
