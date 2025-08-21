# All patterns for Information Disclosure
# Expanded and commented for clarity and coverage
information_disclosure_patterns = [
    # JavaScript/Frontend
    r'(?i)console\.log\s*\(',  # JS console.log
    r'(?i)console\.debug\s*\(',  # JS console.debug
    r'(?i)console\.trace\s*\(',  # JS console.trace
    r'(?i)console\.warn\s*\(',  # JS console.warn
    r'(?i)console\.error\s*\(',  # JS console.error
    r'(?i)alert\s*\(',  # JS alert
    r'(?i)window\.alert\s*\(',  # JS window.alert
    r'(?i)window\.print\s*\(',  # JS window.print
    # PHP
    r'(?i)print_r\s*\(',  # PHP print_r
    r'(?i)var_dump\s*\(',  # PHP var_dump
    r'(?i)phpinfo\s*\(',  # PHP phpinfo
    r'(?i)die\s*\(',  # PHP die()
    r'(?i)exit\s*\(',  # PHP exit()
    r'(?i)error_log\s*\(',  # PHP error_log
    # Python
    r'(?i)print\s*\(',  # Python print()
    r'(?i)print\(\s*traceback',  # Python print(traceback)
    r'(?i)traceback\.print_exc\s*\(',  # Python traceback.print_exc()
    r'(?i)logging\.debug\s*\(',  # Python logging.debug
    r'(?i)logging\.info\s*\(',  # Python logging.info
    # Java
    r'(?i)System\.out\.print',  # Java System.out.print
    r'(?i)System\.err\.print',  # Java System.err.print
    r'(?i)\.printStackTrace\s*\(',  # Java .printStackTrace()
    # Ruby
    r'(?i)\bputs\s*\(',  # Ruby puts (word boundary to be more specific)
    # r'(?i)p\s*\(',  # Ruby p - removed as too broad, catches many false positives
    # C#
    r'(?i)Console\.WriteLine\s*\(',  # C# Console.WriteLine
    # Generic debug keywords in comments
    r'(?i)<!--\s*DEBUG',  # HTML debug comment
    r'(?i)//\s*DEBUG',  # JS debug comment
    r'(?i)#\s*DEBUG',  # Python/Ruby debug comment
    r'(?i)/\*\s*DEBUG',  # C/Java debug comment
    # User input echoed (PHP, JS, etc.)
    r'(?i)^\s*echo\s+.*\$_(?:GET|POST|REQUEST|COOKIE)',  # PHP echo with user input
    r'(?i)document\.write\s*\(',  # JS document.write
    # .env and backup files
    r'(?i)\.env',  # .env file
    r'(?i)\.bak$',  # .bak backup file
    r'(?i)\.bkp$',  # .bkp backup file
    r'(?i)\.bckp$',  # .bckp backup file
    r'(?i)\.backup$',  # .backup backup file
    r'(?i)~$',  # Editor backup file
    r'(?i)\.swp$',  # Swap file
    r'(?i)\.old$',  # .old backup file
    r'(?i)\.orig$',  # .orig backup file
    r'(?i)\.tmp$',  # .tmp temp file
    # Sensitive config files
    r'(?i)\.git',  # .git directory
    r'(?i)\.svn',  # .svn directory
    r'(?i)\.hg',  # .hg directory
    r'(?i)\.DS_Store',  # macOS DS_Store
    r'(?i)id_rsa',  # Private key
    r'(?i)id_dsa',  # Private key
    r'(?i)\.pem$',  # PEM key file
    r'(?i)\.key$',  # Key file
    r'(?i)\.crt$',  # Certificate file
    r'(?i)passwd',  # passwd file
    r'(?i)/etc/shadow',  # shadow file (specific path to avoid CSS false positives)
    # r'(?i)\bshadow\b',  # Removed: still catches CSS, too broad
    r'(?i)\.htpasswd',  # .htpasswd file
    r'(?i)\.htaccess',  # .htaccess file
]
