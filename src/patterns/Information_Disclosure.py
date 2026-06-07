# Patterns for Information Disclosure
# Strategy: flag debug output functions that expose internals in production,
# direct echoing of user input, and sensitive file references.
# Removed: console.log, print(), puts(), alert(), logging.info/debug,
# System.out.print, Console.WriteLine, die(), exit(), error_log() —
# these are normal development patterns and produce massive false positive noise.

information_disclosure_patterns = [
    # PHP debug functions that dump internal state — should not be in production
    r'(?i)\bphpinfo\s*\(',
    r'(?i)\bvar_dump\s*\(',
    r'(?i)\bprint_r\s*\(',

    # PHP direct echo of user input — information disclosure + XSS
    r'(?i)^\s*echo\s+.*\$_(?:GET|POST|REQUEST|COOKIE)',

    # Java/Python stack trace output to response
    r'(?i)\.printStackTrace\s*\(',
    r'(?i)traceback\.print_exc\s*\(',
    r'(?i)print\s*\(\s*traceback',

    # Debug comments left in source
    r'(?i)<!--\s*DEBUG',
    r'(?i)//\s*DEBUG\s*:',
    r'(?i)#\s*DEBUG\s*:',
    r'(?i)/\*\s*DEBUG',

    # Sensitive file extensions / paths referenced in code
    r'(?i)\bid_rsa\b',
    r'(?i)\bid_dsa\b',
    r'(?i)\.pem["\'\s]',
    r'(?i)/etc/passwd',
    r'(?i)/etc/shadow',
    r'(?i)\.htpasswd',
    r'(?i)\.htaccess',

    # Source control and editor artefact exposure
    r'(?i)\.git[/"\'\s]',
    r'(?i)\.svn[/"\'\s]',
    r'(?i)\.hg[/"\'\s]',
    r'(?i)\.DS_Store',

    # Backup / temp file patterns (when referenced in code/config)
    r'(?i)\b[\w.-]+\.bak["\'\s]',
    r'(?i)\b[\w.-]+\.bkp["\'\s]',
    r'(?i)\b[\w.-]+\.backup["\'\s]',
    r'(?i)\b[\w.-]+\.orig["\'\s]',
    r'(?i)\b[\w.-]+\.swp["\'\s]',
]
