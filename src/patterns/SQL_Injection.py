# Patterns for SQL Injection (expanded and well-commented)
sql_injection_patterns = [
    # Classic SQLi in PHP, Python, Java, Node, Ruby, Go, etc.
    r'(?i)(?:execute|exec)\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*=\s*[\'\"]+.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)INSERT\s+INTO\s+.*\s+VALUES\s*\(.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)UPDATE\s+.*\s+SET\s+.*=.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)DELETE\s+FROM\s+.*\s+WHERE\s+.*=.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)(?:mysql|mysqli|pdo)_query\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)(?:query|prepare)\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE).*$',
    r'(?i)\.executeQuery\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE).*[+]',
    r'(?i)cursor\.execute\s*\(\s*f?["\'][^\)]+%[a-zA-Z]|\.format',  # Only .format and %
    r'(?i)\\bselect\\b.*\\bfrom\\b.*\\bwhere\\b.*[=><]\s*\\?.*',
    # DB-specific functions (these are rarely false positives)
    r'(?i)pg_sleep\s*\(',
    r'(?i)dbms_pipe\.receive_message',
    r'(?i)dbms_lock\.sleep',
    r'(?i)utl_inaddr\.get_host_address',
    r'(?i)utl_http\.request',
    r'(?i)utl_file\.fopen',
    r'(?i)xp_cmdshell',
    r'(?i)sp_executesql',
    r'(?i)sp_makewebtask',
    r'(?i)sp_oacreate',
    r'(?i)sp_addextendedproc',
    r'(?i)sp_add_job',
    r'(?i)sp_addtask',
    # Obfuscated/encoded SQLi (these are highly specific)
    r'(?i)%27\s*or\s*%271%27\s*=%271',
    r'(?i)%22\s*or\s*%221%22\s*=%221',
    r'(?i)%27\s*or\s*%271%27\s*=%271%27--',
    r'(?i)%22\s*or\s*%221%22\s*=%221%22--',
    r'(?i)%27\s*or\s*%271%27\s*=%271%27%23',
    r'(?i)%22\s*or\s*%221%22\s*=%221%22%23',
    r'(?i)%27\s*or\s*%271%27\s*=%271%27%3B',
    r'(?i)%22\s*or\s*%221%22\s*=%221%22%3B',
    # Blind SQLi with DB-specific context
    r'(?i)and\s+sleep\s*\(',
    r'(?i)or\s+sleep\s*\(',
    r'(?i)and\s+benchmark\s*\(',
    r'(?i)or\s+benchmark\s*\(',
    r'(?i)and\s+pg_sleep\s*\(',
    r'(?i)or\s+pg_sleep\s*\(',
    r'(?i)and\s+dbms_pipe\.receive_message',
    r'(?i)or\s+dbms_pipe\.receive_message',
    # Stacked queries and comment evasion (only with clear SQL context)
    # r'(?i);\s*shutdown\\b',  # Removed: too broad
    # r'(?i);\s*drop\s+table',  # Removed: too broad
    # r'(?i);\s*exec\s+',       # Removed: too broad
    # r'(?i)\b;\b.*\bselect\b', # Removed: too broad
]