# All patterns for SSRF Vulnerabilities
patterns = [
    r'(?i)(?:axios|fetch|http|request|got|superagent|curl_exec)\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)new\s+URL\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)\.get\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)\.post\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)\.send\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)\.open\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    # Expanded patterns for more SSRF detection
    r'(?i)urllib\.request\.urlopen\s*\(\s*.*\)',  # Python
    r'(?i)requests\.(get|post|put|delete|head|options|patch)\s*\(\s*.*\)',  # Python
    r'(?i)http\.get\s*\(\s*.*\)',  # Node.js
    r'(?i)http\.request\s*\(\s*.*\)',  # Node.js
    r'(?i)net\.http\.get\s*\(\s*.*\)',  # Ruby
    r'(?i)net\.http\.post\s*\(\s*.*\)',  # Ruby
    r'(?i)curl\s*\(\s*.*\)',  # PHP
    r'(?i)file_get_contents\s*\(\s*.*http',  # PHP
    r'(?i)openConnection\s*\(\s*.*\)',  # Java
    r'(?i)URLConnection\s*\(\s*.*\)',  # Java
    r'(?i)WebRequest\.Create\s*\(\s*.*\)',  # C#
    r'(?i)HttpWebRequest\s*\(\s*.*\)',  # C#
    r'(?i)socket\.connect\s*\(\s*.*\)',  # Python/Java
    r'(?i)URL\s+url\s*=\s*new\s+URL\s*\(\s*.*\)',  # Java
    r'(?i)wget\s+.*',  # shell
    r'(?i)curl\s+.*',  # shell
    r'(?i)fetch\s*\(\s*.*\)',  # JS
    r'(?i)axios\s*\(\s*.*\)',  # JS
]
