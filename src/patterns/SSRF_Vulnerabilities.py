# Patterns for SSRF Vulnerabilities (expanded and well-commented)
ssrf_vulnerabilities_patterns = [
    r'(?i)(?:axios|fetch|http|request|got|superagent|curl_exec)\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',  # HTTP client with user input
    r'(?i)new\s+URL\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',  # JS URL() with user input
    r'(?i)\.get\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',  # .get() with user input
    r'(?i)\.post\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',  # .post() with user input
    r'(?i)\.send\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',  # .send() with user input
    r'(?i)\.open\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',  # .open() with user input
    # Expanded patterns for more SSRF detection
    r'(?i)urllib\.request\.urlopen\s*\(\s*.*\)',  # Python urllib urlopen
    r'(?i)requests\.(get|post|put|delete|head|options|patch)\s*\(\s*.*\)',  # Python requests
    r'(?i)http\.get\s*\(\s*.*\)',  # Node.js http.get
    r'(?i)http\.request\s*\(\s*.*\)',  # Node.js http.request
    r'(?i)net\.http\.get\s*\(\s*.*\)',  # Ruby net.http.get
    r'(?i)net\.http\.post\s*\(\s*.*\)',  # Ruby net.http.post
    r'(?i)curl\s*\(\s*.*\)',  # PHP curl()
    r'(?i)file_get_contents\s*\(\s*.*http',  # PHP file_get_contents with http
    r'(?i)openConnection\s*\(\s*.*\)',  # Java openConnection
    r'(?i)URLConnection\s*\(\s*.*\)',  # Java URLConnection
    r'(?i)WebRequest\.Create\s*\(\s*.*\)',  # C# WebRequest.Create
    r'(?i)HttpWebRequest\s*\(\s*.*\)',  # C# HttpWebRequest
    r'(?i)socket\.connect\s*\(\s*.*\)',  # socket.connect any input
    r'(?i)URL\s+url\s*=\s*new\s+URL\s*\(\s*.*\)',  # Java new URL()
    r'(?i)wget\s+.*',  # wget command
    r'(?i)curl\s+.*',  # curl command
    r'(?i)fetch\s*\(\s*.*\)',  # JS fetch()
    r'(?i)axios\s*\(\s*.*\)',  # JS axios()
    r'(?i)file://',  # file:// SSRF
    r'(?i)gopher://',  # gopher:// SSRF
    r'(?i)dict://',  # dict:// SSRF
    r'(?i)ftp://',  # ftp:// SSRF

    # SSRF bypass: HTTP requests to private/loopback addresses
    r'(?i)(?:fetch|axios|http\.get|http\.request|requests\.get|requests\.post|urllib\.request\.urlopen|curl)\s*\([^)]*(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1)\b',
    r'(?i)(?:fetch|axios|http\.get|requests\.get|requests\.post)\s*\([^)]*(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
    r'(?i)(?:fetch|axios|http\.get|requests\.get)\s*\([^)]*169\.254\.',  # link-local

    # SSRF bypass via unusual IP representations
    r'\b0x7[fF]\.0x0+\.0x0+\.0x0*1\b',   # hex loopback 0x7f.0x00.0x00.0x01
    r'\b0177\.0+\.0+\.0*1\b',              # octal loopback 0177.0.0.1
    r'\b2130706433\b',                      # decimal loopback (127.0.0.1 = 2130706433)
    r'\b017700000001\b',                    # octal loopback compact

    # Cloud metadata endpoints — high-value SSRF target
    r'(?i)169\.254\.169\.254',              # AWS/GCP/Azure IMDSv1
    r'(?i)metadata\.google\.internal',      # GCP metadata
    r'(?i)169\.254\.170\.2',               # ECS metadata

    # SSRF via user-supplied URL in HTTP client call
    r'(?i)(?:fetch|axios|http\.(?:get|request)|requests\.(?:get|post|put|delete)|urllib\.request\.urlopen)\s*\(\s*req\.(params|query|body)\.',
    r'(?i)(?:fetch|axios|requests\.get)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)',
]
