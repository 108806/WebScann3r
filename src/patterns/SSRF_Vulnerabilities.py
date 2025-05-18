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
]
