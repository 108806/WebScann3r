# Patterns for Reflected File Download (RFD) vulnerabilities (expanded and well-commented)
reflected_file_download_patterns = [
    # Look for user input reflected in file download responses (Python, Flask, Django, etc.)
    r'Content-Disposition.*filename.*\+.*request',  # Python string concat with request
    r'response\.headers\s*\[.*filename.*\]\s*=\s*.*request',  # Python response.headers assignment
    r'Content-Disposition.*filename=.*\{.*\}',  # Python f-string or format
    r'Content-Disposition.*filename=.*%s',  # Python %-formatting
    # JavaScript/Node.js: Express, Koa, etc.
    r'res\.setHeader\(\s*["\"]Content-Disposition["\"],\s*.*req\.(query|body|params)',  # Express setHeader with user input
    r'response\.setHeader\(\s*["\"]Content-Disposition["\"],\s*.*req\.(query|body|params)',
    r'res\.attachment\(.*req\.(query|body|params)',  # Express attachment()
    r'res\.download\(.*req\.(query|body|params)',  # Express download()
    # PHP: header() with user input
    r'header\(\s*["\"]Content-Disposition:.*\$_(?:GET|POST|REQUEST|COOKIE)',
    # Java: setHeader with user input
    r'response\.setHeader\(\s*["\"]Content-Disposition["\"],\s*.*request\.(getParameter|getHeader|getQueryString|getAttribute)',
    # Ruby: send_data/send_file with user input
    r'send_(data|file)\s*\(.*params',
    # Go: w.Header().Set with user input
    r'w\.Header\(\)\.Set\(\s*["\"]Content-Disposition["\"],\s*.*r\.(FormValue|URL\.Query)',
    # Generic: filename parameter with user input
    r'Content-Disposition.*filename=.*(GET|POST|REQUEST|COOKIE|req|request|params|query|body)',
    # Generic: filename reflected from URL or query
    r'filename=[^;\n]*[?&][^;\n]*=',
    # Generic: filename reflected from path
    r'filename=[^;\n]*\/[^;\n]*',
    # Generic: filename reflected from user-controlled variable
    r'filename=.*userinput',
    # Generic: filename reflected from HTTP header
    r'filename=.*http_header',
]
