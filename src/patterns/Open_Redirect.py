# All patterns for Open Redirect (expanded and commented)
open_redirect_patterns = [
    # JavaScript/HTML: Assigning user input to location or meta refresh
    r'(?i)(window\.location|location\.href|location\.replace|location\.assign|location|<meta[^>]*?refresh[^>]*?content=["\'][^"\']*?url=|<meta[^>]*?http-equiv=["\']?refresh[^>]*?content=["\'][^"\']*?url=)\s*=\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    # Server-side: redirect functions with user input (PHP, Node.js, Java, etc.)
    r'(?i)response\.redirect\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)res\.redirect\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)header\(\s*[\'"]Location:\s*[\'"]\.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)sendRedirect\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    # Expanded: Any assignment or function call with user-controlled input
    r'(?i)window\.location\s*=\s*.*',
    r'(?i)location\.replace\s*\(\s*.*\)',
    r'(?i)location\.assign\s*\(\s*.*\)',
    r'(?i)document\.location\s*=\s*.*',
    r'(?i)window\.navigate\s*\(\s*.*\)',
    r'(?i)window\.location\.href\s*=\s*.*',
    r'(?i)window\.location\.replace\s*\(\s*.*\)',
    r'(?i)window\.location\.assign\s*\(\s*.*\)',
    r'(?i)window\.location\.reload\s*\(\s*.*\)',
    r'(?i)window\.location\.search\s*=\s*.*',
    r'(?i)window\.location\.hash\s*=\s*.*',
    r'(?i)window\.location\.pathname\s*=\s*.*',
    r'(?i)window\.location\.protocol\s*=\s*.*',
    r'(?i)window\.location\.host\s*=\s*.*',
    r'(?i)window\.location\.hostname\s*=\s*.*',
    r'(?i)window\.location\.port\s*=\s*.*',
    r'(?i)window\.location\.origin\s*=\s*.*',
    # Java: sendRedirect with user input
    r'(?i)HttpServletResponse\.sendRedirect\s*\(.*request\.getParameter',
    # Python: Flask redirect with request.args/request.form
    r'(?i)redirect\s*\(\s*request\.(args|get|form)',
    # Ruby: redirect_to with params
    r'(?i)redirect_to\s*\(\s*params',
    # .NET: Response.Redirect with Request.QueryString
    r'(?i)Response\.Redirect\s*\(\s*Request\.QueryString',
]
