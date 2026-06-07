# All patterns for Open Redirect (expanded and commented)
open_redirect_patterns = [
    # JavaScript/HTML: Assigning user input to location or meta refresh
    r'(?i)(window\.location|location\.href|location\.replace|location\.assign|location|<meta[^>]*?refresh[^>]*?content=["\'][^"\']*?url=|<meta[^>]*?http-equiv=["\']?refresh[^>]*?content=["\'][^"\']*?url=)\s*=\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    # Server-side: redirect functions with user input (PHP, Node.js, Java, etc.)
    r'(?i)response\.redirect\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)res\.redirect\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)header\(\s*[\'"]Location:\s*[\'"]\.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)sendRedirect\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    # Expanded: location assignments that change the page (navigate away)
    # Exclude assignments of quoted literal strings (not user-controlled)
    r'(?i)window\.location\s*=\s*[^"\'\n]',
    r'(?i)location\.replace\s*\(\s*[^"\'\n]',
    r'(?i)location\.assign\s*\(\s*[^"\'\n]',
    r'(?i)document\.location\s*=\s*[^"\'\n]',
    r'(?i)window\.navigate\s*\(\s*[^"\'\n]',
    r'(?i)window\.location\.href\s*=\s*[^"\'\n]',
    r'(?i)window\.location\.replace\s*\(\s*[^"\'\n]',
    r'(?i)window\.location\.assign\s*\(\s*[^"\'\n]',
    # reload, search, hash, and port removed — not open redirect vectors
    r'(?i)window\.location\.pathname\s*=\s*[^"\'\n]',
    r'(?i)window\.location\.protocol\s*=\s*[^"\'\n]',
    r'(?i)window\.location\.host\s*=\s*[^"\'\n]',
    r'(?i)window\.location\.hostname\s*=\s*[^"\'\n]',
    # Java: sendRedirect with user input
    r'(?i)HttpServletResponse\.sendRedirect\s*\(.*request\.getParameter',
    # Python: Flask redirect with request.args/request.form
    r'(?i)redirect\s*\(\s*request\.(args|get|form)',
    # Ruby: redirect_to with params
    r'(?i)redirect_to\s*\(\s*params',
    # .NET: Response.Redirect with Request.QueryString
    r'(?i)Response\.Redirect\s*\(\s*Request\.QueryString',
]
