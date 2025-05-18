# Patterns for HTTP Parameter Pollution (HPP)
# Expanded to cover more languages, frameworks, and raw query parsing
http_parameter_pollution_patterns = [
    # Python/Flask: getlist allows multiple values for the same parameter
    r'request\.args\.getlist\(',
    # Python: manual parsing of query string
    r'request\.query_string',
    r'parse_qs\(',
    r'parse_qsl\(',
    # PHP: $_GET, $_POST, $_REQUEST direct use (multiple values possible)
    r'\$_GET\s*\[',
    r'\$_POST\s*\[',
    r'\$_REQUEST\s*\[',
    # Node.js/Express: req.query, req.body direct use
    r'req\.query\s*\[',
    r'req\.body\s*\[',
    # Java: request.getParameterValues (returns all values for a parameter)
    r'request\.getParameterValues\(',
    # Java: request.getParameterMap (map of all parameters, may have multiple values)
    r'request\.getParameterMap\(',
    # Ruby on Rails: params[] direct use
    r'params\s*\[',
    # Go: r.URL.Query(), r.FormValue, r.PostFormValue
    r'r\.URL\.Query\(',
    r'r\.FormValue\(',
    r'r\.PostFormValue\(',
    # Generic: splitting/query parsing without deduplication
    r'querystring\.split\(',
    r'querystring\.parse\(',
    # Multiple get() or param access in a single expression (possible HPP)
    r'get\s*\([^)]+\)\s*\+\s*get\s*\([^)]+\)',
    # Use of raw query string
    r'RAW_QUERY_STRING',
    # Use of frameworks/libraries that allow repeated parameters
    r'qs\.parse\(',
    r'urlparse\.parse_qs\(',
    r'urlparse\.parse_qsl\(',
]
