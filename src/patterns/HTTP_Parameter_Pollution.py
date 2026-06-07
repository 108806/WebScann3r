# Patterns for HTTP Parameter Pollution (HPP)
# Strategy: flag APIs specifically designed to return multiple values for the
# same parameter name, which is the prerequisite for HPP exploitation.
# Removed: params\s*\[ (every Rails controller), req\.query\s*\[ (every
# Express handler), $_GET\[$/ $_POST\[$ (every PHP page), r.URL.Query() (every
# Go handler) — these are normal single-value parameter access patterns and
# produce zero HPP-specific signal on their own.

http_parameter_pollution_patterns = [
    # Python/Flask: getlist explicitly retrieves ALL values for a key (HPP-specific)
    r'request\.args\.getlist\s*\(',
    r'request\.form\.getlist\s*\(',

    # Python: parse_qs returns lists — each key maps to a list of values
    r'\bparse_qs\s*\(',
    r'\bparse_qsl\s*\(',
    r'urlparse\.parse_qs\s*\(',
    r'urlparse\.parse_qsl\s*\(',

    # Java: getParameterValues returns ALL values (the HPP-specific API)
    r'request\.getParameterValues\s*\(',
    r'request\.getParameterMap\s*\(',

    # JavaScript: qs.parse produces arrays when a key repeats
    r'\bqs\.parse\s*\(',

    # Generic: multiple get() calls concatenated (possible HPP merge)
    r'get\s*\([^)]+\)\s*\+\s*get\s*\([^)]+\)',
]
