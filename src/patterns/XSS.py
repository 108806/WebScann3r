# Patterns for Cross-Site Scripting (XSS)
# Strategy: require user-input context ($_ vars) where possible.
# Removed: window.name/parent/top/frames/self/opener (normal DOM access),
# ${...} (every ES6 template literal), {{...}} (normal Angular/Handlebars),
# <%...%> (normal server templates — covered by SSTI patterns).

xss_patterns = [
    # PHP user input directly reaching sinks — high confidence
    r'(?i)document\.write\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)\.innerHTML\s*=\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)\.outerHTML\s*=\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)eval\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)setTimeout\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)setInterval\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)new\s+Function\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)\.innerText\s*=\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)document\.body\.appendChild\s*\(.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)\.insertAdjacentHTML\s*\(.*\$_(?:GET|POST|REQUEST|COOKIE)',

    # Dangerous URI schemes in attribute values — XSS payloads
    # Exclude javascript:void(0) (placeholder) and javascript:__doPostBack (ASP.NET WebForms)
    r'(?i)javascript\s*:(?!\s*(?:void[\s(]|__doPostBack))',
    r'(?i)data:text/html',
    r'(?i)vbscript\s*:',

    # CSS expression — IE legacy XSS
    r'(?i)expression\s*\(',

    # Actual XSS payload markers in HTML attributes
    r'(?i)<img[\s\S]*?onerror\s*=\s*["\'][^"\']*["\']',
    r'(?i)<body[\s\S]*?onload\s*=\s*["\'][^"\']*["\']',
    r'(?i)<iframe[^>]+srcdoc\s*=',
    r'(?i)src\s*=\s*["\']data:text/html',

    # React dangerous prop
    r'(?i)dangerouslySetInnerHTML',

    # window.opener — opener-based XSS (specific enough)
    r'(?i)window\.opener\s*\.',
]
