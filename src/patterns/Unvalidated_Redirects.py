# Patterns for Unvalidated Redirects (expanded and well-commented)
unvalidated_redirects_patterns = [
    r'(?i)window\.location\s*=\s*.*',
    r'(?i)header\(\s*[\'\"]Location:.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)\bredirect\b.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)\bResponse\.Redirect\(',
    r'(?i)\bHttpServletResponse\.sendRedirect\(',
]
