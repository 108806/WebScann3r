# Patterns for Server-Side Template Injection (SSTI) (expanded and well-commented)
ssti_patterns = [
    r'(?i)\{\{.*\}\}',
    r'(?i)\{%.*%\}',
    r'(?i)\$\{.*\}',
    r'(?i)<%.*%>',
    r'(?i)\bjinja2\b',
    r'(?i)\btwig\b',
    r'(?i)\berb\b',
    r'(?i)\btemplate\b',
]
