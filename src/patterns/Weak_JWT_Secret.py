# Patterns for Weak JWT Secret (expanded and well-commented)
weak_jwt_secret_patterns = [
    r'(?i)jwt\.sign\(.*[\'\"]{1,8}[\'\"]',
    r'(?i)jwt\.encode\(.*[\'\"]{1,8}[\'\"]',
    r'(?i)secret\s*[:=]\s*[\'\"]{1,8}[\'\"]',
    r'(?i)jwt_secret\s*[:=]\s*[\'\"]{1,8}[\'\"]',
    r'(?i)jwt.*HS256',
]
