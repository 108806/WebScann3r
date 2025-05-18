# Patterns for JWT Issues (expanded and well-commented)
jwt_issues_patterns = [
    r'(?i)JWT\.sign\(\s*.*,\s*[\'"]none[\'"]\s*',
    r'(?i)jwtOptions\s*=\s*{\s*(?:.*,\s*)?[\'"]{0,1}algorithm[\'"]{0,1}\s*:\s*[\'"]{1}none[\'"]{1}',
    r'(?i)\.verifySignature\(\s*false\s*\)',
    r'(?i)\.verify\(\s*.*,\s*.*,\s*{\s*(?:.*,\s*)?[\'"]{0,1}algorithms[\'"]{0,1}\s*:\s*\[[^\]]*[\'"]none[\'"]\s*[^\]]*\]',
    # Expanded patterns for more JWT detection
    r'(?i)jwt\.decode\(\s*.*\)',
    r'(?i)jwt\.verify\(\s*.*\)',
    r'(?i)jwt\.sign\(\s*.*\)',
    r'(?i)jwt\.encode\(\s*.*\)',
    r'(?i)jwt\.decode\(\s*.*\)',
    r'(?i)jwt\.unverified\(\s*.*\)',
    r'(?i)jwt\.get_unverified_header\(\s*.*\)',
    r'(?i)jwt\.get_unverified_claims\(\s*.*\)',
    r'(?i)jwt\.get_unverified_signature\(\s*.*\)',
    r'(?i)jwt\.get_unverified_payload\(\s*.*\)',
    r'(?i)jwt\.get_unverified_token\(\s*.*\)',
    r'(?i)jwt\.get_unverified\(\s*.*\)',
]
