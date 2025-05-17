patterns = [
    r'(?i)Set-Cookie:.*(HttpOnly|Secure)',
    r'(?i)Set-Cookie:.*SameSite=None',
    r'(?i)Set-Cookie:.*Domain=',
    r'(?i)Set-Cookie:.*Path=',
    r'(?i)Set-Cookie:((?!Secure).)*$',
    r'(?i)Set-Cookie:((?!HttpOnly).)*$',
]
