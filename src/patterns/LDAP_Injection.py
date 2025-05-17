patterns = [
    # TLDR: Detects ldapsearch command with special LDAP filter characters and variable
    r'(?i)ldapsearch.*[+&|!].*\$',
    # TLDR: Detects LDAP filter with variable assignment
    r'(?i)(&(.*=\$.*))',
    # TLDR: Detects LDAP filter with wildcard assignment
    r'(?i)(&(.*=\*.*))',
    # TLDR: Detects filter parameter with parentheses (potential injection)
    r'(?i)filter=.*\(|\)',
    # TLDR: Detects objectClass filter with wildcard
    r'(?i)(&(objectClass=*))',
    # TLDR: Detects any ldap_ function usage
    r'(?i)\bldap_.*',
    # TLDR: Detects common LDAP function calls
    r'(?i)\bldap_(add|delete|modify|search|bind|connect)\b',
    # TLDR: Detects filter parameter assigned from variable
    r'(?i)\bfilter=\$[\w]+',
]
