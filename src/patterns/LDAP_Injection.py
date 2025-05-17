patterns = [
    r'(?i)ldapsearch.*[+&|!].*\$',
    r'(?i)(&(.*=\$.*))',
    r'(?i)(&(.*=\*.*))',
    r'(?i)filter=.*\(|\)',
    r'(?i)(&(objectClass=*))',
    r'(?i)\bldap_.*',
    r'(?i)\bldap_(add|delete|modify|search|bind|connect)\b',
    r'(?i)\bfilter=\$[\w]+',
]
