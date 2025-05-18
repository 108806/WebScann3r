# Patterns for Sensitive Data Exposure (expanded and well-commented)
sensitive_data_exposure_patterns = [
    # TLDR: Detects PEM private key blocks
    r'(?i)BEGIN PRIVATE KEY',
    # TLDR: Detects PEM RSA private key blocks
    r'(?i)BEGIN RSA PRIVATE KEY',
    # TLDR: Detects PEM DSA private key blocks
    r'(?i)BEGIN DSA PRIVATE KEY',
    # TLDR: Detects PEM EC private key blocks
    r'(?i)BEGIN EC PRIVATE KEY',
    # TLDR: Detects OpenSSH private key blocks
    r'(?i)BEGIN OPENSSH PRIVATE KEY',
    # TLDR: Detects encrypted private key blocks
    r'(?i)BEGIN ENCRYPTED PRIVATE KEY',
    # TLDR: Detects PEM certificate blocks
    r'(?i)BEGIN CERTIFICATE',
    # TLDR: Detects PGP private key blocks
    r'(?i)BEGIN PGP PRIVATE KEY BLOCK',
    # TLDR: Detects PGP message blocks
    r'(?i)BEGIN PGP MESSAGE',
    # TLDR: Detects PGP public key blocks
    r'(?i)BEGIN PGP PUBLIC KEY BLOCK',
    # TLDR: Detects SSH2 encrypted private key blocks
    r'(?i)BEGIN SSH2 ENCRYPTED PRIVATE KEY',
    # TLDR: Detects X509 certificate revocation lists
    r'(?i)BEGIN X509 CRL',
    # TLDR: Detects Diffie-Hellman parameters
    r'(?i)BEGIN DH PARAMETERS',
    # TLDR: Detects PKCS7 blocks
    r'(?i)BEGIN PKCS7',
    # TLDR: Detects PKCS12 blocks
    r'(?i)BEGIN PKCS12',
    # TLDR: Detects DSA parameters
    r'(?i)BEGIN DSA PARAMETERS',
    # TLDR: Detects EC parameters
    r'(?i)BEGIN EC PARAMETERS',
    # TLDR: Detects certificate signing requests
    r'(?i)BEGIN NEW CERTIFICATE REQUEST',
    # TLDR: Detects password assignments
    r'(?i)password\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects passwd assignments
    r'(?i)passwd\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects pwd assignments
    r'(?i)pwd\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects secret assignments
    r'(?i)secret\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects api_key assignments
    r'(?i)api[_-]?key\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects apikey assignments
    r'(?i)apikey\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects access_key assignments
    r'(?i)access[_-]?key\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects secret_key assignments
    r'(?i)secret[_-]?key\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects client_secret assignments
    r'(?i)client[_-]?secret\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects access_token assignments
    r'(?i)access[_-]?token\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects auth_token assignments
    r'(?i)auth[_-]?token\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects refresh_token assignments
    r'(?i)refresh[_-]?token\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects Bearer tokens
    r'(?i)bearer\s+[A-Za-z0-9\-_\.]+',
    # TLDR: Detects JWT tokens
    r'(?i)jwt\s*[:=]\s*[\'\"]?eyJ[A-Za-z0-9\-_\.]+',
    # TLDR: Detects session_id assignments
    r'(?i)session[_-]?id\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects auth_cookie assignments
    r'(?i)auth[_-]?cookie\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects cookie assignments
    r'(?i)cookie\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects user_password assignments
    r'(?i)user[_-]?password\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects user_secret assignments
    r'(?i)user[_-]?secret\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects user_token assignments
    r'(?i)user[_-]?token\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects user_key assignments
    r'(?i)user[_-]?key\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects db_password assignments
    r'(?i)db[_-]?password\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects db_user assignments
    r'(?i)db[_-]?user\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects db_host assignments
    r'(?i)db[_-]?host\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects db_name assignments
    r'(?i)db[_-]?name\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects db_connection assignments
    r'(?i)db[_-]?connection\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects db_conn assignments
    r'(?i)db[_-]?conn\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects database_password assignments
    r'(?i)database[_-]?password\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects database_user assignments
    r'(?i)database[_-]?user\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects database_host assignments
    r'(?i)database[_-]?host\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects database_name assignments
    r'(?i)database[_-]?name\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects database_connection assignments
    r'(?i)database[_-]?connection\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects database_conn assignments
    r'(?i)database[_-]?conn\s*[:=]\s*[\'\"]?[^\'\"]{6,}[\'\"]?',
    # TLDR: Detects AWS Access Key IDs
    r'(?i)AKIA[0-9A-Z]{16}',
    # TLDR: Detects AWS Temporary Access Keys
    r'(?i)ASIA[0-9A-Z]{16}',
    # TLDR: Detects AWS Root Access Keys
    r'(?i)A3T[A-Z0-9]{16}',
    # TLDR: Detects AWS secret access key assignments
    r'(?i)aws_secret_access_key\s*[:=]\s*[\'\"]?[^\'\"]{20,}[\'\"]?',
    # TLDR: Detects AWS access key ID assignments
    r'(?i)aws_access_key_id\s*[:=]\s*[\'\"]?[^\'\"]{16,}[\'\"]?',
    # TLDR: Detects AWS session token assignments
    r'(?i)aws_session_token\s*[:=]\s*[\'\"]?[^\'\"]{20,}[\'\"]?',
    # TLDR: Detects Google API keys
    r'(?i)AIza[0-9A-Za-z\-_]{35}',
]
