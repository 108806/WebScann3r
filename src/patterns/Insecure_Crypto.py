# All patterns for Insecure Crypto (expanded and commented)
insecure_crypto_patterns = [
    # Weak hash functions
    r'(?i)md5\s*\(',  # Use of MD5
    r'(?i)sha1\s*\(',  # Use of SHA1
    r'(?i)sha-1',  # Use of SHA-1 string
    r'(?i)ripemd160',  # Use of RIPEMD160
    r'(?i)whirlpool',  # Use of Whirlpool
    # Weak/block ciphers (with word boundaries to avoid false positives)
    r'(?i)\bcrypt\s*\(',  # Use of crypt()
    r'(?i)\bdes\s*\(',  # Use of DES
    r'(?i)\brc2\s*\(',  # Use of RC2
    r'(?i)\brc4\s*\(',  # Use of RC4
    r'(?i)\brc5\s*\(',  # Use of RC5
    r'(?i)\bblowfish\s*\(',  # Use of Blowfish
    r'(?i)\bCAST5\b',  # Use of CAST5
    r'(?i)\bCAST6\b',  # Use of CAST6
    r'(?i)\bTEA\b',  # Use of TEA (word boundary to avoid false positives)
    r'(?i)\bXTEA\b',  # Use of XTEA
    r'(?i)\bARC4\b',  # Use of ARC4
    # Insecure modes
    r'(?i)ECB',  # Use of ECB mode
    r'(?i)CBC',  # Use of CBC mode (sometimes insecure if not used with random IV)
    # Insecure/unsalted random
    r'(?i)no\s*salt',  # No salt used
    r'(?i)random\.seed\(',  # Predictable random seed
    r'(?i)random\.setSeed\(',  # Predictable random seed (Java)
    r'(?i)random\.new\(',  # Predictable random (Python)
    r'(?i)RandomNumberGenerator\(',  # Predictable random (C#)
    r'(?i)java\.security\.SecureRandom\s*\(\s*\)',  # Java SecureRandom without seed
    # Insecure crypto libraries/APIs
    r'(?i)CryptoJS\.MD5',
    r'(?i)CryptoJS\.SHA1',
    r'(?i)createHash\([\'\"]md5[\'\"]\)',
    r'(?i)createHash\([\'\"]sha1[\'\"]\)',
    r'(?i)MessageDigest\.getInstance\([\'\"]MD5[\'\"]\)',
    r'(?i)MessageDigest\.getInstance\([\'\"]SHA-1[\'\"]\)',
    r'(?i)hashlib\.md5\(',
    r'(?i)hashlib\.sha1\(',
    r'(?i)openssl_encrypt\s*\(.*[\'\"](?:des|rc2|rc4|rc5|md5|sha1)[\'\"]',
    r'(?i)use\s+([A-Za-z0-9_]+CryptoServiceProvider)',
    # Base64 for encoding secrets (not encryption)
    r'(?i)base64\.(?:encode|decode)\(',
    # XOR for encryption
    r'(?i)xor\s*\(',
    # Use of weak hash or cipher in comments
    r'(?i)use\s+of\s+weak\s+hash',
    r'(?i)use\s+of\s+weak\s+cipher',
    # Deprecated/legacy algorithms
    r'(?i)md2',
    r'(?i)md4',
    r'(?i)HAVAL',
    r'(?i)Tiger',
    # Hardcoded keys or IVs (generic)
    r'(?i)key\s*=\s*[\'\"]?[A-Za-z0-9+/=]{8,}',
    r'(?i)iv\s*=\s*[\'\"]?[A-Za-z0-9+/=]{8,}',
]
