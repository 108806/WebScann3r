# Patterns for Insecure Randomness (expanded and commented)
insecure_randomness_patterns = [
    # JavaScript: Math.random() is not cryptographically secure
    r'(?i)Math\.random\s*\(',
    # Python: random.random(), random.randint(), random.randrange(), random.choice(), etc.
    r'(?i)random\.random\s*\(',
    r'(?i)random\.randint\s*\(',
    r'(?i)random\.randrange\s*\(',
    r'(?i)random\.choice\s*\(',
    r'(?i)random\.shuffle\s*\(',
    r'(?i)random\.uniform\s*\(',
    # PHP: rand(), srand(), mt_rand(), lcg_value()
    r'(?i)rand\s*\(',
    r'(?i)srand\s*\(',
    r'(?i)mt_rand\s*\(',
    r'(?i)lcg_value\s*\(',
    # Java: java.util.Random, SecureRandom without seed
    r'(?i)\bnew\s+Random\b',
    r'(?i)\bSecureRandom\b',
    r'(?i)random\.setSeed\s*\(',
    # C/C++: rand(), srand(), drand48(), random(), getrand(), random_device
    r'(?i)\brand\s*\(',
    r'(?i)srand\s*\(',
    r'(?i)drand48\s*\(',
    r'(?i)getrand\s*\(',
    r'(?i)random_device',
    # Ruby: rand, srand
    r'(?i)\brand\b',
    r'(?i)\bsrand\b',
    # Go: math/rand package
    r'(?i)math/rand',
    # Node.js: Math.random(), crypto.pseudoRandomBytes (deprecated)
    r'(?i)crypto\.pseudoRandomBytes\s*\(',
    # Generic: use of weak/random for tokens, session IDs, etc.
    r'(?i)token\s*=\s*random',
    r'(?i)sessionid\s*=\s*random',
    r'(?i)password\s*=\s*random',
]
