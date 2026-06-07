# Patterns for Insecure Randomness
# Strategy: flag use of non-cryptographic PRNGs in contexts where security-
# grade randomness is needed. Removed: SecureRandom (that IS the secure API),
# bare \brand\b / \bsrand\b (match variable names like 'brand'), random_device
# (C++ secure source), and rand\s*\( as a standalone pattern (too broad).

insecure_randomness_patterns = [
    # JavaScript: Math.random() is not CSPRNG
    r'(?i)Math\.random\s*\(',

    # Python: random module is not CSPRNG — flag the module-qualified calls
    r'(?i)random\.random\s*\(',
    r'(?i)random\.randint\s*\(',
    r'(?i)random\.randrange\s*\(',
    r'(?i)random\.choice\s*\(',
    r'(?i)random\.shuffle\s*\(',
    r'(?i)random\.uniform\s*\(',

    # PHP: non-cryptographic functions
    r'(?i)\bmt_rand\s*\(',
    r'(?i)\blcg_value\s*\(',

    # Java: new Random() (not SecureRandom)
    r'(?i)\bnew\s+Random\s*\(',
    r'(?i)random\.setSeed\s*\(',  # seeded = predictable output

    # C: drand48 family (non-CSPRNG)
    r'(?i)\bdrand48\s*\(',

    # Go: math/rand package (not crypto/rand)
    r'(?i)["\']math/rand["\']',

    # Node.js: deprecated pseudo-random
    r'(?i)crypto\.pseudoRandomBytes\s*\(',

    # Security-sensitive values assigned from non-crypto random
    r'(?i)(?:token|sessionid|session_id|nonce|salt|password|secret)\s*=\s*.*[Mm]ath\.random\s*\(',
    r'(?i)(?:token|sessionid|session_id|nonce|salt|password|secret)\s*=\s*.*random\.(?:random|randint|choice)\s*\(',
]
