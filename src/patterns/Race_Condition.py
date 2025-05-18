# Patterns for Race Condition (TOCTOU, concurrency, etc.) vulnerabilities (expanded and well-commented)
race_condition_patterns = [
    # Classic time-of-check to time-of-use (TOCTOU) in Python
    r'os\.access\s*\(.*\)\s*;?\s*open\s*\(',  # Check then open
    r'flock\s*\(',  # Use of flock (may indicate locking, but also race if not used properly)
    # Python: tempfile usage without delete=False
    r'tempfile\.NamedTemporaryFile\s*\(',
    # Python: use of mktemp (deprecated, insecure)
    r'os\.mktemp\s*\(',
    # C/C++: open() with O_CREAT|O_EXCL without proper checks
    r'open\s*\(.*O_CREAT.*O_EXCL',
    # C/C++: use of tmpnam, tempnam, mktemp (unsafe temp file creation)
    r'tmpnam\s*\(',
    r'tempnam\s*\(',
    r'mktemp\s*\(',
    # Java: File.createTempFile without secure random or proper permissions
    r'File\.createTempFile\s*\(',
    # Java: File.delete() followed by File.createNewFile()
    r'File\.delete\s*\(\)\s*;?\s*File\.createNewFile\s*\(',
    # Node.js: fs.open with flags 'wx' or 'ax' (should check for races)
    r'fs\.open\s*\(.*["\"][wa]x["\"]',
    # Node.js: use of tmp or temp modules
    r'require\(["\"]tmp["\"]\)',
    r'require\(["\"]temp["\"]\)',
    # Go: os.CreateTemp, ioutil.TempFile (should check for races)
    r'os\.CreateTemp\s*\(',
    r'ioutil\.TempFile\s*\(',
    # Generic: critical section without lock
    r'critical_section\s*\(',
    r'no_lock\s*\(',
    # Generic: comment or TODO about race condition
    r'TODO.*race',
    r'FIXME.*race',
    r'//.*race condition',
    r'#.*race condition',
]
