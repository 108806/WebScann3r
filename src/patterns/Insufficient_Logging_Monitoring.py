# Patterns for Insufficient Logging & Monitoring
# Strategy: flag structural code smells that provably swallow errors silently.
# Removed: generic CRUD function names (delete, update, create), endpoint
# keywords (admin, auth, login) and comment searches — these fire on every
# web application and carry no actionable signal without taint analysis.

insufficient_logging_monitoring_patterns = [
    # Empty exception handler — errors silently swallowed (Python)
    r'except\s*:\s*pass',
    r'except\s+\w+.*:\s*pass',

    # Empty catch block — errors silently swallowed (Java, JS, C#, PHP)
    r'catch\s*\([^)]*\)\s*\{\s*\}',

    # Explicit no-logging comment (developer acknowledged it)
    r'pass\s*#\s*no\s*logg',

    # Catch-all exception with only a pass/noop — Python
    r'except\s+Exception\s*:\s*pass',

    # JS/TS: catch block with only a comment or empty body
    r'catch\s*\([^)]*\)\s*\{\s*//[^\n]*\n\s*\}',
]
