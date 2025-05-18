# Patterns for Insufficient Logging & Monitoring (expanded and commented)
insufficient_logging_monitoring_patterns = [
    # Placeholder: pass with comment about no logging (Python)
    r'pass\s*#\s*no\s*logging',
    # TODO comments about missing logging
    r'TODO.*log',
    # Critical actions without logging (generic, may need manual review)
    r'(?i)delete\s*\(',  # Deletion without logging
    r'(?i)update\s*\(',  # Update without logging
    r'(?i)insert\s*\(',  # Insert without logging
    r'(?i)remove\s*\(',  # Remove without logging
    r'(?i)create\s*\(',  # Create without logging
    # Look for empty except blocks (Python)
    r'except\s*:\s*pass',
    # Look for catch blocks with no logging (Java, JS, etc.)
    r'catch\s*\([^)]*\)\s*\{\s*\}',
    # Look for commented out logging statements
    r'(?i)//\s*log',
    r'(?i)#\s*log',
    # Look for missing audit/logging in sensitive endpoints (generic)
    r'(?i)admin',
    r'(?i)auth',
    r'(?i)login',
    r'(?i)logout',
    r'(?i)register',
    r'(?i)payment',
    r'(?i)transfer',
]
