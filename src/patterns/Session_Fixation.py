# Patterns for Session Fixation
patterns = [
    # Look for session id settable by user
    r'session_id\s*=\s*request', # session_id from user input
    r'session\.set\s*\(', # session.set() call
    r'Set-Cookie:\s*PHPSESSID=', # Set-Cookie PHPSESSID
]
