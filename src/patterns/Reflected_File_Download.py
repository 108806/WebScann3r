# Patterns for Reflected File Download
patterns = [
    # Look for user input reflected in file download responses
    r'Content-Disposition.*filename.*\+.*request',
    r'response\.headers\s*\[.*filename.*\]\s*=\s*.*request',
]
