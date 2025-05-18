# Patterns for Directory Listing Enabled (expanded and commented)
directory_listing_enabled_patterns = [
    # Apache, Nginx, and generic directory listing indicators
    r'(?i)Index of /',  # Apache, Nginx, generic
    r'(?i)Directory listing for /',  # Python SimpleHTTPServer, generic
    r'(?i)Options Indexes',  # Apache config
    r'(?i)autoindex on',  # Nginx config
    r'(?i)mod_autoindex',  # Apache module
    r'(?i)Parent Directory',  # Common in directory listings
    r'(?i)Directory of /',  # IIS
    r'(?i)Directory Listing -- /',  # Tomcat
    r'(?i)Directory: /',  # Node.js/Express serve-index
    r'(?i)list of files',  # Generic
    r'(?i)href="[^"]*/\?C=N;O=D"',  # Apache sort links
    r'(?i)href="[^"]*/\?C=M;O=A"',  # Apache sort links
    r'(?i)href="[^"]*/\?C=S;O=A"',  # Apache sort links
    r'(?i)href="[^"]*/\?C=D;O=A"',  # Apache sort links
    r'(?i)Directory Listing Denied',  # Some servers when disabled
]
