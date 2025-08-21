"""
Patterns for extracting URLs from JavaScript, CSS, and HTML content.
Expand these lists as new URL usage patterns are discovered in the wild.
"""

js_url_patterns = [
    r'(https?://[^\s\'"<>()]+)',  # HTTP URLs
    r'[\'\"]([/][^\'\"]*\.(js|css|php|html|htm))[\'\"]',  # Quoted paths with extensions
    r'[\'\"]([/][a-zA-Z0-9_\-/\.]+)[\'\"]',  # Quoted paths
    r'fetch\([\'\"]([^\'\"]+)[\'\"]\)',  # fetch API calls
    r'xhr\.open\([\'\"]GET[\'\"], [\'\"]([^\'\"]+)[\'\"]',  # XHR requests
    r'axios\.(get|post|put|delete|patch)\([\'\"]([^\'\"]+)[\'\"]',  # axios requests - group 2 is the URL
    r'\.ajax\(\{\s*url:\s*[\'\"]([^\'\"]+)[\'\"]',  # jQuery AJAX calls
    r'import\([\'\"]([^\'\"]+)[\'\"]\)',  # dynamic import()
    r'WebSocket\([\'\"]([^\'\"]+)[\'\"]\)',  # WebSocket URLs
    r'EventSource\([\'\"]([^\'\"]+)[\'\"]\)',  # EventSource URLs
    r'location\.href\s*=\s*[\'\"]([^\'\"]+)[\'\"]',  # location.href assignment
    r'window\.open\([\'\"]([^\'\"]+)[\'\"]',  # window.open
    # New patterns for dynamic script loading
    r'document\.createElement\([\'\"]\s*script\s*[\'\"]\)[\s\S]*?\.src\s*=\s*[\'\"]([^\'\"]+)[\'\"]',  # createElement script
    r'\.setAttribute\(\s*[\'\"]\s*src\s*[\'\"]\s*,\s*[\'\"]([^\'\"]+)[\'\"]',  # setAttribute src
    r'\.src\s*=\s*[\'\"]([^\'\"]+\.js[^\'\"]*)[\'\"]\s*;',  # Direct .src assignment
    r'require\([\'\"]([^\'\"]+)[\'\"]\)',  # CommonJS require
    r'loadScript\([\'\"]([^\'\"]+)[\'\"]\)',  # Custom loadScript functions
    r'getScript\([\'\"]([^\'\"]+)[\'\"]\)',  # jQuery getScript
    r'[\'\"](\s*/[^\'\"]*\.js[^\'\"]*)\s*[\'\"]\s*[,\)]',  # JS file paths in arrays/function calls
    # AJAX and XHR patterns
    r'ajaxGet\(\s*[\'\"]([^\'\"]+)[\'\"]',  # Custom ajaxGet function calls
    r'get\(\s*[\'\"]([^\'\"]+)[\'\"]',  # Custom get function calls (like in our target)
    r'x\.open\(\s*[\'\"]GET[\'\"],\s*[\'\"]([^\'\"]+)[\'\"]',  # Direct XMLHttpRequest.open calls
    r'\.send\(\s*[\'\"]([^\'\"]+)[\'\"]',  # XHR send with URL
]

css_url_patterns = [
    r'url\([\'\"]?([^\'\"<>()]+)[\'\"]?\)',  # CSS url() function
    r'@import\s+[\'\"]([^\'\"]+)[\'\"]',  # CSS @import rule
]

html_url_patterns = [
    # These are typically handled by tag/attribute extraction, but regex for inline URLs can be added if needed
    r'(https?://[^\s\'"<>()]+)',
    r'(\/[^\s\'"<>()]+\.(js|css|php|html|htm|jpg|jpeg|png|gif|svg|webp|ico|json|xml))',
]
