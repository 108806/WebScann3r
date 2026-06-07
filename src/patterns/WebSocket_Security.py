# Patterns for WebSocket Security Issues
websocket_security_patterns = [
    # Unencrypted ws:// instead of wss://
    r'\bws://[^\s\'"]+',
    r'(?i)new\s+WebSocket\s*\(\s*["\']ws://',
    r'(?i)(?:wsUrl|wsEndpoint|socketUrl|wsUri)\s*=\s*["\']ws://',
    r'(?i)websocket.*url\s*:\s*["\']ws://',

    # Missing origin validation on server-side connection handler
    r'(?i)\.on\s*\(\s*["\']connection["\']',

    # WebSocket message content used directly without validation
    r'(?i)(?:JSON\.parse|eval)\s*\(\s*(?:event\.data|message\.data|e\.data|msg\.data)\s*\)',
    r'(?i)(?:innerHTML|document\.write|eval)\s*\(.*event\.data',

    # Socket.io without auth middleware on connection
    r'(?i)io\.on\s*\(\s*["\']connection["\']',
    r'(?i)socket\.on\s*\(\s*["\']message["\']',

    # Sensitive data transmitted over WebSocket
    r'(?i)socket\.(?:send|emit)\s*\([^)]*(?:password|token|secret|api_?key|credential)',
    r'(?i)ws\.send\s*\([^)]*(?:password|token|secret|api_?key|credential)',

    # CSRF via WebSocket — no token/nonce on upgrade
    r'(?i)new\s+WebSocket\s*\([^)]*\)',

    # ws/socket.io server listening without authentication
    r'(?i)const\s+(?:wss|wsServer)\s*=\s*new\s+(?:WebSocket\.Server|Server)\s*\(',
    r'(?i)app\.ws\s*\(\s*["\'][^"\']+["\']',
]
