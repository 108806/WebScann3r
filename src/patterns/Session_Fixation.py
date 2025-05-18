# Patterns for Session Fixation (expanded and well-commented)
session_fixation_patterns = [
    # Look for session id settable by user (Python, Flask, Django, etc.)
    r'session_id\s*=\s*request',  # session_id from user input
    r'session\.set\s*\(',  # session.set() call
    r'Set-Cookie:\s*PHPSESSID=',  # Set-Cookie PHPSESSID
    # Flask: manually setting session cookie from user input
    r'session\[.*\]\s*=\s*request\.(args|get|form|cookies)',
    # Django: manually setting sessionid from user input
    r'response\.set_cookie\(\s*["\"]sessionid["\"],\s*request\.(GET|POST|COOKIES)',
    # Express/Node.js: res.cookie with user input
    r'res\.cookie\(\s*["\"]connect\.sid["\"],\s*req\.(query|body|cookies)',
    r'res\.setHeader\(\s*["\"]Set-Cookie["\"],\s*.*req\.(query|body|cookies)',
    # PHP: session_id() set from user input
    r'session_id\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'setcookie\s*\(\s*["\"]PHPSESSID["\"],\s*\$_(?:GET|POST|REQUEST|COOKIE)',
    # Java: setHeader with JSESSIONID from user input
    r'response\.setHeader\(\s*["\"]Set-Cookie["\"],\s*.*request\.(getParameter|getHeader|getQueryString|getAttribute)',
    # .NET: Response.Cookies with user input
    r'Response\.Cookies\[.*\]\.Value\s*=\s*Request\.(QueryString|Form|Cookies)',
    # Ruby: cookies[] set from params
    r'cookies\[.*\]\s*=\s*params',
    # Generic: session id reflected from URL or query
    r'sessionid=\w{10,}',
    r'jsessionid=\w{10,}',
    r'phpsessid=\w{10,}',
    r'connect\.sid=\w{10,}',
    # Generic: session id set from user-controlled variable
    r'session_id\s*=\s*userinput',
    r'sessionid\s*=\s*userinput',
]
