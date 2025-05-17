# All patterns for XSS
patterns = [
    r'(?i)document\.write\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)', # JS document.write with user input
    r'(?i)\.innerHTML\s*=\s*.*\$_(?:GET|POST|REQUEST|COOKIE)', # JS innerHTML with user input
    r'(?i)\.outerHTML\s*=\s*.*\$_(?:GET|POST|REQUEST|COOKIE)', # JS outerHTML with user input
    r'(?i)eval\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)', # JS eval with user input
    r'(?i)setTimeout\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)', # JS setTimeout with user input
    r'(?i)setInterval\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)', # JS setInterval with user input
    r'(?i)new\s+Function\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)', # JS Function() with user input
    r'(?i)\.innerText\s*=\s*.*\$_(?:GET|POST|REQUEST|COOKIE)', # JS innerText with user input
    r'(?i)document\.body\.appendChild\(.*\$_(?:GET|POST|REQUEST|COOKIE)', # appendChild with user input
    r'(?i)\.insertAdjacentHTML\(.*\$_(?:GET|POST|REQUEST|COOKIE)', # insertAdjacentHTML with user input
    r'(?i)window\.location\s*=\s*.*', # JS window.location assignment
    r'(?i)document\.(?:URL|cookie|domain|referrer)', # JS document properties
    r'(?i)on\w+\s*=\s*["\"][^"\"]*["\"]', # Inline event handlers
    r'(?i)<svg[\s\S]*?>[\s\S]*?<\/svg>', # SVG tag XSS
    r'(?i)<math[\s\S]*?>[\s\S]*?<\/math>', # MathML tag XSS
    r'(?i)<iframe[\s\S]*?>[\s\S]*?<\/iframe>', # iframe tag XSS
    r'(?i)<script[\s\S]*?>[\s\S]*?<\/script>', # script tag XSS
    r'(?i)<img[\s\S]*?onerror\s*=\s*["\"][^"\"]*["\"]', # img onerror XSS
    r'(?i)<body[\s\S]*?onload\s*=\s*["\"][^"\"]*["\"]', # body onload XSS
    r'(?i)\{\{.*\}\}', # Template injection (Handlebars, etc.)
    r'(?i)<%=?\s*.*%>', # Template injection (EJS, etc.)
    r'(?i)\$\{.*\}', # Template injection (ES6, etc.)
    r'(?i)\bon[a-z]+\s*=\s*["\"][^"\"]*["\"]', # Any on* event handler
    r'(?i)javascript:', # javascript: URI
    r'(?i)data:text/html', # data: URI
    r'(?i)vbscript:', # vbscript: URI
    r'(?i)expression\s*\(', # CSS expression()
    r'(?i)document\.location', # document.location
    r'(?i)location\.hash', # location.hash
    r'(?i)window\.name', # window.name
    r'(?i)window\.open\s*\(', # window.open()
    r'(?i)window\.parent', # window.parent
    r'(?i)window\.top', # window.top
    r'(?i)window\.frames', # window.frames
    r'(?i)window\.self', # window.self
    r'(?i)window\.opener', # window.opener
    r'(?i)window\.frameElement', # window.frameElement
    r'(?i)window\.content', # window.content
    r'(?i)window\.external', # window.external
    r'(?i)<iframe[^>]+srcdoc=', # iframe srcdoc attribute
    r'(?i)src\s*=\s*["\']data:text/html', # src=data:text/html
]
