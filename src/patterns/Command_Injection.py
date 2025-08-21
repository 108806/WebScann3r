# Patterns for Command Injection (expanded and well-commented)
command_injection_patterns = [
    r'(?i)(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)', # PHP functions with user input
    r'(?i)(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\(\s*.*\+', # PHP functions with concat
    r'(?i)spawn\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)', # spawn with user input
    r'(?i)child_process\.exec\s*\(\s*.*\+', # Node.js exec with concat
    r'(?i)Runtime\.getRuntime\(\)\.exec\(.*\+', # Java exec with concat
    r'(?i)ProcessBuilder\(.*\+', # Java ProcessBuilder with concat
    r'(?i)os\.system\(.*\+', # Python os.system with concat
    r'(?i)subprocess\.(?:call|Popen|run)\(.*\+', # Python subprocess with concat
    r'(?i)os\.system\s*\(\s*.*\)', # Python os.system any input
    r'(?i)subprocess\.(?:call|Popen|run)\s*\(\s*.*\)', # Python subprocess any input
    r'(?i)commands\.getoutput\s*\(\s*.*\)', # Python getoutput any input
    r'(?i)child_process\.(?:exec|spawn|execFile)\s*\(\s*.*\)', # Node.js exec/spawn/execFile
    r'(?i)Runtime\.getRuntime\(\)\.exec\s*\(\s*.*\)', # Java exec any input
    r'(?i)ProcessBuilder\s*\(\s*.*\)', # Java ProcessBuilder any input
    r'(?i)\`[^\`]+\`', # Shell backticks
    r'(?i)%x\{[^}]+\}', # Ruby %x{} shell
    r'(?i)IO\.popen\s*\(\s*.*\)', # Ruby IO.popen
    # r'(?i)popen\s*\(\s*.*\)', # popen any input (commented: too broad, not always dangerous)
    # r'(?i)system\s*\(\s*.*\)', # system() any input (commented: too broad, not always dangerous)
    # r'(?i)passthru\s*\(\s*.*\)', # passthru() any input (commented: too broad, not always dangerous)
    # r'(?i)shell_exec\s*\(\s*.*\)', # shell_exec() any input (commented: too broad, not always dangerous)
    # r'(?i)open\s*\(\s*.*\)', # open() any input (commented: too broad, not always dangerous)
    # Removed overly broad patterns that cause false positives:
    # r'(?i)\$\(.*\)', # Shell $() - too broad, catches JavaScript selectors
    # r'(?i)\$\w+', # Shell vars - too broad, catches JS variables
    # r'(?i)\bcat\b|\bgrep\b|\bwget\b|\bcurl\b|\bftp\b|\bscp\b|\bssh\b|\bpython\b|\bperl\b|\bphp\b|\bnode\b|\bjava\b|\bawk\b|\bsed\b|\bnetcat\b|\bnc\b', # Commented: too broad, causes false positives on common words like 'node', 'php', etc.
    r'(?i)sh\s+-c\s+.*', # sh -c command string
    r'(?i)bash\s+-c\s+.*', # bash -c command string
    r'(?i)cmd\.exe\s+/c\s+.*', # Windows cmd.exe /c command string
    
    # More precise patterns to reduce false positives
    r'(?i)\beval\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)', # eval with user input
    r'(?i)\bassert\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)', # PHP assert with user input
    r'(?i)(?:exec|system|shell_exec)\s*\(\s*["\'].*\$_(?:GET|POST|REQUEST)', # Commands with user input
    r'(?i)(?:exec|system|shell_exec)\s*\(\s*.*\.\s*\$_(?:GET|POST|REQUEST)', # Command concatenation
]
