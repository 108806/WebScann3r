# All patterns for Command Injection
patterns = [
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
    r'(?i)popen\s*\(\s*.*\)', # popen any input
    r'(?i)system\s*\(\s*.*\)', # system() any input
    r'(?i)passthru\s*\(\s*.*\)', # passthru() any input
    r'(?i)shell_exec\s*\(\s*.*\)', # shell_exec() any input
    r'(?i)open\s*\(\s*.*\)', # open() any input (generic)
    r'(?i)\|\s*\w+', # Pipe to command
    r'(?i);\s*\w+', # Semicolon then command
    r'(?i)&\s*\w+', # Ampersand then command
    r'(?i)\$\(.*\)', # Shell $() command substitution
    r'(?i)\$\w+', # Shell variable expansion
    r'(?i)\bcat\b|\bgrep\b|\bwget\b|\bcurl\b|\bftp\b|\bscp\b|\bssh\b|\bpython\b|\bperl\b|\bphp\b|\bnode\b|\bjava\b|\bawk\b|\bsed\b|\bnetcat\b|\bnc\b', # Common dangerous commands
    r'(?i)sh\s+-c\s+.*', # sh -c command string
    r'(?i)bash\s+-c\s+.*', # bash -c command string
    r'(?i)cmd\.exe\s+/c\s+.*', # Windows cmd.exe /c command string
]
