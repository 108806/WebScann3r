# Patterns for Use of Dangerous Functions
# Strategy: flag functions that are inherently dangerous regardless of input,
# or that indicate code/command execution and unsafe deserialization.
# Removed: setTimeout, setInterval, input(), require(), include(), fopen(),
# fwrite(), copy(), file_get_contents(), send(), fork(), assert(), base64_decode(),
# system() standalone — these are legitimate in virtually all web applications.

use_of_dangerous_functions_patterns = [
    # Python/JS: code execution (negative lookbehind excludes .eval() .exec() method calls)
    r'(?i)(?<!\.)\beval\s*\(',
    r'(?i)(?<!\.)\bexec\s*\(',
    r'(?i)\bexecfile\s*\(',
    r'(?i)\bos\.system\s*\(',
    r'(?i)\bos\.popen\s*\(',
    r'(?i)\bos\.popen[234]\s*\(',
    r'(?i)\bos\.execl[ep]?\s*\(',
    r'(?i)\bos\.execv[ep]?\s*\(',
    r'(?i)\bos\.startfile\s*\(',

    # Python: subprocess — command execution
    r'(?i)\bsubprocess\.Popen\s*\(',
    r'(?i)\bsubprocess\.call\s*\(',
    r'(?i)\bsubprocess\.run\s*\(',
    r'(?i)\bsubprocess\.check_output\s*\(',
    r'(?i)\bsubprocess\.getoutput\s*\(',
    r'(?i)\bsubprocess\.getstatusoutput\s*\(',

    # Python: unsafe deserialization
    r'(?i)\bpickle\.loads?\s*\(',
    r'(?i)\bcPickle\.loads?\s*\(',
    r'(?i)\bmarshal\.loads?\s*\(',
    r'(?i)\byaml\.load\s*\(',           # safe alternative is yaml.safe_load

    # PHP: code/command execution
    r'(?i)\bshell_exec\s*\(',
    r'(?i)\bpassthru\s*\(',
    r'(?i)\bproc_open\s*\(',
    r'(?i)\bcreate_function\s*\(',       # deprecated PHP eval wrapper
    r'(?i)\bunserialize\s*\(',           # PHP unsafe deserialization
    r'(?i)preg_replace\s*\([^,]+/e',    # eval flag in preg_replace

    # Node.js: child process execution
    r'(?i)\bchild_process\.exec\s*\(',
    r'(?i)\bchild_process\.execSync\s*\(',
    r'(?i)\bchild_process\.spawn\s*\(',
    r'(?i)\bchild_process\.spawnSync\s*\(',
    r'(?i)\bchild_process\.fork\s*\(',
    r'(?i)require\s*\(\s*["\']child_process["\']\s*\)',

    # React: dangerous HTML injection
    r'(?i)dangerouslySetInnerHTML',
    r'(?i)dangerouslyAllowAny(?:Origin|Method|Header)',

    # Java: code/command execution
    r'(?i)Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(',
    r'(?i)\bObjectInputStream\s*\(\s*.*\)\s*\.readObject\s*\(',
    r'(?i)\bScriptEngineManager\s*\(',
    r'(?i)javax\.script\.ScriptEngine\b',

    # Ruby: code/command execution and eval (eval already covered above, skip duplicate)
    r'(?i)(?<!\.)\binstance_eval\s*\(',
    r'(?i)\bclass_eval\s*\(',
    r'(?i)\bmodule_eval\s*\(',
    r'(?i)\bKernel\.eval\s*\(',
    r'(?i)\bKernel\.system\s*\(',
    r'(?i)\bKernel\.open\s*\(',
    r'(?i)\bIO\.popen\s*\(',
]
