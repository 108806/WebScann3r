"""
Dangerous sink patterns for WebScann3r

Patterns here identify where user-controlled data could cause security issues.
Used to generate sinks.md (fuzzing target list) — NOT the security_report.md findings.

Rules to prevent noise floods:
- exec/eval: require negative lookbehind (?<!\\.) to exclude .exec()/.eval() method calls
- Function: case-sensitive capital-F only (the JS constructor), not the 'function' keyword
- render: only specific template engine render calls, not React render()
- open: require it is not a method call (e.g. xhr.open is excluded)
- No duplicate entries — each sink appears exactly once
"""

sink_patterns = [
    # ── Code execution ────────────────────────────────────────────────────────
    r'(?i)(?<!\.)\beval\s*\(',           # eval() but not .eval() (JS method)
    r'(?i)(?<!\.)\bexec\s*\(',           # exec() but not .exec() (RegExp.exec)
    r'(?i)system\s*\(',
    r'(?i)(?<!\.)\bpopen\s*\(',
    r'(?i)passthru\s*\(',
    r'(?i)proc_open\s*\(',
    r'(?i)shell_exec\s*\(',
    r'(?i)create_function\s*\(',         # deprecated PHP eval wrapper
    r'(?i)assert\s*\(',
    r'(?i)base64_decode\s*\(',
    r'(?i)execfile\s*\(',
    r'(?i)compile\s*\(',
    r'(?i)exec_module\b',

    # ── JS Function constructor (capital-F only — avoids 'function' keyword) ─
    r'Function\s*\(',                    # case-sensitive: Function( not function(
    r'new\s+Function\b',
    r'window\.Function\b',
    r'window\.eval\b',

    # ── JS timers (can execute strings as code) ──────────────────────────────
    r'(?i)setTimeout\s*\(',
    r'(?i)setInterval\s*\(',

    # ── DOM sinks (HTML injection, XSS) ──────────────────────────────────────
    r'(?i)document\.write\s*\(',
    r'(?i)document\.writeln\s*\(',
    r'(?i)innerHTML\s*=\s*',
    r'(?i)outerHTML\s*=\s*',
    r'(?i)insertAdjacentHTML\s*\(',
    r'(?i)dangerouslySetInnerHTML',
    r'(?i)document\.execCommand\s*\(',
    r'(?i)\.srcdoc\s*=',
    r'(?i)\.setAttribute\s*\(\s*["\'](?:src|href|action|onclick|on\w+)["\']',

    # ── Redirect sinks (open redirect) ────────────────────────────────────────
    r'(?i)document\.location\b',
    r'(?i)window\.location\b',
    r'(?i)location\.href\s*=',
    r'(?i)location\.replace\s*\(',
    r'(?i)location\.assign\s*\(',
    r'(?i)window\.navigate\s*\(',

    # ── Browser storage ───────────────────────────────────────────────────────
    r'(?i)localStorage\.setItem\s*\(',
    r'(?i)sessionStorage\.setItem\s*\(',
    r'(?i)document\.cookie\s*=',
    r'(?i)window\.postMessage\s*\(',
    r'(?i)window\.open\s*\(',

    # ── File operations (server-side) ─────────────────────────────────────────
    r'(?i)(?<!\.)\bopen\s*\(',           # Python/Ruby open() — exclude .open() method calls
    r'(?i)fopen\s*\(',
    r'(?i)file_get_contents\s*\(',
    r'(?i)file_put_contents\s*\(',
    r'(?i)readfile\s*\(',
    r'(?i)move_uploaded_file\s*\(',
    r'(?i)fs\.(readFile|writeFile|appendFile|createWriteStream|createReadStream|unlink|rmdir|chmod|chown|mkdir|readdir)\s*\(',

    # ── File upload sinks (Node.js / Python / PHP) ───────────────────────────
    r'(?i)multer\s*\(',
    r'(?i)formidable\s*\(',
    r'(?i)busboy\s*\(',
    r'(?i)multiparty\s*\(',
    r'(?i)request\.files\b',
    r'(?i)\$_FILES\b',
    r'(?i)\.save\s*\(\s*["\']?(?:upload|file)',   # ORM/framework save to upload path

    # ── HTTP request sinks (SSRF) ─────────────────────────────────────────────
    r'(?i)fetch\s*\(',
    r'(?i)axios\.(?:get|post|put|delete|patch|request)\s*\(',
    r'(?i)\.ajax\s*\(',
    r'(?i)XMLHttpRequest\b',
    r'(?i)http\.(?:get|request)\s*\(',
    r'(?i)https\.(?:get|request)\s*\(',
    r'(?i)requests\.(?:get|post|put|delete|patch)\s*\(',
    r'(?i)urllib\.request\b',
    r'(?i)curl_exec\s*\(',
    r'(?i)curl_setopt\s*\(',
    r'(?i)curl_init\s*\(',

    # ── Network / socket sinks ────────────────────────────────────────────────
    r'(?i)new\s+WebSocket\s*\(',
    r'(?i)io\.connect\s*\(',             # Socket.IO client
    r'(?i)net\.connect\s*\(',            # Node.js net module
    r'(?i)net\.createConnection\s*\(',
    r'(?i)\bsocket\s*\.\s*(?:connect|send|write)\s*\(',

    # ── SQL sinks ─────────────────────────────────────────────────────────────
    r'(?i)mysql_query\s*\(',
    r'(?i)mysqli_query\s*\(',
    r'(?i)pg_query\s*\(',
    r'(?i)sqlite_query\s*\(',
    r'(?i)db\.query\s*\(',
    r'(?i)cursor\.execute\s*\(',
    r'(?i)\.executeQuery\s*\(',
    r'(?i)\.executeUpdate\s*\(',
    r'(?i)sequelize\.query\s*\(',
    r'(?i)knex\.raw\s*\(',
    r'(?i)Model\.objects\.raw\s*\(',     # Django ORM raw
    r'(?i)xp_cmdshell\b',
    r'(?i)sp_executesql\b',

    # ── NoSQL sinks ───────────────────────────────────────────────────────────
    r'(?i)\$where\s*:',
    r'(?i)mapReduce\s*\(',
    r'(?i)collection\.find\s*\(',
    r'(?i)mongoose\.\w+\.find\s*\(',

    # ── Template rendering sinks (SSTI) ────────────────────────────────────────
    r'(?i)render_template\s*\(',         # Flask
    r'(?i)twig\.render\s*\(',
    r'(?i)ejs\.render\s*\(',
    r'(?i)mustache\.render\s*\(',
    r'(?i)Handlebars\.compile\s*\(',
    r'(?i)pug\.render\s*\(',
    r'(?i)jade\.render\s*\(',
    r'(?i)nunjucks\.render\s*\(',
    r'(?i)env\.from_string\s*\(',        # Jinja2 from_string (dangerous)
    r'(?i)Template\s*\(\s*[^)]*\+',     # Template with string concat
    r'(?i)vm\.runInNewContext\s*\(',     # Node.js vm module

    # ── Deserialization sinks ─────────────────────────────────────────────────
    r'(?i)unserialize\s*\(',
    r'(?i)pickle\.loads?\s*\(',
    r'(?i)yaml\.load\s*\(',             # safe is yaml.safe_load
    r'(?i)marshal\.loads?\s*\(',
    r'(?i)unmarshal\s*\(',
    r'(?i)ObjectInputStream\.readObject\b',
    r'(?i)JSON\.parse\s*\(',            # safe but worth noting for prototype pollution

    # ── Dynamic import / code loading ─────────────────────────────────────────
    r'(?i)importlib\.import_module\s*\(',
    r'(?i)require\s*\(',               # CommonJS dynamic require
    r'(?i)__import__\s*\(',
    r'(?i)import\s*\(\s*[^"\')\n]',   # Dynamic import() with variable

    # ── Process / OS (server-side command execution) ──────────────────────────
    r'(?i)os\.system\s*\(',
    r'(?i)os\.popen\s*\(',
    r'(?i)os\.exec[lv][ep]?\s*\(',
    r'(?i)os\.startfile\s*\(',
    r'(?i)subprocess\.(?:Popen|call|run|check_call|check_output|getoutput)\s*\(',
    r'(?i)child_process\.(?:exec|execSync|spawn|spawnSync|fork|execFile)\s*\(',
    r'(?i)process\.binding\s*\(',       # Node.js internal binding (dangerous)

    # ── Java execution sinks ──────────────────────────────────────────────────
    r'(?i)Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(',
    r'(?i)ProcessBuilder\s*\(',
    r'(?i)Process\.Start\s*\(',
    r'(?i)Assembly\.Load\s*\(',
    r'(?i)AppDomain\.CreateDomain\s*\(',
    r'(?i)Type\.GetType\s*\(',
    r'(?i)ScriptEngineManager\s*\(',

    # ── LDAP sinks ────────────────────────────────────────────────────────────
    r'(?i)ldap_search\s*\(',
    r'(?i)ldap_bind\s*\(',
    r'(?i)ldap\.search\s*\(',
    r'(?i)DirContext\.search\s*\(',

    # ── Path traversal sinks ──────────────────────────────────────────────────
    r'(?i)parse_str\s*\(',
    r'(?i)preg_replace\s*\(',
    r'(?i)php://\w',
    r'(?i)file:///',

    # ── JWT / crypto misuse ───────────────────────────────────────────────────
    r'(?i)jwt\.sign\s*\(',
    r'(?i)jwt\.verify\s*\(',
    r'(?i)jsonwebtoken\.sign\s*\(',
    r'(?i)crypto\.createCipher\s*\(',   # deprecated — no auth
    r'(?i)crypto\.createDecipher\s*\(',
    r'(?i)Math\.random\s*\(',           # PRNG for security context
]
