# Patterns for Server-Side Template Injection (SSTI)
# Strategy: flag confirmed SSTI indicators only.
# Removed: \btemplate\b (matches every HTML comment, every JS file, Dreamweaver annotations),
#           \$\{.*\} (every JS template literal), <%.*%> (normal ASP/JSP tags).
# Kept: library names, unambiguous SSTI test payload markers, and high-specificity syntax.

ssti_patterns = [
    # Server-side template library names — presence in output indicates template engine in use
    r'(?i)\bjinja2\b',
    r'(?i)\btwig\b',
    r'(?i)\bsmartty\b',
    r'(?i)\bfreemarker\b',
    r'(?i)\bvelocity\b',
    r'(?i)\bpebble\b',
    r'(?i)\bcheetah\b',

    # Unprocessed double-brace syntax in server response — could be Angular/Vue OR unprocessed Jinja2/Twig
    # Require {{...}} to contain something that looks like server-side logic (not just a var name)
    r'(?i)\{\{.*(?:config|request|self|__class__|__mro__|__subclasses__|g\.|session\.|namespace).*\}\}',

    # Spring Expression Language SSTI markers
    r'(?i)\$\{T\s*\(',               # ${T(java.lang.Runtime).getRuntime()}
    r'(?i)\#\{.*getRuntime\s*\(',    # #{T(Runtime).exec()}

    # Specific SSTI test payloads that indicate active exploitation attempt
    r'(?i)\{\{7\s*\*\s*7\}\}',       # Jinja2/Twig probe: {{7*7}}
    r'(?i)\$\{7\s*\*\s*7\}',         # EL probe: ${7*7}
    r'(?i)\#\{7\s*\*\s*7\}',         # Freemarker probe: #{7*7}
    r'(?i)<\?=\s*\d+\s*\*\s*\d+',   # PHP short tag probe: <?= 7*7

    # Jinja2-specific dangerous patterns (Python code execution)
    r'(?i)\{%.*import\s+os',
    r'(?i)\{%.*__import__',
    r'(?i)\{\{.*__class__.*__mro__',
    r'(?i)\{\{.*subprocess',
]
