# Patterns for Business Logic Flaws — static indicators of exploitable workflow weaknesses
business_logic_flaw_patterns = [
    # IDOR: user-controlled ID passed directly to DB lookup without intermediate mapping
    r'(?i)\.find(?:One|ById)?\s*\(\s*\{?[^)]*req\.(params|query|body)\.(?:id|user_?id|account_?id|order_?id|uuid)\b',
    r'(?i)(?:findById|findOne|getById)\s*\(\s*req\.(params|query|body)\.(?:id|user_?id|account_?id|order_?id|uuid)\b',

    # Mass assignment: raw request body passed to ORM create/update
    r'(?i)Object\.assign\s*\(\s*\w+\s*,\s*req\.body\s*\)',
    r'(?i)\.(?:create|update|save|insert)\s*\(\s*req\.body\s*\)',
    r'(?i)\.(?:create|update|save|insert)\s*\(\s*\{[^}]*\.\.\.\s*req\.body',
    r'(?i)new\s+\w+Model?\s*\(\s*req\.body\s*\)',

    # Client-side privilege/role checks (trivially bypassable in browser)
    r'(?i)(?:localStorage|sessionStorage)\.getItem\s*\(\s*["\'](?:isAdmin|admin|role|is_admin|userRole|user_role|privilege)["\']',
    r'(?i)cookie(?:s)?\.get\s*\(\s*["\'](?:admin|role|isAdmin|is_admin|privilege|access_level)["\']',
    r'(?i)document\.cookie\.(?:split|match|indexOf)\s*\([^)]*(?:admin|role|isAdmin)',

    # Auth bypass flags — deliberate back-doors or insecure debug flags
    r'(?i)\b(?:bypassAuth|skipAuth|disableAuth|bypass_auth|skip_auth|disable_auth|noAuthCheck)\b',
    r'(?i)req\.headers\s*\[\s*["\']x-(?:admin|bypass|privileged|override|sudo|internal)["\']',
    r'(?i)if\s*\([^)]*["\']x-(?:admin|bypass|internal)["\'][^)]*\)',

    # Insecure price/quantity — numeric value taken from client without server-side re-calculation
    r'(?i)(?:price|amount|total|cost)\s*=\s*(?:parseFloat|parseInt|Number)\s*\(\s*req\.(body|query|params)\.',
    r'(?i)(?:price|amount|total|cost)\s*=\s*req\.(body|query|params)\.',

    # Negative price/discount bypass
    r'(?i)(?:price|quantity|amount)\s*=\s*-\s*\d',

    # Hardcoded boolean privilege escalation in code
    r'(?i)\bisAdmin\s*=\s*true\b(?!\s*;?\s*//\s*test)',
    r'(?i)\bisTrusted\s*=\s*true\b(?!\s*;?\s*//\s*test)',

    # Broken access control: sensitive route handler without auth middleware in the same line
    r'(?i)app\.(delete|put|patch)\s*\(\s*["\'][^"\']+["\']\s*,\s*(?:async\s*)?\(?(?:req|request)\b',

    # Account enumeration: different error strings for valid vs invalid accounts
    r'(?i)["\'](?:invalid password|wrong password|incorrect password|password is wrong)["\']',
    r'(?i)["\'](?:user not found|account not found|email not found|no such user)["\']',
]
