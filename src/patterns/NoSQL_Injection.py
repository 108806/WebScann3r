# Patterns for NoSQL Injection
# Strategy: focus on injection-specific signals, not generic MongoDB usage.
# Bare operators ($ne, $gt, $regex) in aggregation pipelines are normal — only flag them
# when they appear in the context of user-controlled input or dangerous constructs.
nosql_injection_patterns = [
    # $where always evaluates JavaScript server-side — inherently dangerous
    r'(?i)\$where\s*:\s*["\']?.*',
    r'(?i)\$where\s*:\s*function\s*\(',

    # MongoDB operator injection via bracket notation (classic bypass)
    r'(?i)\[\s*["\']?\$(?:ne|gt|lt|gte|lte|in|nin|regex|exists|where|or|and)\s*["\']?\s*\]',

    # Query built with user-controlled input flowing into find/aggregate
    r'(?i)\.find(?:One)?\s*\(\s*\{[^}]*req\.(params|query|body)',
    r'(?i)\.aggregate\s*\(\s*\[[^\]]*\$match[^\]]*req\.(params|query|body)',
    r'(?i)\.(?:updateOne|updateMany|deleteOne|deleteMany)\s*\(\s*\{[^}]*req\.(params|query|body)',

    # JSON.parse of user input used as a query filter (operator injection vector)
    r'(?i)(?:filter|query|conditions?)\s*=\s*JSON\.parse\s*\(\s*req\.(params|query|body)',

    # Direct filter property set from user input via bracket notation
    r'(?i)(?:filter|query)\s*\[\s*\w+\s*\]\s*=\s*req\.(params|query|body)',

    # PHP-style NoSQL injection via $_REQUEST
    r'(?i)db\..*\.find\(\s*\$_(?:GET|POST|REQUEST|COOKIE)',

    # Mongoose findByIdAndUpdate/findOneAndUpdate with body directly
    r'(?i)\.findByIdAndUpdate\s*\(\s*\w+\s*,\s*req\.body',
    r'(?i)\.findOneAndUpdate\s*\(\s*\{[^}]*req\.(params|query|body)',
]
