# Patterns for Prototype Pollution
# Strategy: only flag direct __proto__ manipulation and known-dangerous merge
# functions receiving user-controlled data. Removed all bare JS built-in names
# (JSON, Math, Promise, constructor, prototype as standalone words) because
# they appear in virtually every JS file and produce zero actionable signal.

prototype_pollution_patterns = [
    # Direct __proto__ manipulation — high signal
    # Exclude: in {} (feature detection), == / === / !== (guard comparisons like "__proto__" === key ? void 0)
    r'(?i)["\']__proto__["\'](?!\s*(?:in\b|!?={2,3}))',
    r'(?i)\b__proto__\s*=(?!\s*\w+\.prototype)',  # assignment but not proto = Something.prototype (polyfill)
    r'(?i)\[(?:"|\')?__proto__(?:"|\')?\]\s*=',

    # setPrototypeOf — genuine risk when receiving user input
    r'(?i)Object\.setPrototypeOf\s*\(',
    r'(?i)Reflect\.setPrototypeOf\s*\(',

    # defineProperty on Object.prototype specifically — any other .prototype is normal OOP
    r'(?i)Object\.definePropert(?:y|ies)\s*\(\s*Object\.prototype',
    r'(?i)Reflect\.definePropert(?:y|ies)\s*\(\s*Object\.prototype',

    # URL/query parameter __proto__ injection — both direct and bracket notation
    r'(?i)[?&]__proto__(?:\[|%5b|\s*=)',
    r'(?i)[?&]constructor(?:\[|%5b)prototype',

    # Deep merge/extend with __proto__ explicitly present
    r'(?i)\bmerge\s*\(.*__proto__',
    r'(?i)\bdeepmerge\s*\(.*__proto__',
    r'(?i)\bextend\s*\(.*__proto__',
    r'(?i)\bassign\s*\(.*__proto__',

    # Known vulnerable lodash/jQuery patterns (specific enough)
    r'(?i)\b_\.merge\s*\(',
    r'(?i)\b_\.defaultsDeep\s*\(',
    r'(?i)\bjQuery\.extend\s*\(\s*true',  # deep extend is the risky variant
    r'(?i)\$\.extend\s*\(\s*true',

    # JSON parse result directly used to set prototype
    r'(?i)\{\s*["\']?__proto__["\']?\s*:',
    r'(?i)name=["\']?__proto__["\']?',

    # Encoded variants used in payloads
    r'(?i)%5f%5fproto%5f%5f',
    r'(?i)%255f%255fproto%255f%255f',
    r'(?i)\\u005f\\u005fproto\\u005f\\u005f',
]
