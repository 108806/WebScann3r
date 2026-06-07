# Patterns for XML Injection
# Strategy: flag XML parser APIs receiving input and injection-specific syntax.
# Removed: <?xml...?> and <!DOCTYPE...> — these match every XHTML/XML response
# header and every HTML5 doctype, producing 100% false positives with zero
# signal value since their presence in a response means nothing about injection.

xml_injection_patterns = [
    # XML parser functions — these process user-supplied XML
    r'(?i)\bxml_parse\s*\(',
    r'(?i)\bxml_load\s*\(',
    r'(?i)\bxmlreader\b',
    r'(?i)\bxml2js\s*\(',

    # XXE-style external entity references (actual injection payload markers)
    r'(?i)<!ENTITY\s+\w+\s+SYSTEM',
    r'(?i)<!ENTITY\s+\w+\s+PUBLIC',
    r'(?i)file:///etc/',
    r'(?i)file:///c:/',

    # CDATA pattern removed — JS XML-serialization libraries match it as a false positive
    # (e.g. code that wraps text in CDATA tags as protection, not as injection)

    # Java/Python XML parsers explicitly enabling external entities
    r'(?i)setFeature\s*\([^)]*external[^)]*',
    r'(?i)FEATURE_EXTERNAL_GENERAL_ENTITIES',
    r'(?i)FEATURE_EXTERNAL_PARAMETER_ENTITIES',
    r'(?i)XMLInputFactory\.IS_SUPPORTING_EXTERNAL_ENTITIES',
    r'(?i)DocumentBuilderFactory\.newInstance',
    r'(?i)SAXParserFactory\.newInstance',
    r'(?i)resolve_entities\s*=\s*True',
    r'(?i)lxml\.etree',
]
