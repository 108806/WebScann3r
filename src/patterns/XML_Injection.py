# Patterns for XML Injection (expanded and well-commented)
xml_injection_patterns = [
    r'(?i)<\?xml.*\?>',
    r'(?i)<!DOCTYPE.*>',
    r'(?i)\bxml_parse\b',
    r'(?i)\bxml_load\b',
    r'(?i)\bxmlreader\b',
    r'(?i)\bxml2js\b',
]
