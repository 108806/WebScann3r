# All patterns for XXE Vulnerabilities
patterns = [
    r'(?i)\.setFeature\("http://apache.org/xml/features/disallow-doctype-decl",\s*false\)',
    r'(?i)\.setFeature\("http://xml.org/sax/features/external-general-entities",\s*true\)',
    r'(?i)\.setFeature\("http://xml.org/sax/features/external-parameter-entities",\s*true\)',
    r'(?i)DocumentBuilderFactory\s*.*\.setExpandEntityReferences\(\s*true\s*\)',
    r'(?i)\.setFeature\(XMLConstants\.FEATURE_SECURE_PROCESSING,\s*false\)',
    r'(?i)libxml_disable_entity_loader\(\s*false\s*\)',
    # Expanded patterns for more XXE detection
    r'(?i)<!DOCTYPE\s+[^>]+\[.*<!ENTITY',
    r'(?i)xml\.parse\s*\(\s*.*\)',  # Python
    r'(?i)xml2js\.parseString\s*\(\s*.*\)',  # Node.js
    r'(?i)lxml\.etree\.parse\s*\(\s*.*\)',  # Python
    r'(?i)defusedxml\.ElementTree\.parse\s*\(\s*.*\)',  # Python
    r'(?i)SAXParserFactory\.newInstance\(\)',  # Java
    r'(?i)SAXParser\.parse\s*\(\s*.*\)',  # Java
    r'(?i)XMLInputFactory\.createXMLStreamReader\s*\(\s*.*\)',  # Java
    r'(?i)xml\.DocumentBuilderFactory',  # Java
    r'(?i)xml\.sax\.make_parser',  # Python
    r'(?i)xml\.dom\.minidom\.parse\s*\(\s*.*\)',  # Python
    r'(?i)xml\.etree\.ElementTree\.parse\s*\(\s*.*\)',  # Python
]
