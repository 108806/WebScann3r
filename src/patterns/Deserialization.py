# All patterns for Deserialization
patterns = [
    r'(?i)unserialize\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)ObjectInputStream\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)yaml\.load\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)json_decode\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)Marshal\.load\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)pickle\.loads?\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    # Expanded patterns for more Deserialization detection
    r'(?i)pickle\.load\(\s*.*\)',  # Python
    r'(?i)pickle\.loads\(\s*.*\)',  # Python
    r'(?i)jsonpickle\.decode\(\s*.*\)',  # Python
    r'(?i)jsonpickle\.encode\(\s*.*\)',  # Python
    r'(?i)php_unserialize\(\s*.*\)',  # PHP
    r'(?i)php_serialize\(\s*.*\)',  # PHP
    r'(?i)Marshal\.dump\(\s*.*\)',  # Ruby
    r'(?i)Marshal\.restore\(\s*.*\)',  # Ruby
    r'(?i)YAML\.load\(\s*.*\)',  # Ruby
    r'(?i)YAML\.load_stream\(\s*.*\)',  # Ruby
    r'(?i)YAML\.parse\(\s*.*\)',  # Ruby
    r'(?i)YAML\.parse_stream\(\s*.*\)',  # Ruby
    r'(?i)ObjectInputStream\s*\(\s*.*\)',  # Java
    r'(?i)ObjectOutputStream\s*\(\s*.*\)',  # Java
    r'(?i)XMLDecoder\s*\(\s*.*\)',  # Java
    r'(?i)XMLEncoder\s*\(\s*.*\)',  # Java
    r'(?i)BinaryFormatter\.Deserialize\(\s*.*\)',  # C#
    r'(?i)BinaryFormatter\.Serialize\(\s*.*\)',  # C#
]
