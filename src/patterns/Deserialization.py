# Patterns for Deserialization (expanded and well-commented)
deserialization_patterns = [
    # TLDR: Detects PHP unserialize() with user input (dangerous deserialization)
    r'(?i)unserialize\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    # TLDR: Detects Java ObjectInputStream with user input
    r'(?i)ObjectInputStream\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    # TLDR: Detects Python/Ruby YAML load with user input
    r'(?i)yaml\.load\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    # TLDR: Detects PHP json_decode() with user input
    r'(?i)json_decode\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    # TLDR: Detects Ruby Marshal.load() with user input
    r'(?i)Marshal\.load\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    # TLDR: Detects Python pickle.loads() with user input
    r'(?i)pickle\.loads?\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
    # TLDR: Detects Python pickle.load() (general usage)
    r'(?i)pickle\.load\(\s*.*\)',
    # TLDR: Detects Python pickle.loads() (general usage)
    r'(?i)pickle\.loads\(\s*.*\)',
    # TLDR: Detects Python jsonpickle.decode() (general usage)
    r'(?i)jsonpickle\.decode\(\s*.*\)',
    # TLDR: Detects Python jsonpickle.encode() (general usage)
    r'(?i)jsonpickle\.encode\(\s*.*\)',
    # TLDR: Detects PHP php_unserialize() (general usage)
    r'(?i)php_unserialize\(\s*.*\)',
    # TLDR: Detects PHP php_serialize() (general usage)
    r'(?i)php_serialize\(\s*.*\)',
    # TLDR: Detects Ruby Marshal.dump() (general usage)
    r'(?i)Marshal\.dump\(\s*.*\)',
    # TLDR: Detects Ruby Marshal.restore() (general usage)
    r'(?i)Marshal\.restore\(\s*.*\)',
    # TLDR: Detects Ruby YAML.load() (general usage)
    r'(?i)YAML\.load\(\s*.*\)',
    # TLDR: Detects Ruby YAML.load_stream() (general usage)
    r'(?i)YAML\.load_stream\(\s*.*\)',
    # TLDR: Detects Ruby YAML.parse() (general usage)
    r'(?i)YAML\.parse\(\s*.*\)',
    # TLDR: Detects Ruby YAML.parse_stream() (general usage)
    r'(?i)YAML\.parse_stream\(\s*.*\)',
    # TLDR: Detects Java ObjectInputStream (general usage)
    r'(?i)ObjectInputStream\s*\(\s*.*\)',
    # TLDR: Detects Java ObjectOutputStream (general usage)
    r'(?i)ObjectOutputStream\s*\(\s*.*\)',
    # TLDR: Detects Java XMLDecoder (general usage)
    r'(?i)XMLDecoder\s*\(\s*.*\)',
    # TLDR: Detects Java XMLEncoder (general usage)
    r'(?i)XMLEncoder\s*\(\s*.*\)',
    # TLDR: Detects C# BinaryFormatter.Deserialize (general usage)
    r'(?i)BinaryFormatter\.Deserialize\(\s*.*\)',
    # TLDR: Detects C# BinaryFormatter.Serialize (general usage)
    r'(?i)BinaryFormatter\.Serialize\(\s*.*\)',
]
