# Pattern Confidence Scoring
# High confidence patterns are very likely to be real vulnerabilities
# Medium confidence patterns may need manual review
# Low confidence patterns are prone to false positives

# Confidence levels: HIGH, MEDIUM, LOW
pattern_confidence = {
    # Command Injection
    'Command Injection': {
        'HIGH': [
            r'(?i)(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
            r'(?i)child_process\.exec\s*\(\s*.*\+',
            r'(?i)Runtime\.getRuntime\(\)\.exec\(.*\+',
            r'(?i)os\.system\(.*\+',
            r'(?i)subprocess\.(?:call|Popen|run)\(.*\+',
        ],
        'MEDIUM': [
            r'(?i)eval\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
            r'(?i)assert\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
            r'(?i)sh\s+-c\s+.*',
            r'(?i)bash\s+-c\s+.*',
        ],
        'LOW': [
            r'(?i)os\.system\s*\(\s*.*\)',
            r'(?i)subprocess\.(?:call|Popen|run)\s*\(\s*.*\)',
        ]
    },
    
    # XSS
    'XSS': {
        'HIGH': [
            r'(?i)document\.write\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
            r'(?i)\.innerHTML\s*=\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
            r'(?i)eval\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
        ],
        'MEDIUM': [
            r'(?i){{.*}}',  # Template injection patterns
            r'(?i)location\.hash',
            r'(?i)document\.URL',
        ],
        'LOW': [
            r'(?i)window\.open\(\)',
            r'(?i)javascript:',
        ]
    },
    
    # File Inclusion
    'File Inclusion': {
        'HIGH': [
            r'(?i)(?:include|require|include_once|require_once)\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
            r'(?i)file_get_contents\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
            r'(?i)(?:include|require).*\.\./',
        ],
        'MEDIUM': [
            r'(?i)fopen\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
            r'(?i)readfile\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
            r'(?i)file_get_contents\s*\(\s*["\']?https?://',
        ],
        'LOW': [
            r'(?i)fs\.readFile\(.*\+',
            r'(?i)java\.io\.File\(.*\+',
        ]
    },
    
    # Information Disclosure
    'Information Disclosure': {
        'HIGH': [
            r'(?i)\.env',
            r'(?i)\.git',
            r'(?i)id_rsa',
            r'(?i)\.pem$',
            r'(?i)\.key$',
            r'(?i)phpinfo\s*\(',
        ],
        'MEDIUM': [
            r'(?i)console\.log\s*\(',
            r'(?i)var_dump\s*\(',
            r'(?i)print_r\s*\(',
            r'(?i)/etc/shadow',
        ],
        'LOW': [
            r'(?i)alert\s*\(',
            r'(?i)print\s*\(',
            r'(?i)\.bak$',
        ]
    },
    
    # Insecure Crypto
    'Insecure Crypto': {
        'HIGH': [
            r'(?i)md5\s*\(',
            r'(?i)sha1\s*\(',
            r'(?i)\bdes\s*\(',
            r'(?i)\brc4\s*\(',
        ],
        'MEDIUM': [
            r'(?i)ECB',
            r'(?i)no\s*salt',
            r'(?i)base64\.(?:encode|decode)\(',
        ],
        'LOW': [
            r'(?i)CBC',
            r'(?i)random\.seed\(',
        ]
    },
    
    # SQL Injection  
    'SQL Injection': {
        'HIGH': [
            r'(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\s+.*\$_(?:GET|POST|REQUEST|COOKIE)',
            r'(?i)(?:mysql_query|mysqli_query|pg_query)\s*\(\s*.*\$_(?:GET|POST|REQUEST)',
        ],
        'MEDIUM': [
            r'(?i)(?:SELECT|INSERT|UPDATE|DELETE).*\+.*\$',
            r'(?i)query\s*\(\s*.*\$_(?:GET|POST|REQUEST)',
        ],
        'LOW': [
            r'(?i)(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|ORDER\s+BY)',
        ]
    }
}

def get_pattern_confidence(vulnerability_type, pattern):
    """
    Get confidence level for a specific pattern.
    
    Args:
        vulnerability_type (str): Type of vulnerability
        pattern (str): Pattern to check
        
    Returns:
        str: Confidence level (HIGH, MEDIUM, LOW, UNKNOWN)
    """
    if vulnerability_type not in pattern_confidence:
        return 'UNKNOWN'
    
    vuln_patterns = pattern_confidence[vulnerability_type]
    
    for confidence_level in ['HIGH', 'MEDIUM', 'LOW']:
        if pattern in vuln_patterns.get(confidence_level, []):
            return confidence_level
    
    return 'UNKNOWN'

def filter_by_confidence(findings, min_confidence='MEDIUM'):
    """
    Filter findings by minimum confidence level.
    
    Args:
        findings (dict): Security findings
        min_confidence (str): Minimum confidence level (HIGH, MEDIUM, LOW)
        
    Returns:
        dict: Filtered findings
    """
    confidence_order = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
    min_score = confidence_order.get(min_confidence, 2)
    
    filtered_findings = {}
    
    for file_path, file_findings in findings.items():
        filtered_file_findings = {}
        
        for vuln_type, matches in file_findings.items():
            filtered_matches = []
            
            for match in matches:
                # Determine confidence based on pattern (this would need pattern info)
                confidence = 'MEDIUM'  # Default confidence
                confidence_score = confidence_order.get(confidence, 0)
                
                if confidence_score >= min_score:
                    match['confidence'] = confidence
                    filtered_matches.append(match)
            
            if filtered_matches:
                filtered_file_findings[vuln_type] = filtered_matches
        
        if filtered_file_findings:
            filtered_findings[file_path] = filtered_file_findings
    
    return filtered_findings
