# Framework Detection Patterns
# Detect common web frameworks to reduce false positives

import re

framework_patterns = {
    'jquery': [
        r'jQuery',
        r'\$\s*\(',
        r'\.ajax\(',
        r'\.get\(',
        r'\.post\(',
        r'jQuery\.fn',
    ],
    
    'angular': [
        r'angular\.module',
        r'ng-',
        r'$scope',
        r'$http',
        r'angular\.js',
    ],
    
    'react': [
        r'React\.',
        r'ReactDOM',
        r'jsx',
        r'useState',
        r'useEffect',
    ],
    
    'vue': [
        r'Vue\.',
        r'v-if',
        r'v-for',
        r'v-model',
        r'@click',
    ],
    
    'intraweb': [
        r'IW\.',
        r'IWBase',
        r'IWGecko',
        r'IWLib',
        r'iwnotify',
        r'IntraWeb',
    ],
    
    'bootstrap': [
        r'bootstrap',
        r'btn-',
        r'col-',
        r'row',
        r'container',
    ],
    
    'express': [
        r'express',
        r'app\.get',
        r'app\.post',
        r'req\.',
        r'res\.',
    ],
    
    'laravel': [
        r'Laravel',
        r'Illuminate\\',
        r'@extends',
        r'@section',
        r'Route::',
    ],
    
    'django': [
        r'django',
        r'from django',
        r'{% ',
        r'{{ ',
        r'urls\.py',
    ],
    
    'rails': [
        r'Rails',
        r'ActionController',
        r'<%= ',
        r'<% ',
        r'rails',
    ]
}

# Known safe function patterns for each framework
framework_safe_patterns = {
    'jquery': [
        r'IW\.\$\(',  # IntraWeb's jQuery-like selector
        r'\$\("[^"]+"\)',  # jQuery selectors
        r'\$\(\'[^\']+\'\)',  # jQuery selectors
        r'\$\(document\)',  # jQuery document ready
        r'\$\(this\)',  # jQuery this reference
    ],
    
    'intraweb': [
        r'IW\.\$\(',  # IntraWeb selectors
        r'executeAjaxEvent',  # IntraWeb AJAX
        r'IWTop\(\)',  # IntraWeb functions
        r'iwnotify\.',  # IntraWeb notifications
    ],
    
    'dom_api': [
        r'document\.open\(',  # DOM API
        r'window\.open\(',  # DOM API
        r'\.hasChildNodes\(',  # DOM API
        r'\.appendChild\(',  # DOM API
        r'\.removeChild\(',  # DOM API
    ],
    
    'css': [
        r'box-shadow',  # CSS properties
        r'text-shadow',  # CSS properties
        r'-webkit-',  # CSS prefixes
        r'-moz-',  # CSS prefixes
    ]
}

def detect_frameworks(content):
    """
    Detect which frameworks are used in the content.
    
    Args:
        content (str): File content to analyze
        
    Returns:
        list: List of detected frameworks
    """
    detected = []
    
    for framework, patterns in framework_patterns.items():
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                detected.append(framework)
                break  # One match per framework is enough
    
    return detected

def is_safe_pattern(content, match, detected_frameworks):
    """
    Check if a match is a known safe pattern for detected frameworks.
    
    Args:
        content (str): File content
        match (str): Matched string
        detected_frameworks (list): List of detected frameworks
        
    Returns:
        bool: True if this is a safe pattern
    """
    import re
    
    # Check framework-specific safe patterns
    for framework in detected_frameworks:
        if framework in framework_safe_patterns:
            for safe_pattern in framework_safe_patterns[framework]:
                if re.search(safe_pattern, match, re.IGNORECASE):
                    return True
    
    # Check DOM API patterns
    for safe_pattern in framework_safe_patterns['dom_api']:
        if re.search(safe_pattern, match, re.IGNORECASE):
            return True
    
    # Check CSS patterns
    for safe_pattern in framework_safe_patterns['css']:
        if re.search(safe_pattern, match, re.IGNORECASE):
            return True
    
    return False

def get_context_around_match(content, match_start, match_end, context_lines=2):
    """
    Get context lines around a match for better analysis.
    
    Args:
        content (str): Full content
        match_start (int): Start position of match
        match_end (int): End position of match
        context_lines (int): Number of context lines to include
        
    Returns:
        dict: Context information
    """
    lines = content.splitlines()
    match_line_num = content[:match_start].count('\n')
    
    start_line = max(0, match_line_num - context_lines)
    end_line = min(len(lines), match_line_num + context_lines + 1)
    
    context = {
        'before': lines[start_line:match_line_num],
        'match_line': lines[match_line_num] if match_line_num < len(lines) else '',
        'after': lines[match_line_num + 1:end_line],
        'line_number': match_line_num + 1
    }
    
    return context
