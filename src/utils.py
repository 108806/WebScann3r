#!/usr/bin/env python3

import os
import re
import logging
from urllib.parse import urlparse

logger = logging.getLogger('WebScann3r.Utils')

def normalize_url(url):
    """
    Normalize a URL by removing fragments and ensuring it has a scheme
    
    Args:
        url (str): URL to normalize
        
    Returns:
        str: Normalized URL
    """
    if not url:
        return None
    
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Parse URL
    parsed = urlparse(url)
    
    # Reconstruct URL without fragment
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    # Add query if present
    if parsed.query:
        normalized += f"?{parsed.query}"
    
    return normalized

def is_same_domain(url1, url2):
    """
    Check if two URLs have the same domain
    
    Args:
        url1 (str): First URL
        url2 (str): Second URL
        
    Returns:
        bool: Whether the URLs have the same domain
    """
    domain1 = urlparse(url1).netloc
    domain2 = urlparse(url2).netloc
    
    return domain1 == domain2

def get_file_extension(url):
    """
    Get the file extension from a URL
    
    Args:
        url (str): URL to get extension from
        
    Returns:
        str: File extension (including the dot) or empty string
    """
    path = urlparse(url).path
    return os.path.splitext(path)[1].lower()

def get_content_type(headers):
    """
    Get content type from response headers
    
    Args:
        headers (dict): Response headers
        
    Returns:
        str: Content type or None
    """
    return headers.get('Content-Type', '').lower().split(';')[0]

def is_binary_content(content_type):
    """
    Check if content type is binary
    
    Args:
        content_type (str): Content type
        
    Returns:
        bool: Whether the content is binary
    """
    binary_types = [
        'application/octet-stream',
        'application/pdf',
        'application/zip',
        'application/x-rar-compressed',
        'application/x-tar',
        'application/x-7z-compressed',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument',
        'application/msword',
        'application/vnd.ms-powerpoint',
        'image/',
        'audio/',
        'video/',
    ]
    
    return any(binary_type in content_type for binary_type in binary_types)

def find_security_issue(content, pattern):
    """
    Find security issues in content based on a pattern
    
    Args:
        content (str): Content to search
        pattern (str): Regex pattern
        
    Returns:
        list: List of matches with line numbers
    """
    matches = []
    
    for match in re.finditer(pattern, content):
        line_number = content[:match.start()].count('\n') + 1
        line = content.splitlines()[line_number - 1].strip()
        matches.append({
            'line': line_number,
            'code': line,
            'match': match.group(0),
        })
    
    return matches

def truncate_string(string, max_length=100):
    """
    Truncate a string to a specified length
    
    Args:
        string (str): String to truncate
        max_length (int): Maximum length
        
    Returns:
        str: Truncated string
    """
    if len(string) <= max_length:
        return string
    
    return string[:max_length-3] + '...'
