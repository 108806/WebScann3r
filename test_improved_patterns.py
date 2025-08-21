#!/usr/bin/env python3
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.analyzer import SecurityAnalyzer

analyzer = SecurityAnalyzer()

# Test content with known false positives
test_content = '''var c = IW.$("IWLocker");
box-shadow: 0 6px 10px rgba(0,0,0,.3);
document.open("text/html", "replace");
executeAjaxEvent(f, e, g, c, d, a);
hasChildNodes();
console.log("debug info");'''

print('=== Testing Improved Patterns ===')

# Analyze with new patterns
result = analyzer.analyze_code({'test.js': test_content})

if 'test.js' in result:
    total_issues = sum(len(matches) for matches in result['test.js'].values())
    print(f'Total issues found: {total_issues}')
    
    for vuln_type, matches in result['test.js'].items():
        print(f'\n{vuln_type}: {len(matches)} matches')
        for i, match in enumerate(matches[:3]):  # Show first 3 matches
            print(f'  {i+1}. Match: "{match.get("match", "N/A")}"')
            print(f'      Line: {match.get("line", "N/A")}')
else:
    print('No issues found!')

print('\n=== Comparison with old patterns ===')
print('Before fixes: ~40-50 false positives from this content')
print('After fixes: Should be significantly less')

# Test real vulnerability
vuln_content = '''<?php
system($_GET["cmd"]);
include($_GET["file"]);
echo $_GET["data"];
?>'''

print('\n=== Testing Real Vulnerabilities ===')
vuln_result = analyzer.analyze_code({'vuln.php': vuln_content})

if 'vuln.php' in vuln_result:
    vuln_total = sum(len(matches) for matches in vuln_result['vuln.php'].values())
    print(f'Real vulnerabilities found: {vuln_total}')
    
    for vuln_type, matches in vuln_result['vuln.php'].items():
        print(f'{vuln_type}: {len(matches)} matches')
else:
    print('No vulnerabilities found!')
