#!/usr/bin/env python3

import re
import logging
import json
from collections import defaultdict
from patterns.Insecure_Configuration import patterns as insecure_config_patterns
from patterns.CSRF_Vulnerabilities import patterns as csrf_vulnerabilities_patterns
from patterns.SQL_Injection import patterns as sql_injection_patterns
from patterns.XSS import patterns as xss_patterns
from patterns.Command_Injection import patterns as command_injection_patterns
from patterns.File_Inclusion import patterns as file_inclusion_patterns
from patterns.Insecure_Crypto import patterns as insecure_crypto_patterns
from patterns.Hardcoded_Credentials import patterns as hardcoded_credentials_patterns
from patterns.Information_Disclosure import patterns as information_disclosure_patterns
from patterns.SSRF_Vulnerabilities import patterns as ssrf_vulnerabilities_patterns
from patterns.XXE_Vulnerabilities import patterns as xxe_vulnerabilities_patterns
from patterns.Open_Redirect import patterns as open_redirect_patterns
from patterns.JWT_Issues import patterns as jwt_issues_patterns
from patterns.Deserialization import patterns as deserialization_patterns
from patterns.LDAP_Injection import patterns as ldap_injection_patterns
from patterns.NoSQL_Injection import patterns as NoSQL_injection_patterns
from patterns.Prototype_Pollution import patterns as prototype_pollution_patterns
from patterns.Insecure_Randomness import patterns as insecure_randomness_patterns
from patterns.Path_Traversal import patterns as path_traversal_patterns
from patterns.Unrestricted_File_Upload import patterns as unrestricted_upload_patterns
from patterns.Software_Library_Versions import patterns as software_library_versions_patterns
from patterns.Directory_Listing_Enabled import patterns as directory_listing_enabled_patterns
from patterns.Weak_JWT_Secret import patterns as weak_jwt_secret_patterns
from patterns.Server_Side_Template_Injection import patterns as ssti_patterns
from patterns.Unvalidated_Redirects import patterns as unvalidated_redirects_patterns
from patterns.Sensitive_Data_Exposure import patterns as sensitive_data_exposure_patterns
from patterns.CORS_Misconfiguration import patterns as cors_misconfiguration_patterns
from patterns.XML_Injection import patterns as xml_injection_patterns
from patterns.Insecure_Cookie_Flags import patterns as insecure_cookie_flags_patterns
from patterns.Use_of_Dangerous_Functions import patterns as use_of_dangerous_functions_patterns
from patterns.Insecure_HTTP_Headers import patterns as insecure_http_headers_patterns

logger = logging.getLogger('WebScann3r.Analyzer')

class SecurityAnalyzer:
    def __init__(self):
        """
        Initialize the security analyzer
        """
        self.security_patterns = {
            'SQL Injection': sql_injection_patterns,
            'XSS': xss_patterns,
            'Command Injection': command_injection_patterns,
            'File Inclusion': file_inclusion_patterns,
            'Insecure Crypto': insecure_crypto_patterns,
            'Hardcoded Credentials': hardcoded_credentials_patterns,
            'Information Disclosure': information_disclosure_patterns,
            'CSRF Vulnerabilities': csrf_vulnerabilities_patterns,
            'SSRF Vulnerabilities': ssrf_vulnerabilities_patterns,
            'XXE Vulnerabilities': xxe_vulnerabilities_patterns,
            'Open Redirect': open_redirect_patterns,
            'JWT Issues': jwt_issues_patterns,
            'Deserialization': deserialization_patterns,
            'LDAP Injection': ldap_injection_patterns,
            # Additional patterns and categories below:
            'NoSQL Injection': NoSQL_injection_patterns,
            'Prototype Pollution': prototype_pollution_patterns,
            'Insecure Randomness': insecure_randomness_patterns,
            'Path Traversal': path_traversal_patterns,
            'Weak JWT Secret': weak_jwt_secret_patterns,
            'Software/Library Versions': software_library_versions_patterns,
            'Directory Listing Enabled': directory_listing_enabled_patterns,
            'Server-Side Template Injection (SSTI)': ssti_patterns,
            'Insecure Configuration': insecure_config_patterns,
            'Unrestricted File Upload': unrestricted_upload_patterns,
            'Directory Listing Enabled': directory_listing_enabled_patterns,
            'Unvalidated Redirects': unvalidated_redirects_patterns,
            'Sensitive Data Exposure': sensitive_data_exposure_patterns,
            'CORS Misconfiguration': cors_misconfiguration_patterns,
            'Insecure HTTP Headers': insecure_http_headers_patterns,
            'XML Injection': xml_injection_patterns,
            'Insecure Cookie Flags': insecure_cookie_flags_patterns,
            'Use of Dangerous Functions': use_of_dangerous_functions_patterns,
        }
        
        # Mapping security issues to OWASP Top 10 Categories
        self.owasp_categories = {
            'SQL Injection': 'A03:2021-Injection',
            'XSS': 'A03:2021-Injection',
            'Command Injection': 'A03:2021-Injection',
            'File Inclusion': 'A01:2021-Broken Access Control',
            'SSRF Vulnerabilities': 'A10:2021-Server-Side Request Forgery (SSRF)',
            'XXE Vulnerabilities': 'A05:2021-Security Misconfiguration',
            'Open Redirect': 'A01:2021-Broken Access Control',
            'Path Traversal': 'A01:2021-Broken Access Control',
            'Insecure Crypto': 'A02:2021-Cryptographic Failures',
            'Hardcoded Credentials': 'A07:2021-Identification and Authentication Failures',
            'Information Disclosure': 'A04:2021-Insecure Design',
            'Insecure Configuration': 'A05:2021-Security Misconfiguration',
            'CSRF Vulnerabilities': 'A01:2021-Broken Access Control',
            'JWT Issues': 'A02:2021-Cryptographic Failures',
            'Deserialization': 'A08:2021-Software and Data Integrity Failures',
            'Software/Library Versions': 'A06:2021-Vulnerable and Outdated Components',
            'LDAP Injection': 'A03:2021-Injection',
            'NoSQL Injection': 'A03:2021-Injection',
            'Prototype Pollution': 'A08:2021-Software and Data Integrity Failures',
            'Insecure Randomness': 'A02:2021-Cryptographic Failures',
            'Weak JWT Secret': 'A02:2021-Cryptographic Failures',
            'Directory Listing Enabled': 'A05:2021-Security Misconfiguration',
            'Server-Side Template Injection (SSTI)': 'A03:2021-Injection',
            'Unrestricted File Upload': 'A01:2021-Broken Access Control',
            'Unvalidated Redirects': 'A01:2021-Broken Access Control',
            'Sensitive Data Exposure': 'A02:2021-Cryptographic Failures',
            'CORS Misconfiguration': 'A05:2021-Security Misconfiguration',
            'Insecure HTTP Headers': 'A05:2021-Security Misconfiguration',
            'XML Injection': 'A03:2021-Injection',
            'Insecure Cookie Flags': 'A05:2021-Security Misconfiguration',
            'Use of Dangerous Functions': 'A03:2021-Injection',
            'Race Condition': 'A01:2021-Broken Access Control',
            'Business Logic Flaw': 'A04:2021-Insecure Design',
            'Clickjacking': 'A05:2021-Security Misconfiguration',
            'HTTP Parameter Pollution': 'A03:2021-Injection',
            'Reflected File Download': 'A04:2021-Insecure Design',
            'Log Injection': 'A09:2021-Security Logging and Monitoring Failures',
            'Host Header Injection': 'A05:2021-Security Misconfiguration',
            'Misconfigured Caching': 'A05:2021-Security Misconfiguration',
            'Session Fixation': 'A07:2021-Identification and Authentication Failures',
            'Insufficient Logging & Monitoring': 'A09:2021-Security Logging and Monitoring Failures',
        }
        
        # Risk levels for each vulnerability type
        self.risk_levels = {
            'SQL Injection': 'High',
            'XSS': 'Medium',
            'Command Injection': 'High',
            'File Inclusion': 'High',
            'SSRF Vulnerabilities': 'High',
            'XXE Vulnerabilities': 'High',
            'Open Redirect': 'Medium',
            'Path Traversal': 'High',
            'Insecure Crypto': 'Medium',
            'Hardcoded Credentials': 'High',
            'Information Disclosure': 'Low',
            'Insecure Configuration': 'Medium',
            'CSRF Vulnerabilities': 'Medium',
            'JWT Issues': 'High',
            'Deserialization': 'High',
            'Software/Library Versions': 'Medium',
            'LDAP Injection': 'High',
            'NoSQL Injection': 'High',
            'Prototype Pollution': 'High',
            'Insecure Randomness': 'Medium',
            'Weak JWT Secret': 'High',
            'Directory Listing Enabled': 'Medium',
            'Server-Side Template Injection (SSTI)': 'High',
            'Unrestricted File Upload': 'High',
            'Unvalidated Redirects': 'Medium',
            'Sensitive Data Exposure': 'High',
            'CORS Misconfiguration': 'Medium',
            'Insecure HTTP Headers': 'Medium',
            'XML Injection': 'High',
            'Insecure Cookie Flags': 'Medium',
            'Use of Dangerous Functions': 'High',
            'Race Condition': 'High',
            'Business Logic Flaw': 'High',
            'Clickjacking': 'Medium',
            'HTTP Parameter Pollution': 'Medium',
            'Reflected File Download': 'Medium',
            'Log Injection': 'Medium',
            'Host Header Injection': 'High',
            'Misconfigured Caching': 'Medium',
            'Session Fixation': 'High',
            'Insufficient Logging & Monitoring': 'Medium',
        }
        
        # Descriptions for each vulnerability type
        self.vulnerability_descriptions = {
            'SQL Injection': 'SQL injection occurs when untrusted data is sent to an interpreter as part of a command or query. The attacker\'s hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.',
            'XSS': 'Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user.',
            'Command Injection': 'Command injection is an attack in which the goal is execution of arbitrary commands on the host operating system via a vulnerable application. Command injection attacks are possible when an application passes unsafe user supplied data to a system shell.',
            'File Inclusion': 'File inclusion vulnerabilities allow an attacker to include a file, usually exploiting a "dynamic file inclusion" mechanisms implemented in the target application. The vulnerability occurs due to the use of user-supplied input without proper validation.',
            'SSRF Vulnerabilities': 'Server-Side Request Forgery (SSRF) flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall or VPN.',
            'XXE Vulnerabilities': 'XML External Entity (XXE) attacks target applications that parse XML input. This attack occurs when XML input containing a reference to an external entity is processed by a weakly configured XML parser.',
            'Open Redirect': 'Open redirect vulnerabilities occur when a web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect. This can allow attackers to create links to trusted sites that redirect to malicious sites.',
            'Path Traversal': 'Path traversal attacks aim to access files and directories that are stored outside the web root folder. By manipulating variables that reference files with "dot-dot-slash (../)" sequences and variations, an attacker can access arbitrary files on the web server.',
            'Insecure Crypto': 'Cryptographic failures refer to weaknesses in encryption, hashing, or other cryptographic implementations. This includes using outdated or weak algorithms, insecure random number generation, or improper key management.',
            'Hardcoded Credentials': 'Hardcoded credentials, such as passwords, API keys, and tokens in source code, represent a significant security risk. If discovered, these credentials can be exploited to gain unauthorized access to systems or data.',
            'Information Disclosure': 'Information disclosure vulnerabilities expose sensitive information to unauthorized parties. This can include technical details, error messages, debug information, or other data that could be used to exploit the system.',
            'Insecure Configuration': 'Security misconfiguration is a common vulnerability that occurs when security controls are improperly configured or missing. This can include insecure default configurations, open cloud storage, verbose error messages, or improper HTTP headers.',
            'CSRF Vulnerabilities': 'Cross-Site Request Forgery (CSRF) attacks force authenticated users to submit unwanted requests to web applications. Without proper protection, attackers can trick users into performing actions they did not intend to perform.',
            'JWT Issues': 'JSON Web Token (JWT) vulnerabilities often stem from improper implementation or verification. Issues include weak signing algorithms, token tampering, and missing validation.',
            'Deserialization': 'Insecure deserialization vulnerabilities occur when applications deserialize data from untrusted sources without proper validation. This can lead to denial of service, authentication bypasses, or remote code execution.',
            'Software/Library Versions': 'Using outdated libraries or software versions can expose the application to known vulnerabilities that have been fixed in newer versions. Regular updates are essential to maintain security.',
            'LDAP Injection': 'LDAP injection occurs when untrusted input is used to construct LDAP queries, allowing attackers to modify queries and access unauthorized data.',
            'NoSQL Injection': 'NoSQL injection vulnerabilities occur when user input is unsafely included in NoSQL queries, potentially allowing attackers to bypass authentication or extract data.',
            'Prototype Pollution': 'Prototype pollution is a vulnerability that allows attackers to inject properties into JavaScript object prototypes, potentially leading to denial of service or code execution.',
            'Insecure Randomness': 'Insecure randomness refers to the use of predictable or weak random number generators, which can undermine cryptographic operations and security controls.',
            'Weak JWT Secret': 'Weak JWT secrets make it easier for attackers to forge or tamper with tokens, leading to authentication bypass or data exposure.',
            'Directory Listing Enabled': 'Directory listing enabled allows attackers to view the contents of directories on the server, potentially exposing sensitive files.',
            'Server-Side Template Injection (SSTI)': 'SSTI occurs when user input is unsafely embedded in server-side templates, allowing attackers to execute arbitrary code on the server.',
            'Unrestricted File Upload': 'Unrestricted file upload vulnerabilities allow attackers to upload malicious files, which can lead to code execution or data compromise.',
            'Unvalidated Redirects': 'Unvalidated redirects occur when user input is used to construct URLs for redirection without proper validation, potentially leading to phishing or malware attacks.',
            'Sensitive Data Exposure': 'Sensitive data exposure occurs when applications do not adequately protect sensitive information such as passwords, credit card numbers, or personal data.',
            'CORS Misconfiguration': 'CORS misconfiguration can allow unauthorized domains to access resources, leading to data theft or manipulation.',
            'Insecure HTTP Headers': 'Insecure HTTP headers can expose applications to various attacks by not enforcing security policies in browsers.',
            'XML Injection': 'XML injection occurs when user input is unsafely included in XML documents or queries, potentially allowing data manipulation or disclosure.',
            'Insecure Cookie Flags': 'Insecure cookie flags (missing HttpOnly, Secure, or SameSite) can expose cookies to theft or misuse.',
            'Use of Dangerous Functions': 'Use of dangerous functions (such as eval, exec, or system) can lead to code injection or execution vulnerabilities.',
            'Race Condition': 'Race conditions occur when the outcome of a process depends on the sequence or timing of uncontrollable events, potentially allowing attackers to exploit timing windows for unauthorized actions.',
            'Business Logic Flaw': 'Business logic flaws are weaknesses in the intended workflow of an application, allowing attackers to manipulate legitimate functionality for malicious purposes.',
            'Clickjacking': 'Clickjacking is an attack that tricks users into clicking on something different from what the user perceives, potentially revealing confidential information or allowing unauthorized actions.',
            'HTTP Parameter Pollution': 'HTTP Parameter Pollution occurs when multiple HTTP parameters with the same name are sent in a request, potentially bypassing input validation or causing unexpected application behavior.',
            'Reflected File Download': 'Reflected File Download vulnerabilities occur when user input is reflected in downloadable files, potentially allowing attackers to trick users into downloading malicious files.',
            'Log Injection': 'Log injection occurs when untrusted user input is written directly to logs, potentially allowing attackers to forge log entries or inject malicious content.',
            'Host Header Injection': 'Host header injection occurs when applications use unvalidated Host headers, potentially leading to cache poisoning, password reset poisoning, or web cache deception.',
            'Misconfigured Caching': 'Misconfigured caching can expose sensitive data to unauthorized users by improperly storing or serving cached content.',
            'Session Fixation': 'Session fixation vulnerabilities allow attackers to set or reuse a valid session ID, potentially hijacking a user session.',
            'Insufficient Logging & Monitoring': 'Insufficient logging and monitoring can allow attackers to perform malicious actions without detection, delaying response and remediation.',
        }
        
        # Mitigation recommendations for each vulnerability type
        self.mitigation_recommendations = {
            'SQL Injection': [
                'Use parameterized queries (prepared statements) for all database operations',
                'Apply input validation and sanitization',
                'Implement proper escaping of user input',
                'Apply the principle of least privilege for database accounts',
                'Use ORM (Object Relational Mapping) libraries when possible'
            ],
            'XSS': [
                'Implement Content Security Policy (CSP)',
                'Use output encoding for all user-generated content',
                'Validate input on both client and server side',
                'Use modern frameworks that automatically escape XSS by design',
                'Use the X-XSS-Protection header as an additional layer of protection'
            ],
            'Command Injection': [
                'Avoid using system commands with user-provided input',
                'Use safer alternatives to shell commands',
                'Implement strict input validation and whitelist input values',
                'Use APIs for the needed functionality instead of system commands',
                'Run with the least privileges necessary'
            ],
            'File Inclusion': [
                'Implement proper input validation and sanitization',
                'Use whitelist of allowed files instead of direct user input',
                'Avoid passing user-supplied input to file system APIs',
                'Store sensitive files outside the web root',
                'Implement proper access controls'
            ],
            'SSRF Vulnerabilities': [
                'Implement a whitelist of allowed domains and resources',
                'Disable unnecessary URL schemas (file://, ftp://, etc.)',
                'Use a URL parser to validate URLs',
                'Block requests to private networks (127.0.0.1, 169.254.0.0, etc.)',
                'Implement request timeouts to prevent denial of service'
            ],
            'XXE Vulnerabilities': [
                'Disable external entity processing in XML parsers',
                'Use less complex data formats like JSON when possible',
                'Patch or upgrade XML processors and libraries',
                'Implement server-side input validation, filtering, or sanitization',
                'Configure XML parsers to use secure settings by default'
            ],
            'Open Redirect': [
                'Implement a whitelist of allowed redirect URLs',
                'Use indirect reference maps for redirects',
                'Avoid passing user-supplied input directly to redirect functions',
                'Validate URLs before redirecting',
                'Use absolute URLs within the application'
            ],
            'Path Traversal': [
                'Validate and sanitize user input',
                'Use built-in path canonicalization functions',
                'Implement proper access controls',
                'Apply the principle of least privilege',
                'Use file system APIs that restrict access to specific directories'
            ],
            'Insecure Crypto': [
                'Use modern, strong encryption algorithms (AES-256, RSA-2048)',
                'Implement proper key management',
                'Use secure hashing algorithms (SHA-256, SHA-3)',
                'Never roll your own cryptography',
                'Keep cryptographic libraries updated'
            ],
            'Hardcoded Credentials': [
                'Use environment variables or secure configuration storage',
                'Implement proper secrets management',
                'Use credential rotation',
                'Encrypt sensitive configuration values',
                'Implement the principle of least privilege'
            ],
            'Information Disclosure': [
                'Implement proper error handling',
                'Disable debugging information in production',
                'Configure proper HTTP headers',
                'Remove unnecessary files and documentation from production servers',
                'Implement proper access controls'
            ],
            'Insecure Configuration': [
                'Implement secure configuration management',
                'Use security headers (X-Content-Type-Options, X-Frame-Options, etc.)',
                'Disable unnecessary features and modules',
                'Keep systems and software updated',
                'Use automated scanning tools to check for misconfigurations'
            ],
            'CSRF Vulnerabilities': [
                'Implement anti-CSRF tokens for all state-changing operations',
                'Use the SameSite cookie attribute',
                'Verify the origin of requests',
                'Implement proper session management',
                'Use the X-Frame-Options header to prevent clickjacking'
            ],
            'JWT Issues': [
                'Use strong signing keys',
                'Implement proper signature validation',
                'Include expiration times in tokens',
                'Do not store sensitive data in JWTs',
                'Use secure algorithms (RS256 instead of HS256 for public clients)'
            ],
            'Deserialization': [
                'Avoid deserializing data from untrusted sources',
                'Implement integrity checks',
                'Use safer serialization formats',
                'Monitor applications for unexpected deserialization',
                'Apply the principle of least privilege'
            ],
            'Software/Library Versions': [
                'Maintain an inventory of used libraries and dependencies',
                'Regularly update dependencies to their latest secure versions',
                'Use automated tools to check for outdated dependencies',
                'Subscribe to security bulletins for used components',
                'Implement a proper patch management process'
            ],
            'LDAP Injection': [
                'Use parameterized LDAP queries',
                'Validate and sanitize all user inputs',
                'Apply the principle of least privilege',
                'Escape special characters in LDAP queries',
                'Monitor and log LDAP access patterns'
            ],
            'NoSQL Injection': [
                'Use safe query APIs that separate code from data',
                'Validate and sanitize all user inputs',
                'Avoid string concatenation in queries',
                'Apply the principle of least privilege',
                'Monitor and log database access patterns'
            ],
            'Prototype Pollution': [
                'Avoid using user input to set object properties directly',
                'Use libraries that protect against prototype pollution',
                'Validate and sanitize all user inputs',
                'Keep dependencies updated',
                'Monitor for unexpected object property changes'
            ],
            'Insecure Randomness': [
                'Use cryptographically secure random number generators',
                'Avoid using Math.random() or similar for security-sensitive operations',
                'Review all uses of randomness in the codebase',
                'Document and test random number usage',
                'Keep cryptographic libraries updated'
            ],
            'Weak JWT Secret': [
                'Use strong, randomly generated secrets for signing JWTs',
                'Rotate secrets regularly',
                'Do not expose secrets in code or configuration',
                'Monitor for brute-force attempts',
                'Use environment variables for secret management'
            ],
            'Directory Listing Enabled': [
                'Disable directory listing on the web server',
                'Restrict access to sensitive directories',
                'Use proper access controls',
                'Remove unnecessary files from web directories',
                'Monitor server configuration changes'
            ],
            'Server-Side Template Injection (SSTI)': [
                'Avoid using user input in templates',
                'Use template engines that auto-escape input',
                'Validate and sanitize all template data',
                'Apply the principle of least privilege',
                'Monitor for unexpected template rendering behavior'
            ],
            'Unrestricted File Upload': [
                'Restrict allowed file types and sizes',
                'Scan uploaded files for malware',
                'Store uploads outside the web root',
                'Implement authentication and authorization checks',
                'Rename uploaded files to prevent overwriting'
            ],
            'Unvalidated Redirects': [
                'Avoid using user input for redirect destinations',
                'Implement a whitelist of allowed redirect URLs',
                'Validate and sanitize all redirect parameters',
                'Log and monitor redirect usage',
                'Educate users about phishing risks'
            ],
            'Sensitive Data Exposure': [
                'Encrypt sensitive data at rest and in transit',
                'Mask sensitive data in logs and error messages',
                'Use strong authentication and access controls',
                'Regularly audit data storage and access',
                'Comply with relevant data protection regulations'
            ],
            'CORS Misconfiguration': [
                'Set strict CORS policies',
                'Avoid using wildcard origins',
                'Validate allowed origins and methods',
                'Monitor CORS policy changes',
                'Educate developers on CORS risks'
            ],
            'Insecure HTTP Headers': [
                'Set security headers such as Content-Security-Policy, X-Frame-Options, and X-Content-Type-Options',
                'Review and update header configurations regularly',
                'Disable unnecessary headers',
                'Monitor for header misconfigurations',
                'Educate developers on secure header usage'
            ],
            'XML Injection': [
                'Validate and sanitize all XML input',
                'Use safe XML parsers',
                'Avoid dynamic construction of XML documents from user input',
                'Apply the principle of least privilege',
                'Monitor for unexpected XML processing behavior'
            ],
            'Insecure Cookie Flags': [
                'Set HttpOnly, Secure, and SameSite flags on all cookies',
                'Avoid storing sensitive data in cookies',
                'Regularly review cookie settings',
                'Monitor for cookie theft attempts',
                'Educate developers on secure cookie practices'
            ],
            'Use of Dangerous Functions': [
                'Avoid using dangerous functions such as eval, exec, or system',
                'Use safer alternatives or libraries',
                'Validate and sanitize all inputs to such functions',
                'Apply the principle of least privilege',
                'Monitor for unexpected function usage'
            ],
            'Race Condition': [
                'Use proper locking mechanisms and atomic operations',
                'Avoid time-of-check to time-of-use (TOCTOU) bugs',
                'Review concurrent code for shared resource access',
                'Test for race conditions in multi-threaded environments',
                'Apply principle of least privilege to critical operations'
            ],
            'Business Logic Flaw': [
                'Review application workflows for abuse cases',
                'Implement strict input validation and authorization checks',
                'Perform threat modeling and business logic testing',
                'Educate developers on business logic risks',
                'Monitor for unusual application behavior'
            ],
            'Clickjacking': [
                'Set X-Frame-Options header to DENY or SAMEORIGIN',
                'Implement Content Security Policy (CSP) frame-ancestors directive',
                'Avoid embedding sensitive pages in iframes',
                'Educate users about clickjacking risks',
                'Test application for frame-based attacks'
            ],
            'HTTP Parameter Pollution': [
                'Deduplicate and validate all HTTP parameters',
                'Use frameworks that handle parameter arrays safely',
                'Avoid using user input directly in queries',
                'Log and monitor for suspicious parameter usage',
                'Educate developers on parameter pollution risks'
            ],
            'Reflected File Download': [
                'Avoid reflecting user input in file names or contents',
                'Validate and sanitize all user-supplied file names',
                'Set appropriate Content-Disposition headers',
                'Educate users about download risks',
                'Monitor for suspicious file download activity'
            ],
            'Log Injection': [
                'Sanitize user input before logging',
                'Avoid logging sensitive or untrusted data',
                'Implement log integrity controls',
                'Monitor logs for suspicious entries',
                'Educate developers on log injection risks'
            ],
            'Host Header Injection': [
                'Validate and whitelist Host headers',
                'Avoid using Host headers for security decisions',
                'Set a default host value on the server',
                'Monitor for unusual Host header values',
                'Educate developers on host header risks'
            ],
            'Misconfigured Caching': [
                'Set strict Cache-Control headers for sensitive data',
                'Avoid caching authenticated or sensitive responses',
                'Review and test cache configurations',
                'Educate developers on caching risks',
                'Monitor for cache-related incidents'
            ],
            'Session Fixation': [
                'Regenerate session IDs after login',
                'Do not accept session IDs from user input',
                'Set session cookies with Secure and HttpOnly flags',
                'Monitor for session fixation attempts',
                'Educate developers on session management best practices'
            ],
            'Insufficient Logging & Monitoring': [
                'Log all critical security events',
                'Monitor logs for suspicious activity',
                'Alert on detection of security incidents',
                'Retain logs securely for forensic analysis',
                'Regularly review and test logging mechanisms'
            ],
        }
    
    def analyze_code(self, code_files):
        """
        Analyze code files for security vulnerabilities
        
        Args:
            code_files (dict): Dictionary of code files and their contents
            
        Returns:
            dict: Dictionary of security findings
        """
        logger.info("Starting detailed security analysis...")
        
        # Dictionary to store security findings
        security_findings = {}
        
        # Dictionary to store software/library versions
        detected_libraries = {}
        
        # Analyze each code file
        for file_path, content in code_files.items():
            file_findings = {}
            
            # Check for security issues
            for issue_type, patterns in self.security_patterns.items():
                matches = []
                
                for pattern in patterns:
                    for match in re.finditer(pattern, content):
                        line_number = content[:match.start()].count('\n') + 1
                        code_lines = content.splitlines()
                        
                        # Get context (a few lines before and after)
                        start_line = max(0, line_number - 3)
                        end_line = min(len(code_lines), line_number + 3)
                        
                        context_lines = []
                        for i in range(start_line, end_line):
                            context_lines.append(f"{i+1}: {code_lines[i]}")
                        
                        match_info = {
                            'line': line_number,
                            'code': code_lines[line_number - 1].strip(),
                            'match': match.group(0),
                            'context': "\n".join(context_lines),
                            'risk_level': self.risk_levels.get(issue_type, 'Medium'),
                            'owasp_category': self.owasp_categories.get(issue_type, 'Unknown'),
                            'description': self.vulnerability_descriptions.get(issue_type, ''),
                            'mitigation': self.mitigation_recommendations.get(issue_type, [])
                        }
                        
                        matches.append(match_info)
                        
                        # If this is a Software/Library Version finding, store the version
                        if issue_type == 'Software/Library Versions' and len(match.groups()) > 0:
                            library_name = match.group(0).split('-')[0].strip()
                            version = match.group(1)
                            detected_libraries[library_name] = version
                
                if matches:
                    file_findings[issue_type] = matches
            
            if file_findings:
                security_findings[file_path] = file_findings
        
        logger.info(f"Completed security analysis. Found issues in {len(security_findings)} files.")
        
        # Add summary data
        security_findings['__summary__'] = {
            'total_files_analyzed': len(code_files),
            'files_with_issues': len(security_findings),
            'total_issues': sum(len(issues) for file_issues in security_findings.values() if isinstance(file_issues, dict) for issues in file_issues.values()),
            'issues_by_type': self._count_issues_by_type(security_findings),
            'issues_by_risk': self._count_issues_by_risk(security_findings),
            'issues_by_owasp': self._count_issues_by_owasp(security_findings),
            'detected_libraries': detected_libraries
        }
        
        return security_findings
    
    def _count_issues_by_type(self, security_findings):
        """
        Count issues by type
        
        Args:
            security_findings (dict): Dictionary of security findings
            
        Returns:
            dict: Dictionary of issue counts by type
        """
        issues_by_type = defaultdict(int)
        
        for file_path, file_findings in security_findings.items():
            if file_path == '__summary__' or not isinstance(file_findings, dict):
                continue
                
            for issue_type, matches in file_findings.items():
                issues_by_type[issue_type] += len(matches)
        
        return dict(issues_by_type)
    
    def _count_issues_by_risk(self, security_findings):
        """
        Count issues by risk level
        
        Args:
            security_findings (dict): Dictionary of security findings
            
        Returns:
            dict: Dictionary of issue counts by risk level
        """
        issues_by_risk = defaultdict(int)
        
        for file_path, file_findings in security_findings.items():
            if file_path == '__summary__' or not isinstance(file_findings, dict):
                continue
                
            for issue_type, matches in file_findings.items():
                for match in matches:
                    risk_level = match.get('risk_level', 'Medium')
                    issues_by_risk[risk_level] += 1
        
        return dict(issues_by_risk)
    
    def _count_issues_by_owasp(self, security_findings):
        """
        Count issues by OWASP category
        
        Args:
            security_findings (dict): Dictionary of security findings
            
        Returns:
            dict: Dictionary of issue counts by OWASP category
        """
        issues_by_owasp = defaultdict(int)
        
        for file_path, file_findings in security_findings.items():
            if file_path == '__summary__' or not isinstance(file_findings, dict):
                continue
                
            for issue_type, matches in file_findings.items():
                for match in matches:
                    owasp_category = match.get('owasp_category', 'Unknown')
                    issues_by_owasp[owasp_category] += 1
        
        return dict(issues_by_owasp)
    
    def get_enhanced_report_data(self, security_findings):
        """
        Get enhanced report data for generating comprehensive reports
        
        Args:
            security_findings (dict): Dictionary of security findings
            
        Returns:
            dict: Dictionary of enhanced report data
        """
        if '__summary__' not in security_findings:
            return {}
            
        summary = security_findings['__summary__']
        
        # Get top 5 most common vulnerability types
        top_vulnerabilities = sorted(summary['issues_by_type'].items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Get risk distribution
        risk_distribution = summary['issues_by_risk']
        
        # Get OWASP Top 10 distribution
        owasp_distribution = summary['issues_by_owasp']
        
        # Compile enhanced data
        enhanced_data = {
            'top_vulnerabilities': top_vulnerabilities,
            'risk_distribution': risk_distribution,
            'owasp_distribution': owasp_distribution,
            'overall_risk_score': self._calculate_overall_risk_score(risk_distribution),
            'recommendations': self._get_top_recommendations(top_vulnerabilities),
            'detected_libraries': summary['detected_libraries']
        }
        
        return enhanced_data
    
    def _calculate_overall_risk_score(self, risk_distribution):
        """
        Calculate overall risk score
        
        Args:
            risk_distribution (dict): Dictionary of risk counts
            
        Returns:
            float: Overall risk score between 0 and 10
        """
        # Weights for each risk level
        weights = {
            'High': 10,
            'Medium': 5,
            'Low': 1
        }
        
        total_issues = sum(risk_distribution.values())
        if total_issues == 0:
            return 0
            
        weighted_sum = sum(weights.get(risk, 1) * count for risk, count in risk_distribution.items())
        
        # Normalize to a scale of 0-10
        max_possible_score = total_issues * 10
        if max_possible_score == 0:
            return 0
            
        normalized_score = (weighted_sum / max_possible_score) * 10
        
        return round(normalized_score, 1)
    
    def _get_top_recommendations(self, top_vulnerabilities):
        """
        Get top recommendations based on most common vulnerabilities
        
        Args:
            top_vulnerabilities (list): List of tuples (vulnerability_type, count)
            
        Returns:
            list: List of recommendation dictionaries
        """
        recommendations = []
        
        for vuln_type, count in top_vulnerabilities:
            if vuln_type in self.mitigation_recommendations:
                recommendations.append({
                    'vulnerability_type': vuln_type,
                    'count': count,
                    'mitigation_steps': self.mitigation_recommendations[vuln_type]
                })
        
        return recommendations
