#!/usr/bin/env python3

import re
import logging
import json
from collections import defaultdict

logger = logging.getLogger('WebScann3r.Analyzer')

class SecurityAnalyzer:
    def __init__(self):
        """
        Initialize the security analyzer
        """
        self.security_patterns = {
            'SQL Injection': [
                r'(?i)(?:execute|exec)\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*=\s*[\'"].*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)INSERT\s+INTO\s+.*\s+VALUES\s*\(.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)UPDATE\s+.*\s+SET\s+.*=.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)DELETE\s+FROM\s+.*\s+WHERE\s+.*=.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)(?:mysql|mysqli|pdo)_query\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)(?:query|prepare)\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE).*\$',
                r'(?i)\.executeQuery\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE).*\+',
            ],
            'XSS': [
                r'(?i)document\.write\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)\.innerHTML\s*=\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)\.outerHTML\s*=\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)eval\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)setTimeout\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)setInterval\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)new\s+Function\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)\.innerText\s*=\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)document\.body\.appendChild\(.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)\.insertAdjacentHTML\(.*\$_(?:GET|POST|REQUEST|COOKIE)',
            ],
            'Command Injection': [
                r'(?i)(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\(\s*.*\+',
                r'(?i)spawn\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)child_process\.exec\s*\(\s*.*\+',
                r'(?i)Runtime\.getRuntime\(\)\.exec\(.*\+',
                r'(?i)ProcessBuilder\(.*\+',
                r'(?i)os\.system\(.*\+',
                r'(?i)subprocess\.(?:call|Popen|run)\(.*\+',
            ],
            'File Inclusion': [
                r'(?i)(?:include|require|include_once|require_once)\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)fopen\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)file_get_contents\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)readfile\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)new\s+FileReader\(.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)fs\.readFile\(.*\+',
                r'(?i)java\.io\.File\(.*\+',
                r'(?i)open\(.*\+.*,\s*[\'"]r[\'"]\)',
            ],
            'Insecure Crypto': [
                r'(?i)md5\s*\(',
                r'(?i)sha1\s*\(',
                r'(?i)crypt\s*\(',
                r'(?i)CryptoJS\.MD5',
                r'(?i)CryptoJS\.SHA1',
                r'(?i)createHash\([\'"]md5[\'"]\)',
                r'(?i)createHash\([\'"]sha1[\'"]\)',
                r'(?i)MessageDigest\.getInstance\([\'"]MD5[\'"]\)',
                r'(?i)MessageDigest\.getInstance\([\'"]SHA-1[\'"]\)',
                r'(?i)hashlib\.md5\(',
                r'(?i)hashlib\.sha1\(',
            ],
            'Hardcoded Credentials': [
                r'(?i)(?:password|passwd|pwd|token|secret|api_key|apikey)\s*=\s*[\'"][^\'"]+[\'"]',
                r'(?i)Authorization:\s*Basic\s+[a-zA-Z0-9+/=]+',
                r'(?i)Authorization:\s*Bearer\s+[a-zA-Z0-9._~+/=-]+',
                r'(?i)(?:access_key|access_token|secret_key|api_key|apikey)\s*[=:]\s*[\'"][^\'"]{8,}[\'"]',
                r'(?i)const\s+(?:password|passwd|pwd|token|secret|api_key|apikey)\s*=\s*[\'"][^\'"]+[\'"]',
                r'(?i)var\s+(?:password|passwd|pwd|token|secret|api_key|apikey)\s*=\s*[\'"][^\'"]+[\'"]',
                r'(?i)let\s+(?:password|passwd|pwd|token|secret|api_key|apikey)\s*=\s*[\'"][^\'"]+[\'"]',
                r'(?i)private\s+(?:final\s+)?String\s+(?:password|passwd|pwd|token|secret|api_key|apikey)\s*=\s*[\'"][^\'"]+[\'"]',
            ],
            'Information Disclosure': [
                r'(?i)console\.log\s*\(',
                r'(?i)alert\s*\(',
                r'(?i)print_r\s*\(',
                r'(?i)var_dump\s*\(',
                r'(?i)phpinfo\s*\(',
                r'(?i)<!--\s*DEBUG',
                r'(?i)//\s*DEBUG',
                r'(?i)^\s*echo\s+.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)\.debug\s*\(',
                r'(?i)System\.out\.print',
                r'(?i)print\(\s*traceback',
                r'(?i)\.printStackTrace\(\)',
            ],
            'Insecure Configuration': [
                r'(?i)allow_url_include\s*=\s*On',
                r'(?i)allow_url_fopen\s*=\s*On',
                r'(?i)display_errors\s*=\s*On',
                r'(?i)expose_php\s*=\s*On',
                r'(?i)disable_functions\s*=\s*',
                r'(?i)safe_mode\s*=\s*Off',
                r'(?i)X-XSS-Protection:\s*0',
                r'(?i)Access-Control-Allow-Origin:\s*\*',
                r'(?i)helmet.noCache\(\s*false\s*\)',
                r'(?i)helmet.noSniff\(\s*false\s*\)',
                r'(?i)helmet.xssFilter\(\s*false\s*\)',
                r'(?i)secureConnection\s*=\s*false',
                r'(?i)validateCertificates\s*=\s*false',
                r'(?i)verify\s*=\s*False',
            ],
            'Software/Library Versions': [
                r'(?i)jquery[\.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
                r'(?i)bootstrap[\.-](\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)',
                r'(?i)angular[\.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
                r'(?i)react[\.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
                r'(?i)vue[\.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
                r'(?i)wordpress\/(\d+\.\d+)(?:\.\d+)?',
                r'(?i)express\/(\d+\.\d+\.\d+)',
                r'(?i)php(?:\/|-)(\d+\.\d+\.\d+)',
                r'(?i)python(?:\/|-)(\d+\.\d+\.\d+)',
                r'(?i)ruby(?:\/|-)(\d+\.\d+\.\d+)',
                r'(?i)node(?:\/|-)(\d+\.\d+\.\d+)',
                r'(?i)(?:<!--|\*|//|#)\s*[Pp]owered by\s+([A-Za-z0-9\.-]+)',
                r'(?i)<meta\s+name=[\'"]generator[\'"]\s+content=[\'"]([^\'"]*)[\'"]\s*\/?>'
            ],
            'CSRF Vulnerabilities': [
                r'(?i)csrf_token\s*=\s*[\'"]\s*[\'"]\s*',
                r'(?i)anticsrf\s*=\s*[\'"]\s*[\'"]\s*',
                r'(?i)_csrf\s*=\s*[\'"]\s*[\'"]\s*',
                r'(?i)<form[^>]*method=[\'"]post[\'"][^>]*>(?:(?!csrf).)*<\/form>',
                r'(?i)\.setRequestHeader\([\'"]X-CSRF-Token[\'"]\s*,\s*[\'"][\'"]\)',
                r'(?i)\.setRequestHeader\([\'"]X-CSRF-Token[\'"]\s*,\s*null\)',
            ],
            'SSRF Vulnerabilities': [
                r'(?i)(?:axios|fetch|http|request|got|superagent|curl_exec)\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)new\s+URL\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)\.get\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)\.post\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)\.send\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)\.open\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
            ],
            'XXE Vulnerabilities': [
                r'(?i)\.setFeature\("http://apache.org/xml/features/disallow-doctype-decl",\s*false\)',
                r'(?i)\.setFeature\("http://xml.org/sax/features/external-general-entities",\s*true\)',
                r'(?i)\.setFeature\("http://xml.org/sax/features/external-parameter-entities",\s*true\)',
                r'(?i)DocumentBuilderFactory\s*.*\.setExpandEntityReferences\(\s*true\s*\)',
                r'(?i)\.setFeature\(XMLConstants\.FEATURE_SECURE_PROCESSING,\s*false\)',
                r'(?i)libxml_disable_entity_loader\(\s*false\s*\)',
            ],
            'Open Redirect': [
                r'(?i)(?:window\.location|location\.href|location\.replace|location\.assign|location|(?:<meta[^>]*?refresh[^>]*?content=["\'][^"\']*?url=)|(?:<meta[^>]*?http-equiv=["\']?refresh[^>]*?content=["\'][^"\']*?url=))\s*=\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)response\.redirect\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)res\.redirect\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)header\(\s*[\'"]Location:\s*[\'"].*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)sendRedirect\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
            ],
            'Path Traversal': [
                r'(?i)\.\.\/.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)\.\.\\\\.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)\.\.%2F.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)\.\.%5C.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)%2e%2e%2f.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)%2e%2e%5c.*\$_(?:GET|POST|REQUEST|COOKIE)',
            ],
            'JWT Issues': [
                r'(?i)JWT\.sign\(\s*.*,\s*[\'"]none[\'"]\s*',
                r'(?i)jwtOptions\s*=\s*{\s*(?:.*,\s*)?[\'"]{0,1}algorithm[\'"]{0,1}\s*:\s*[\'"]{1}none[\'"]{1}',
                r'(?i)\.verifySignature\(\s*false\s*\)',
                r'(?i)\.verify\(\s*.*,\s*.*,\s*{\s*(?:.*,\s*)?[\'"]{0,1}algorithms[\'"]{0,1}\s*:\s*\[[^\]]*[\'"]none[\'"]\s*[^\]]*\]',
            ],
            'Deserialization': [
                r'(?i)unserialize\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)ObjectInputStream\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)yaml\.load\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)json_decode\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)Marshal\.load\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)pickle\.loads?\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
            ]
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
            'Deserialization': 'A08:2021-Software and Data Integrity Failures'
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
            'Software/Library Versions': 'Medium'
        }
        
        # Descriptions for each vulnerability type
        self.vulnerability_descriptions = {
            'SQL Injection': 'SQL injection occurs when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.',
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
            'Software/Library Versions': 'Using outdated libraries or software versions can expose the application to known vulnerabilities that have been fixed in newer versions. Regular updates are essential to maintain security.'
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
            ]
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
