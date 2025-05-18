#!/usr/bin/env python3

import re
import logging
import json
import os
from collections import defaultdict
from .patterns.Insecure_Configuration import insecure_config_patterns
from .patterns.CSRF_Vulnerabilities import csrf_vulnerabilities_patterns
from .patterns.SQL_Injection import sql_injection_patterns
from .patterns.XSS import xss_patterns
from .patterns.Command_Injection import command_injection_patterns
from .patterns.File_Inclusion import file_inclusion_patterns
from .patterns.Insecure_Crypto import insecure_crypto_patterns
from .patterns.Hardcoded_Credentials import hardcoded_credentials_patterns
from .patterns.Information_Disclosure import information_disclosure_patterns
from .patterns.SSRF_Vulnerabilities import ssrf_vulnerabilities_patterns
from .patterns.XXE_Vulnerabilities import xxe_vulnerabilities_patterns
from .patterns.Open_Redirect import open_redirect_patterns
from .patterns.JWT_Issues import jwt_issues_patterns
from .patterns.Deserialization import deserialization_patterns
from .patterns.LDAP_Injection import ldap_injection_patterns
from .patterns.NoSQL_Injection import nosql_injection_patterns
from .patterns.Insecure_Randomness import insecure_randomness_patterns
from .patterns.Path_Traversal import path_traversal_patterns
from .patterns.Unrestricted_File_Upload import unrestricted_file_upload_patterns
from .patterns.Software_Library_Versions import software_library_versions_patterns
from .patterns.Directory_Listing_Enabled import directory_listing_enabled_patterns
from .patterns.Weak_JWT_Secret import weak_jwt_secret_patterns
from .patterns.Server_Side_Template_Injection import ssti_patterns
from .patterns.Unvalidated_Redirects import unvalidated_redirects_patterns
from .patterns.Sensitive_Data_Exposure import sensitive_data_exposure_patterns
from .patterns.Reflected_File_Download import reflected_file_download_patterns
from .patterns.Insecure_HTTP_Headers import insecure_http_header_patterns
from .patterns.Session_Fixation import session_fixation_patterns
from .patterns.Race_Condition import race_condition_patterns
from .patterns.Clickjacking import clickjacking_patterns
from .patterns.Host_Header_Injection import host_header_injection_patterns
from .patterns.CORS_Misconfiguration import cors_misconfiguration_patterns
from .patterns.XML_Injection import xml_injection_patterns
from .patterns.Insecure_Cookie_Flags import insecure_cookie_flag_patterns
from .patterns.Use_of_Dangerous_Functions import use_of_dangerous_functions_patterns
from .patterns.Prototype_Pollution import prototype_pollution_patterns

# Load vulnerability descriptions and recommendations from JSON files
with open(os.path.join(os.path.dirname(__file__), 'patterns', 'vuln_descriptions.json')) as f:
    VULN_DESCRIPTIONS = json.load(f)
with open(os.path.join(os.path.dirname(__file__), 'patterns', 'vuln_recommendations.json')) as f:
    VULN_RECOMMENDATIONS = json.load(f)

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
            'NoSQL Injection': nosql_injection_patterns,
            'Insecure Randomness': insecure_randomness_patterns,
            'Path Traversal': path_traversal_patterns,
            'Weak JWT Secret': weak_jwt_secret_patterns,
            'Software/Library Versions': software_library_versions_patterns,
            'Directory Listing Enabled': directory_listing_enabled_patterns,
            'Server-Side Template Injection (SSTI)': ssti_patterns,
            'Insecure Configuration': insecure_config_patterns,
            'Unrestricted File Upload': unrestricted_file_upload_patterns,
            'Directory Listing Enabled': directory_listing_enabled_patterns,
            'Unvalidated Redirects': unvalidated_redirects_patterns,
            'CORS Misconfiguration': cors_misconfiguration_patterns,
            'Insecure HTTP Headers': insecure_http_header_patterns,
            'XML Injection': xml_injection_patterns,
            'Insecure Cookie Flags': insecure_cookie_flag_patterns,
            'Use of Dangerous Functions': use_of_dangerous_functions_patterns,
            'Prototype Pollution': prototype_pollution_patterns,
            'Sensitive Data Exposure': sensitive_data_exposure_patterns,
            'Reflected File Download': reflected_file_download_patterns,
            'Session Fixation': session_fixation_patterns,
            'Race Condition': race_condition_patterns,
            'Clickjacking': clickjacking_patterns,
            'Host Header Injection': host_header_injection_patterns,
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
            'Insecure Randomness': 'A02:2021-Cryptographic Failures',
            'Weak JWT Secret': 'A02:2021-Cryptographic Failures',
            'Directory Listing Enabled': 'A05:2021-Security Misconfiguration',
            'Server-Side Template Injection (SSTI)': 'A03:2021-Injection',
            'Unrestricted File Upload': 'A01:2021-Broken Access Control',
            'Unvalidated Redirects': 'A01:2021-Broken Access Control',
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
            'Insecure Randomness': 'Medium',
            'Weak JWT Secret': 'High',
            'Directory Listing Enabled': 'Medium',
            'Server-Side Template Injection (SSTI)': 'High',
            'Unrestricted File Upload': 'High',
            'Unvalidated Redirects': 'Medium',
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
        
        # Use loaded JSON for descriptions and recommendations
        self.vulnerability_descriptions = VULN_DESCRIPTIONS
        self.mitigation_recommendations = VULN_RECOMMENDATIONS
    
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
            try:
                # Check for security issues
                for issue_type, patterns in self.security_patterns.items():
                    matches = []
                    for pattern in patterns:
                        try:
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
                        except re.error as regex_err:
                            logger.error(f"Regex error in pattern for {issue_type}: {pattern}\nError: {regex_err}")
                            import traceback
                            traceback.print_exc()
                            matches.append({'regex_error': str(regex_err), 'pattern': pattern})
                        except Exception as e:
                            logger.error(f"Unexpected error in pattern for {issue_type}: {pattern}\nError: {e}")
                            import traceback
                            traceback.print_exc()
                            matches.append({'unexpected_error': str(e), 'pattern': pattern})
                    if matches:
                        file_findings[issue_type] = matches
            except Exception as file_exc:
                logger.error(f"Error analyzing file {file_path}: {file_exc}")
                import traceback
                traceback.print_exc()
                file_findings['analyzer_error'] = str(file_exc)
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
