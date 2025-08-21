#!/usr/bin/env python3
"""
Reporter Module - Responsible for generating various reports from scan data

This module contains the Reporter class that generates different types of reports
including security findings, function usage, and a comprehensive final report.
Reports are saved in markdown and JSON formats for easy viewing.
"""

import os
import time
import logging
import json
from pathlib import Path
import pytz
from datetime import datetime


# Configure module logger
logger = logging.getLogger('WebScann3r.Reporter')


class Reporter:
    """
    Reporter class for generating various types of reports from scan data
    
    This class handles the creation of security reports, function usage reports,
    file structure reports, and a comprehensive final report that combines all findings.

    ---
    Data Structure Notes:

    security_findings: dict
        Structure:
            {
                'relative/file/path1': {
                    'Issue Type 1': [
                        {
                            'line': <int>,         # Line number where the issue was found
                            'code': <str>,         # The full line of code containing the match
                            'match': <str>,        # The exact regex fragment that matched
                        },
                        ...
                    ],
                    'Issue Type 2': [...],
                    ...
                },
                'relative/file/path2': {...},
                ...
            }
        Description:
            Maps each scanned file to a dictionary of issue types (e.g., 'SQL Injection', 'XSS'),
            each containing a list of matches with line number, code, and the matching fragment.

    scan_info: dict
        Structure:
            {
                'visited_urls': [<str>, ...],      # List of all URLs visited during the scan
                'downloaded_files': [<str>, ...], # List of all downloaded file paths (relative or absolute)
                'same_domain_only': <bool>,        # Whether scan was limited to the same domain
                'urls_visited': <int>,             # Count of URLs visited
                'files_downloaded': <int>,         # Count of files downloaded
                'download_media': <bool>,          # Whether media files were downloaded
                'download_archives': <bool>,       # Whether archive files were downloaded
                'download_text': <bool>,           # Whether text files were downloaded
                ... (other scan settings/metadata)
            }
        Description:
            Contains summary and settings for the scan, including lists of URLs/files and scan options.
    ---
    """
    
    def __init__(self, target_url, report_dir='reports', download_dir='downloads'):
        """
        Initialize the reporter
        
        Args:
            target_url (str): Target URL that was scanned
            report_dir (str): Directory to save generated reports
            download_dir (str): Directory where scanned files were downloaded
        """
        self.target_url = target_url
        self.report_dir = os.path.abspath(report_dir)
        self.download_dir = os.path.abspath(download_dir)
        
        # Create report directory if it doesn't exist
        os.makedirs(self.report_dir, exist_ok=True)
    
    def generate_files_directories_json(self, visited_urls, downloaded_files):
        """
        Generate a JSON file containing all discovered files and directories
        
        Creates a structured JSON report that catalogs all URLs visited during scanning
        and organizes the directory structure of downloaded files for easier navigation.
        This helps in understanding the site structure and content organization.
        
        Args:
            visited_urls (list): List of all URLs visited during scanning
            downloaded_files (list): List of all files downloaded during scanning
            
        Returns:
            str: Path to the generated JSON file
        """
        logger.info("Generating files and directories JSON dump...")
        
        # Extract base domain from target URL for reference
        from urllib.parse import urlparse
        base_domain = urlparse(self.target_url).netloc
        
        # Get all discovered files and directories
        files_dirs = {
            "target_url": self.target_url,
            "base_domain": base_domain,
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "visited_urls": visited_urls,
            "downloaded_files": downloaded_files,
            "directories": []
        }
        
        # Create a set of unique directory paths from all downloaded files
        dir_set = set()
        for file_path in downloaded_files:
            # Get the directory portion of the path
            dir_path = os.path.dirname(file_path)
            # Split by "/" to get all parent directories too
            parts = dir_path.split("/")
            current = ""
            for part in parts:
                if part:
                    current = os.path.join(current, part) if current else part
                    dir_set.add(current)
        
        files_dirs["directories"] = sorted(list(dir_set))
        
        # Save to JSON file
        json_path = os.path.join(self.report_dir, 'discovered_files_dirs.json')
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(files_dirs, f, indent=4)
        
        logger.info(f"Files and directories JSON dump generated: {json_path}")
        print(f"[SUMMARY] Discovered files/dirs: {len(downloaded_files)} files, {len(files_dirs['directories'])} directories")
        return json_path
        
    def generate_security_report(self, security_findings, pattern_map=None):
        """
        Generate a human-friendly, numbered, and clearly separated security report.
        Each issue is numbered, separated by ASCII art, and shows the regex pattern above the code snippet.
        Uses Berlin time for the report timestamp.
        """
        print("[DEBUG] generate_security_report called!")  # Debug print
        logger.info("Generating security report...")
        import re
        berlin = pytz.timezone('Europe/Berlin')
        now_berlin = datetime.now(berlin).strftime('%Y-%m-%d %H:%M:%S %Z')
        report_path = os.path.join(self.report_dir, 'security_report.md')

        def highlight_match(code, match):
            idx = code.find(match)
            if idx == -1:
                snippet = code[:120] + ('...' if len(code) > 120 else '')
                return f'`{snippet}`'
            start = max(0, idx - 40)
            end = min(len(code), idx + len(match) + 40)
            before = code[start:idx]
            after = code[idx+len(match):end]
            snippet = before + '**' + match + '**' + after
            if start > 0:
                snippet = '...' + snippet
            if end < len(code):
                snippet = snippet + '...'
            return snippet.replace('`', '\u0060')

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("# WebScann3r Security Report\n\n")
            f.write(f"**Target:** {self.target_url}\n")
            f.write(f"**Date:** {now_berlin}\n\n")

            if not security_findings:
                f.write("No security issues found.\n")
            else:
                f.write("## Security Issues Found\n\n")
                # Only count issues that are lists, skip summary/stat keys
                issue_count = sum(
                    len(issues)
                    for file_issues in security_findings.values()
                    if isinstance(file_issues, dict)
                    for issues in file_issues.values()
                    if isinstance(issues, list)
                )
                f.write(f"Total issues found: {issue_count}\n\n")
                issue_num = 1
                for file_path, file_findings in security_findings.items():
                    if not isinstance(file_findings, dict):
                        continue
                    for issue_type, matches in file_findings.items():
                        if not isinstance(matches, list):
                            continue
                        for match in matches:
                            # Find the exact regex pattern that matched, if pattern_map is provided
                            pattern_str = None
                            if pattern_map and issue_type in pattern_map:
                                for pat in pattern_map[issue_type]:
                                    try:
                                        if re.search(pat, match['code']):
                                            pattern_str = pat
                                            break
                                    except re.error:
                                        continue
                            # Write a clearly separated, numbered finding
                            f.write(f"-------------------- ISSUE {issue_num} --------------------\n\n")
                            f.write(f"**File:** `{file_path}`  \n")
                            f.write(f"**Type:** {issue_type}  \n")
                            f.write(f"**Line:** {match['line']}\n\n")
                            if pattern_str:
                                f.write(f"**Pattern:**\n```\n{pattern_str}\n```\n\n")
                            else:
                                # Show the actual match string if pattern is not available
                                f.write(f"**Pattern:** _Pattern not available (matched: {match.get('match', 'N/A')})_\n\n")
                            snippet = highlight_match(match['code'], match['match'])
                            f.write(f"**Code:**\n```\n{snippet}\n```\n")
                            f.write("==================================================\n\n")
                            issue_num += 1
        logger.info(f"Security report generated: {report_path}")
        print(f"[SUMMARY] Security report issues: {issue_count}")
        return report_path
    
    def generate_function_usage_report(self, function_calls):
        """
        Generate a report on function usage
        
        Args:
            function_calls (dict): Dictionary of function calls and their counts
        """
        logger.info("Generating function usage report...")
        
        report_path = os.path.join(self.report_dir, 'function_usage_report.md')
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("# WebScann3r Function Usage Report\n\n")
            f.write(f"**Target:** {self.target_url}\n")
            f.write(f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            if not function_calls:
                f.write("No function calls detected.\n")
            else:
                f.write("## Function Calls\n\n")
                
                # Sort function calls by count (descending)
                sorted_functions = sorted(function_calls.items(), key=lambda x: x[1], reverse=True)
                
                f.write("| Function | Call Count |\n")
                f.write("|----------|------------|\n")
                
                for function, count in sorted_functions:
                    f.write(f"| `{function}` | {count} |\n")
        
        logger.info(f"Function usage report generated: {report_path}")
        return report_path
    
    def generate_final_report(self, scan_info, security_findings, function_calls):
        """
        Generate a final comprehensive report
        
        Args:
            scan_info (dict): Dictionary of scan information
            security_findings (dict): Dictionary of security findings
            function_calls (dict): Dictionary of function calls and their counts
        """
        logger.info("Generating final report...")
        
        # First, generate the JSON dump of all discovered files and directories
        visited_urls = scan_info.get('visited_urls', [])
        downloaded_files = scan_info.get('downloaded_files', [])
        json_path = self.generate_files_directories_json(visited_urls, downloaded_files)
        
        report_path = os.path.join(self.report_dir, 'final_report.md')
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("# WebScann3r Final Report\n\n")
            f.write(f"**Target:** {self.target_url}\n")
            f.write(f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## Scan Summary\n\n")
            f.write(f"- **Scan Mode:** {'Same domain only' if scan_info.get('same_domain_only', True) else 'All domains'}\n")
            f.write(f"- **URLs Visited:** {scan_info.get('urls_visited', 0)}\n")
            f.write(f"- **Files Downloaded:** {scan_info.get('files_downloaded', 0)}\n")
            f.write(f"- **Download Settings:**\n")
            f.write(f"  - **Media Files:** {'Yes' if scan_info.get('download_media', False) else 'No'}\n")
            f.write(f"  - **Archive Files:** {'Yes' if scan_info.get('download_archives', False) else 'No'}\n")
            f.write(f"  - **Text Files:** {'Yes' if scan_info.get('download_text', False) else 'No'}\n\n")
            
            f.write(f"- **Files and Directories JSON:** [discovered_files_dirs.json]({os.path.basename(json_path)})\n\n")

            # --- New Section: Found Software Versions ---
            f.write("## Found Software Versions\n\n")
            detected_versions = scan_info.get('detected_versions', {})
            if detected_versions:
                for name, version in detected_versions.items():
                    f.write(f"- **{name}:** {version}\n")
                f.write("\n")
            else:
                f.write("No software versions detected.\n\n")

            # --- New Section: Potential Sinks ---
            f.write("## Potential Sinks (Fuzzing Targets)\n\n")
            potential_sinks = scan_info.get('potential_sinks', [])
            if potential_sinks:
                for sink in potential_sinks:
                    if isinstance(sink, dict):
                        # Pretty print dict sinks
                        for k, v in sink.items():
                            f.write(f"- **{k}:** {v}\n")
                    else:
                        f.write(f"- {sink}\n")
                f.write("\n")
            else:
                f.write("No potential sinks identified.\n\n")

            # --- Existing Section: Site Structure ---
            f.write("## Site Structure\n\n")
            f.write("```\n")
            
            # Create a tree structure of the downloaded files
            def print_tree(dir_path, prefix=""):
                if not os.path.exists(dir_path):
                    f.write(f"{prefix}No files downloaded\n")
                    return
                
                entries = os.listdir(dir_path)
                entries.sort()
                
                for i, entry in enumerate(entries):
                    entry_path = os.path.join(dir_path, entry)
                    is_last = i == len(entries) - 1
                    
                    f.write(f"{prefix}{'+-- ' if is_last else '+-- '}{entry}\n")
                    
                    if os.path.isdir(entry_path):
                        print_tree(entry_path, prefix + ('    ' if is_last else '|   '))
            
            try:
                print_tree(self.download_dir)
            except Exception as e:
                f.write(f"Error generating structure: {e}\n")
            
            f.write("```\n\n")
            
            # Security findings summary
            if security_findings:
                issue_count = sum(len(issues) for file_issues in security_findings.values() for issues in file_issues.values())
                f.write("## Security Issues Summary\n\n")
                f.write(f"Total issues found: {issue_count}\n\n")
                
                # Count by issue type
                issue_types = {}
                for file_findings in security_findings.values():
                    for issue_type, matches in file_findings.items():
                        if issue_type in issue_types:
                            issue_types[issue_type] += len(matches)
                        else:
                            issue_types[issue_type] = len(matches)
                
                # Sort by count
                sorted_issues = sorted(issue_types.items(), key=lambda x: x[1], reverse=True)
                
                f.write("| Issue Type | Count |\n")
                f.write("|------------|-------|\n")
                
                for issue_type, count in sorted_issues:
                    f.write(f"| {issue_type} | {count} |\n")
                
                f.write("\nSee the detailed security report for more information.\n\n")
            else:
                f.write("## Security Issues Summary\n\n")
                f.write("No security issues found.\n\n")
            
            # Most used functions summary
            if function_calls:
                f.write("## Most Used Functions\n\n")
                
                # Sort function calls by count (descending) and take top 10
                sorted_functions = sorted(function_calls.items(), key=lambda x: x[1], reverse=True)[:10]
                
                if sorted_functions:
                    f.write("| Function | Call Count |\n")
                    f.write("|----------|------------|\n")
                    
                    for function, count in sorted_functions:
                        f.write(f"| `{function}` | {count} |\n")
                    
                    f.write("\nSee the detailed function usage report for more information.\n\n")
                else:
                    f.write("No function calls detected.\n\n")
            else:
                f.write("## Function Usage Summary\n\n")
                f.write("No function calls detected.\n\n")
            
            # Recommendations
            f.write("## Recommendations\n\n")
            f.write("Based on the scan results, consider the following recommendations:\n\n")
            
            # Add general recommendations
            f.write("1. **Review Security Issues:** Address any security issues identified in the security report.\n")
            f.write("2. **Update Dependencies:** Check for outdated libraries and update them to the latest secure versions.\n")
            f.write("3. **Input Validation:** Implement proper input validation for all user inputs.\n")
            f.write("4. **Output Encoding:** Use proper output encoding to prevent XSS attacks.\n")
            f.write("5. **Parameterized Queries:** Use parameterized queries to prevent SQL injection.\n")
            f.write("6. **Content Security Policy:** Implement a Content Security Policy to mitigate XSS and other injection attacks.\n")
            f.write("7. **HTTPS:** Ensure the website uses HTTPS with proper certificate configuration.\n")
            f.write("8. **Rate Limiting:** Implement rate limiting to prevent brute force attacks.\n\n")
            
            f.write("## Next Steps\n\n")
            f.write("1. Review the detailed reports for security issues and function usage.\n")
            f.write("2. Perform a manual review of high-risk areas identified in the scan.\n")
            f.write("3. Consider conducting more targeted security tests based on the findings.\n")
        
        logger.info(f"Final report generated: {report_path}")
        # Print discovered versions summary
        detected_versions = scan_info.get('detected_versions', {})
        print(f"[SUMMARY] Discovered software versions: {len(detected_versions)}")
        return report_path
    
    def save_json_data(self, data, filename):
        """
        Save data as JSON
        
        Args:
            data (dict): Data to save
            filename (str): Filename
            
        Returns:
            str: File path
        """
        file_path = os.path.join(self.report_dir, filename)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        
        logger.info(f"JSON data saved: {file_path}")
        return file_path
    
    def generate_sensitive_data_json(self, code_files, visited_urls, base_domain):
        """
        Generate a JSON file containing all found crypto addresses, phone numbers, internal/external links, and IPs.
        
        Args:
            code_files (dict): Dictionary of code files and their contents
            visited_urls (list): List of all URLs visited during scanning
            base_domain (str): The main domain of the target
            
        Returns:
            str: Path to the generated JSON file
        """
        import re
        from urllib.parse import urlparse
        logger.info("Generating sensitive data JSON dump...")

        # Regex patterns
        crypto_patterns = {
            # Bitcoin legacy (1/3...) and bech32 (bc1...)
            'bitcoin': r'\b(?:bc1[a-zA-HJ-NP-Z0-9]{39,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b',
            # Ethereum, BSC, USDT-ERC20
            'ethereum': r'\b0x[a-fA-F0-9]{40}\b',
            # Litecoin (L or M prefix, non-capturing)
            'litecoin': r'\b(?:L|M)[a-km-zA-HJ-NP-Z1-9]{26,33}\b',
            # Dogecoin
            'dogecoin': r'\bD[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}\b',
            # Monero
            'monero': r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b',
            # Ripple (XRP)
            'ripple': r'\br[0-9a-zA-Z]{24,34}\b',
            # Tron, USDT-TRC20
            'tron': r'\bT[a-zA-Z0-9]{33}\b',
            # Dash
            'dash': r'\bX[1-9A-HJ-NP-Za-km-z]{33}\b',
            # Zcash (t-addr)
            'zcash': r'\bt1[a-zA-HJ-NP-Z0-9]{33}\b',
            # Solana
            'solana': r'\b[1-9A-HJ-NP-Za-km-z]{32,44}\b',
            # Cardano Shelley
            'cardano': r'\baddr1[0-9a-z]{53,87}\b',
            # Polkadot
            'polkadot': r'\b1[a-km-zA-HJ-NP-Z1-9]{47}\b',
            # Cosmos
            'cosmos': r'\bcosmos1[0-9a-z]{38}\b',
            # Avalanche X-Chain
            'avalanche': r'\bX-avax1[0-9a-z]{38}\b',
            # Algorand
            'algorand': r'\b[A-Z2-7]{58}\b',
            # Stellar
            'stellar': r'\bG[A-Z2-7]{55}\b',
        }
        # Stricter phone number pattern: requires at least 7 digits, usually 9+ (optionally with country code)
        # Matches numbers like +49 123 4567890, (030) 1234567, 0176-12345678, etc.
        phone_pattern = r"""
        (?:\b|(?<=\D))                # Word boundary or non-digit before
        (?:\+\d{1,3}[\s-]?)?         # Optional country code
        (?:\(?\d{2,4}\)?[\s-]?)?    # Optional area code
        (?:\d[\s-]?){7,}              # At least 7 digits (allowing spaces/dashes)
        (?:\b|(?=\D))                 # Word boundary or non-digit after
        """
        phone_pattern = re.compile(phone_pattern, re.VERBOSE)

        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

        # Collect all text to scan
        all_text = "\n".join(code_files.values())

        # Find crypto addresses (always extract .group(0) for full match)
        crypto_addresses = {}
        for name, pat in crypto_patterns.items():
            matches = [m.group(0) for m in re.finditer(pat, all_text)]
            addr_counts = {}
            for addr in matches:
                addr_counts[addr] = addr_counts.get(addr, 0) + 1
            crypto_addresses[name] = addr_counts

        # Find phone numbers (filter to only those with at least 9 digits)
        raw_phone_numbers = phone_pattern.findall(all_text)
        phone_counts = {}
        for match in raw_phone_numbers:
            digits = re.sub(r'\D', '', match)
            if len(digits) >= 9:
                key = match.strip()
                phone_counts[key] = phone_counts.get(key, 0) + 1

        # Find IP addresses
        ip_matches = re.findall(ip_pattern, all_text)
        ip_counts = {}
        for ip in ip_matches:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

        # Classify links
        internal_links = set()
        external_links = set()
        internal_subdomains = set()
        external_hosts = set()
        for url in visited_urls:
            parsed = urlparse(url)
            if not parsed.netloc:
                continue
            domain = parsed.netloc.lower()
            if domain == base_domain:
                internal_links.add(url)
            elif domain.endswith('.' + base_domain):
                internal_subdomains.add(url)
            else:
                external_links.add(url)
                external_hosts.add(domain)

        sensitive_data = {
            'crypto_addresses': crypto_addresses,
            'phone_numbers': phone_counts,
            'ip_addresses': ip_counts,
            'internal_links': list(sorted(internal_links)),
            'internal_subdomain_links': list(sorted(internal_subdomains)),
            'external_links': list(sorted(external_links)),
            'external_hosts': list(sorted(external_hosts)),
        }

        # Save to JSON file
        json_path = os.path.join(self.report_dir, 'discovered_sensitive_data.json')
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(sensitive_data, f, indent=4)
        logger.info(f"Sensitive data JSON dump generated: {json_path}")
        print(f"[SUMMARY] Sensitive data: {sum(len(v) for v in crypto_addresses.values())} crypto addresses, {len(phone_counts)} phone numbers, {len(ip_counts)} IPs, {len(internal_links)} internal, {len(external_links)} external links")
        return json_path
