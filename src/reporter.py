#!/usr/bin/env python3

import os
import time
import logging
import json
from pathlib import Path

logger = logging.getLogger('WebScann3r.Reporter')

class Reporter:
    def __init__(self, target_url, report_dir='reports', download_dir='downloads'):
        """
        Initialize the reporter
        
        Args:
            target_url (str): Target URL
            report_dir (str): Directory to save reports
            download_dir (str): Directory where files were downloaded
        """
        self.target_url = target_url
        self.report_dir = os.path.abspath(report_dir)
        self.download_dir = os.path.abspath(download_dir)
        
        # Create report directory if it doesn't exist
        os.makedirs(self.report_dir, exist_ok=True)
    
    def generate_security_report(self, security_findings):
        """
        Generate a security report based on findings
        
        Args:
            security_findings (dict): Dictionary of security findings
        """
        logger.info("Generating security report...")
        
        report_path = os.path.join(self.report_dir, 'security_report.md')
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("# WebScann3r Security Report\n\n")
            f.write(f"**Target:** {self.target_url}\n")
            f.write(f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            if not security_findings:
                f.write("No security issues found.\n")
            else:
                f.write("## Security Issues Found\n\n")
                
                issue_count = sum(len(issues) for file_issues in security_findings.values() for issues in file_issues.values())
                f.write(f"Total issues found: {issue_count}\n\n")
                
                for file_path, file_findings in security_findings.items():
                    f.write(f"### {file_path}\n\n")
                    
                    for issue_type, matches in file_findings.items():
                        f.write(f"#### {issue_type}\n\n")
                        
                        for match in matches:
                            f.write(f"- **Line {match['line']}:** `{match['code']}`\n")
                            f.write(f"  - **Match:** `{match['match']}`\n\n")
        
        logger.info(f"Security report generated: {report_path}")
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
            
            # Structure map
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
                    
                    f.write(f"{prefix}{'└── ' if is_last else '├── '}{entry}\n")
                    
                    if os.path.isdir(entry_path):
                        print_tree(entry_path, prefix + ('    ' if is_last else '│   '))
            
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
