#!/usr/bin/env python3

import os
import re
import requests
from urllib.parse import urlparse, urljoin
import logging
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import json
import time
from pathlib import Path
from collections import Counter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("webscann3r.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('WebScann3r')

class WebScanner:
    def __init__(self, target_url, download_dir='downloads', report_dir='reports', same_domain_only=True, 
                 download_media=False, download_archives=False, download_text=False, threads=10, timeout=30):
        """
        Initialize the web scanner
        
        Args:
            target_url (str): Target URL to scan
            download_dir (str): Directory to save downloaded files
            report_dir (str): Directory to save reports
            same_domain_only (bool): Whether to only scan the same domain
            download_media (bool): Whether to download media files
            download_archives (bool): Whether to download archive files
            download_text (bool): Whether to download text files
            threads (int): Number of threads for concurrent requests
            timeout (int): Request timeout in seconds
        """
        self.target_url = target_url
        self.base_domain = urlparse(target_url).netloc
        self.same_domain_only = same_domain_only
        self.download_media = download_media
        self.download_archives = download_archives
        self.download_text = download_text
        self.threads = threads
        self.timeout = timeout
        
        # Directories setup
        self.download_dir = os.path.abspath(download_dir)
        self.report_dir = os.path.abspath(report_dir)
        
        # Create directories if they don't exist
        os.makedirs(self.download_dir, exist_ok=True)
        os.makedirs(self.report_dir, exist_ok=True)
        
        # Set of visited URLs
        self.visited_urls = set()
        
        # Dictionary of code files and their contents
        self.code_files = {}
        
        # File extensions to analyze
        self.code_extensions = ('.js', '.php', '.css', '.html')
        
        # Media extensions to skip unless download_media is True
        self.media_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.mp3', '.mp4', '.avi', '.mov', '.webm')
        
        # Archive extensions to skip unless download_archives is True
        self.archive_extensions = ('.zip', '.rar', '.tar', '.gz', '.7z')
        
        # Text extensions to skip unless download_text is True
        self.text_extensions = ('.txt', '.md', '.csv', '.json', '.xml')
        
        # Exception for robots.txt
        self.special_files = ['robots.txt']
        
        # User agent to mimic a regular browser
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
        }
        
        # Function call counters
        self.function_calls = {}
        
    def start_scan(self):
        """
        Start the scanning process
        """
        logger.info(f"Starting scan on {self.target_url}")
        logger.info(f"Domain scope: {'Same domain only' if self.same_domain_only else 'All domains'}")
        logger.info(f"Download settings - Media: {self.download_media}, Archives: {self.download_archives}, Text: {self.download_text}")
        
        start_time = time.time()
        
        # Queue of URLs to scan
        urls_to_scan = [self.target_url]
        
        # Start scanning
        while urls_to_scan:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                # Prepare new batch of URLs
                current_batch = urls_to_scan[:100]  # Process 100 URLs at a time
                urls_to_scan = urls_to_scan[100:]
                
                # Process URLs in parallel
                future_to_url = {executor.submit(self.process_url, url): url for url in current_batch}
                
                for future in future_to_url:
                    url = future_to_url[future]
                    try:
                        new_urls = future.result()
                        # Add new discovered URLs to the queue if they haven't been visited
                        for new_url in new_urls:
                            if new_url not in self.visited_urls:
                                urls_to_scan.append(new_url)
                    except Exception as exc:
                        logger.error(f"Error processing {url}: {exc}")
        
        # After scanning, analyze the code files
        self.analyze_code_files()
        
        end_time = time.time()
        logger.info(f"Scan completed in {end_time - start_time:.2f} seconds")
        logger.info(f"Visited {len(self.visited_urls)} URLs")
        logger.info(f"Downloaded {len(self.code_files)} code files")
        
        # Generate final report
        self.generate_final_report()
    
    def process_url(self, url):
        """
        Process a single URL
        
        Args:
            url (str): URL to process
            
        Returns:
            list: List of new discovered URLs
        """
        if url in self.visited_urls:
            return []
        
        self.visited_urls.add(url)
        logger.info(f"Processing: {url}")
        
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            
            if response.status_code != 200:
                logger.warning(f"Received status code {response.status_code} for {url}")
                return []
            
            # Parse the URL
            parsed_url = urlparse(url)
            
            # Check if we should download this file
            content_type = response.headers.get('Content-Type', '').lower()
            file_path = self.get_file_path(url)
            
            # Handle based on content type and extension
            if any(ext in file_path.lower() for ext in self.code_extensions):
                # Handle code files
                self.save_and_store_code(url, response.text, file_path)
                # Extract URLs from code files as well
                return self.extract_urls(url, response.text)
            
            elif 'text/html' in content_type:
                # Handle HTML pages
                self.save_and_store_code(url, response.text, file_path)
                return self.extract_urls(url, response.text)
            
            elif any(file in url.lower() for file in self.special_files):
                # Handle special files like robots.txt
                self.save_and_store_code(url, response.text, file_path)
                return []
            
            elif any(ext in file_path.lower() for ext in self.media_extensions) and self.download_media:
                # Handle media files if allowed
                self.save_file(url, response.content, file_path, is_binary=True)
                return []
            
            elif any(ext in file_path.lower() for ext in self.archive_extensions) and self.download_archives:
                # Handle archive files if allowed
                self.save_file(url, response.content, file_path, is_binary=True)
                return []
            
            elif any(ext in file_path.lower() for ext in self.text_extensions) and self.download_text:
                # Handle text files if allowed
                self.save_and_store_code(url, response.text, file_path)
                return []
            
            return []
        
        except Exception as e:
            logger.error(f"Error processing {url}: {e}")
            return []
    
    def get_file_path(self, url):
        """
        Generate a file path from a URL
        
        Args:
            url (str): URL to convert to a file path
            
        Returns:
            str: File path
        """
        parsed_url = urlparse(url)
        
        # Get the path from the URL
        path = parsed_url.path
        
        # Handle empty paths or just '/'
        if not path or path == '/':
            path = '/index.html'
        
        # Add domain as subdirectory when downloading from external domains
        domain_dir = ''
        if parsed_url.netloc != self.base_domain:
            domain_dir = parsed_url.netloc.replace(':', '_') + '/'
        
        file_path = os.path.join(self.download_dir, domain_dir, path.lstrip('/'))
        
        # Create the directory if it doesn't exist
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        return file_path
    
    def save_file(self, url, content, file_path, is_binary=False):
        """
        Save file to disk
        
        Args:
            url (str): URL of the file
            content (str or bytes): Content to save
            file_path (str): Path to save the file to
            is_binary (bool): Whether the content is binary
        """
        try:
            mode = 'wb' if is_binary else 'w'
            encoding = None if is_binary else 'utf-8'
            
            with open(file_path, mode, encoding=encoding) as f:
                f.write(content)
            
            logger.info(f"Saved: {url} to {file_path}")
        except Exception as e:
            logger.error(f"Error saving {url} to {file_path}: {e}")
    
    def save_and_store_code(self, url, content, file_path):
        """
        Save code file and store it for later analysis
        
        Args:
            url (str): URL of the file
            content (str): Content to save
            file_path (str): Path to save the file to
        """
        # Save the file
        self.save_file(url, content, file_path)
        
        # Store the code for analysis
        rel_path = os.path.relpath(file_path, self.download_dir)
        self.code_files[rel_path] = content
    
    def extract_urls(self, base_url, html_content):
        """
        Extract URLs from HTML content
        
        Args:
            base_url (str): Base URL for resolving relative URLs
            html_content (str): HTML content to extract URLs from
            
        Returns:
            list: List of discovered URLs
        """
        discovered_urls = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract URLs from different tags and attributes
            url_patterns = [
                ('a', 'href'),
                ('script', 'src'),
                ('link', 'href'),
                ('img', 'src'),
                ('source', 'src'),
                ('form', 'action'),
                ('iframe', 'src'),
            ]
            
            for tag, attr in url_patterns:
                for element in soup.find_all(tag):
                    url = element.get(attr)
                    if url:
                        absolute_url = urljoin(base_url, url)
                        if self.should_process_url(absolute_url):
                            discovered_urls.append(absolute_url)
            
            # Extract URLs from JavaScript code
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    js_urls = self.extract_urls_from_js(base_url, script.string)
                    discovered_urls.extend(js_urls)
            
            # Extract URLs from inline styles
            styles = soup.find_all('style')
            for style in styles:
                if style.string:
                    css_urls = self.extract_urls_from_css(base_url, style.string)
                    discovered_urls.extend(css_urls)
                    
            # Additionally, look for URLs in custom attributes that might contain URLs
            for element in soup.find_all():
                for attr in element.attrs:
                    if attr.lower() not in ['href', 'src', 'action']:
                        value = element.get(attr)
                        if isinstance(value, str) and (value.startswith('http') or value.startswith('/')):
                            absolute_url = urljoin(base_url, value)
                            if self.should_process_url(absolute_url):
                                discovered_urls.append(absolute_url)
        
        except Exception as e:
            logger.error(f"Error extracting URLs from {base_url}: {e}")
        
        # Also try to find URLs in JavaScript and CSS content using regex
        js_css_urls = []
        url_patterns = [
            r'(https?://[^\s\'"<>()]+)',  # HTTP URLs
            r'(\/[a-zA-Z0-9_\-\/\.]+\.(?:js|css|php|html|htm))',  # Relative paths with extensions
        ]
        
        for pattern in url_patterns:
            for match in re.finditer(pattern, html_content):
                url = match.group(1)
                absolute_url = urljoin(base_url, url)
                if self.should_process_url(absolute_url):
                    js_css_urls.append(absolute_url)
        
        discovered_urls.extend(js_css_urls)
        
        # Remove duplicates and return
        return list(set(discovered_urls))
    
    def extract_urls_from_js(self, base_url, js_content):
        """
        Extract URLs from JavaScript content
        
        Args:
            base_url (str): Base URL for resolving relative URLs
            js_content (str): JavaScript content to extract URLs from
            
        Returns:
            list: List of discovered URLs
        """
        discovered_urls = []
        
        if not js_content:
            return discovered_urls
        
        # Common patterns in JavaScript where URLs might be found
        patterns = [
            r'(https?://[^\s\'"<>()]+)',  # HTTP URLs
            r'[\'"]([\/][^\'"]*\.(js|css|php|html|htm))[\'"]',  # Quoted paths with extensions
            r'[\'"]([\/][a-zA-Z0-9_\-\/\.]+)[\'"]',  # Quoted paths
            r'fetch\([\'"]([^\'"]+)[\'"]\)',  # fetch API calls
            r'xhr\.open\([\'"]GET[\'"], [\'"]([^\'"]+)[\'"]',  # XHR requests
            r'axios\.get\([\'"]([^\'"]+)[\'"]\)',  # axios requests
            r'\.ajax\(\{\s*url:\s*[\'"]([^\'"]+)[\'"]',  # jQuery AJAX calls
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, js_content):
                url = match.group(1)
                absolute_url = urljoin(base_url, url)
                if self.should_process_url(absolute_url):
                    discovered_urls.append(absolute_url)
        
        # Analyze function calls in JS and count them
        self.count_js_function_calls(js_content)
        
        return list(set(discovered_urls))
    
    def extract_urls_from_css(self, base_url, css_content):
        """
        Extract URLs from CSS content
        
        Args:
            base_url (str): Base URL for resolving relative URLs
            css_content (str): CSS content to extract URLs from
            
        Returns:
            list: List of discovered URLs
        """
        discovered_urls = []
        
        if not css_content:
            return discovered_urls
        
        # Common patterns in CSS where URLs might be found
        patterns = [
            r'url\([\'"]?([^\'"<>()]+)[\'"]?\)',  # CSS url() function
            r'@import\s+[\'"]([^\'"]+)[\'"]',  # CSS @import rule
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, css_content):
                url = match.group(1)
                absolute_url = urljoin(base_url, url)
                if self.should_process_url(absolute_url):
                    discovered_urls.append(absolute_url)
        
        return list(set(discovered_urls))
    
    def should_process_url(self, url):
        """
        Check if a URL should be processed
        
        Args:
            url (str): URL to check
            
        Returns:
            bool: Whether the URL should be processed
        """
        # Skip already visited URLs
        if url in self.visited_urls:
            return False
        
        # Parse the URL
        parsed_url = urlparse(url)
        
        # Skip URLs with unsupported schemes
        if parsed_url.scheme not in ['http', 'https']:
            return False
        
        # Skip fragments within the same page
        if not parsed_url.netloc and parsed_url.fragment:
            return False
        
        # Check domain scope
        if self.same_domain_only and parsed_url.netloc and parsed_url.netloc != self.base_domain:
            return False
        
        # Check file extensions
        path = parsed_url.path.lower()
        
        # Always process code files
        if any(path.endswith(ext) for ext in self.code_extensions):
            return True
        
        # Always process special files
        if any(file in path for file in self.special_files):
            return True
        
        # Skip media files unless allowed
        if any(path.endswith(ext) for ext in self.media_extensions) and not self.download_media:
            return False
        
        # Skip archive files unless allowed
        if any(path.endswith(ext) for ext in self.archive_extensions) and not self.download_archives:
            return False
        
        # Skip text files unless allowed
        if any(path.endswith(ext) for ext in self.text_extensions) and not self.download_text:
            return False
        
        return True
    
    def count_js_function_calls(self, js_content):
        """
        Count function calls in JavaScript content
        
        Args:
            js_content (str): JavaScript content to analyze
        """
        # Pattern to find function calls: name(args)
        pattern = r'(\w+)\s*\('
        
        for match in re.finditer(pattern, js_content):
            function_name = match.group(1)
            
            # Skip common JavaScript keywords
            if function_name in ['if', 'for', 'while', 'switch', 'catch']:
                continue
            
            # Count function calls
            if function_name in self.function_calls:
                self.function_calls[function_name] += 1
            else:
                self.function_calls[function_name] = 1
    
    def analyze_code_files(self):
        """
        Analyze downloaded code files for security issues and function usage
        """
        logger.info("Starting code analysis...")
        
        # Security patterns to look for
        security_patterns = {
            'SQL Injection': [
                r'(?i)(?:execute|exec)\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*=\s*[\'"].*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)INSERT\s+INTO\s+.*\s+VALUES\s*\(.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)UPDATE\s+.*\s+SET\s+.*=.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)DELETE\s+FROM\s+.*\s+WHERE\s+.*=.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)(?:mysql|mysqli|pdo)_query\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
            ],
            'XSS': [
                r'(?i)document\.write\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)\.innerHTML\s*=\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)\.outerHTML\s*=\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)eval\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)setTimeout\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)setInterval\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)new\s+Function\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
            ],
            'Command Injection': [
                r'(?i)(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\(\s*.*\+',
                r'(?i)spawn\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)child_process\.exec\s*\(\s*.*\+',
            ],
            'File Inclusion': [
                r'(?i)(?:include|require|include_once|require_once)\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)fopen\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)file_get_contents\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'(?i)readfile\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)',
            ],
            'Insecure Crypto': [
                r'(?i)md5\s*\(',
                r'(?i)sha1\s*\(',
                r'(?i)crypt\s*\(',
                r'(?i)CryptoJS\.MD5',
                r'(?i)CryptoJS\.SHA1',
            ],
            'Hardcoded Credentials': [
                r'(?i)(?:password|passwd|pwd|token|secret|api_key|apikey)\s*=\s*[\'"][^\'"]+[\'"]',
                r'(?i)Authorization:\s*Basic\s+[a-zA-Z0-9+/=]+',
                r'(?i)Authorization:\s*Bearer\s+[a-zA-Z0-9._~+/=-]+',
                r'(?i)(?:access_key|access_token|secret_key|api_key|apikey)\s*[=:]\s*[\'"][^\'"]{8,}[\'"]',
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
            ],
        }
        
        # Dictionary to store security findings
        security_findings = {}
        
        # Analyze each code file
        for file_path, content in self.code_files.items():
            file_findings = {}
            
            # Analyze based on file extension
            extension = os.path.splitext(file_path.lower())[1]
            
            # Check for security issues
            for issue_type, patterns in security_patterns.items():
                matches = []
                
                for pattern in patterns:
                    for match in re.finditer(pattern, content):
                        line_number = content[:match.start()].count('\n') + 1
                        line = content.splitlines()[line_number - 1].strip()
                        matches.append({
                            'line': line_number,
                            'code': line,
                            'match': match.group(0),
                        })
                
                if matches:
                    file_findings[issue_type] = matches
            
            if file_findings:
                security_findings[file_path] = file_findings
            
            # Count function calls in JS files
            if extension == '.js':
                self.count_js_function_calls(content)
        
        # Generate security report
        self.generate_security_report(security_findings)
        
        # Generate function usage report
        self.generate_function_usage_report()
    
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
    
    def generate_function_usage_report(self):
        """
        Generate a report on function usage
        """
        logger.info("Generating function usage report...")
        
        report_path = os.path.join(self.report_dir, 'function_usage_report.md')
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("# WebScann3r Function Usage Report\n\n")
            f.write(f"**Target:** {self.target_url}\n")
            f.write(f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            if not self.function_calls:
                f.write("No function calls detected.\n")
            else:
                f.write("## Function Calls\n\n")
                
                # Sort function calls by count (descending)
                sorted_functions = sorted(self.function_calls.items(), key=lambda x: x[1], reverse=True)
                
                f.write("| Function | Call Count |\n")
                f.write("|----------|------------|\n")
                
                for function, count in sorted_functions:
                    f.write(f"| `{function}` | {count} |\n")
        
        logger.info(f"Function usage report generated: {report_path}")
    
    def generate_final_report(self):
        """
        Generate a final comprehensive report
        """
        logger.info("Generating final report...")
        
        report_path = os.path.join(self.report_dir, 'final_report.md')
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("# WebScann3r Final Report\n\n")
            f.write(f"**Target:** {self.target_url}\n")
            f.write(f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## Scan Summary\n\n")
            f.write(f"- **Scan Mode:** {'Same domain only' if self.same_domain_only else 'All domains'}\n")
            f.write(f"- **URLs Visited:** {len(self.visited_urls)}\n")
            f.write(f"- **Files Downloaded:** {len(self.code_files)}\n")
            f.write(f"- **Download Settings:**\n")
            f.write(f"  - **Media Files:** {'Yes' if self.download_media else 'No'}\n")
            f.write(f"  - **Archive Files:** {'Yes' if self.download_archives else 'No'}\n")
            f.write(f"  - **Text Files:** {'Yes' if self.download_text else 'No'}\n\n")
            
            # Structure map
            f.write("## Site Structure\n\n")
            f.write("```\n")
            
            # Create a tree structure of the downloaded files
            def print_tree(dir_path, prefix=""):
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
            security_report_path = os.path.join(self.report_dir, 'security_report.md')
            if os.path.exists(security_report_path):
                with open(security_report_path, 'r', encoding='utf-8') as sr:
                    security_report = sr.read()
                    
                    # Extract just the summary
                    if "## Security Issues Found" in security_report:
                        summary = security_report.split("## Security Issues Found")[1].split("###")[0].strip()
                        f.write("## Security Issues Summary\n\n")
                        f.write(f"{summary}\n\n")
                        f.write("See the detailed security report for more information.\n\n")
            
            # Most used functions summary
            function_report_path = os.path.join(self.report_dir, 'function_usage_report.md')
            if os.path.exists(function_report_path):
                f.write("## Most Used Functions\n\n")
                
                # Sort function calls by count (descending) and take top 10
                sorted_functions = sorted(self.function_calls.items(), key=lambda x: x[1], reverse=True)[:10]
                
                if sorted_functions:
                    f.write("| Function | Call Count |\n")
                    f.write("|----------|------------|\n")
                    
                    for function, count in sorted_functions:
                        f.write(f"| `{function}` | {count} |\n")
                    
                    f.write("\nSee the detailed function usage report for more information.\n\n")
                else:
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
