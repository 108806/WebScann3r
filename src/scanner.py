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
from colorama import Fore, Style, init
from src.reporter import Reporter
from src.patterns.Dangerous_Sinks import sink_patterns
from src.patterns.Version_Headers import version_headers
from src.patterns.Url_Extraction import js_url_patterns, css_url_patterns, html_url_patterns
from src.patterns.Server_Patterns import server_patterns
from src.patterns.XPowered_Patterns import xpowered_patterns
from src.patterns.Api_Endpoint_Patterns import api_endpoint_patterns
import traceback

# Initialize colorama
init(autoreset=True)

# Custom color formatter for logging
class ColorFormatter(logging.Formatter):
    FORMATS = {
        logging.DEBUG: Fore.WHITE + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + Style.RESET_ALL,
        logging.INFO: Fore.GREEN + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + Style.RESET_ALL,
        logging.WARNING: Fore.YELLOW + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + Style.RESET_ALL,
        logging.ERROR: Fore.RED + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + Style.RESET_ALL,
        logging.CRITICAL: Fore.RED + Style.BRIGHT + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + Style.RESET_ALL
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

# Configure logging with colors
handler = logging.StreamHandler()
handler.setFormatter(ColorFormatter())
file_handler = logging.FileHandler("webscann3r.log")
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

logging.basicConfig(
    level=logging.INFO,
    handlers=[file_handler, handler]
)

logger = logging.getLogger('WebScann3r')

# Load sink_score_map from JSON file
sink_score_map_path = os.path.join(os.path.dirname(__file__), 'patterns', 'sink_score_map.json')
with open(sink_score_map_path, 'r', encoding='utf-8') as f:
    sink_score_map = json.load(f)

class WebScanner:
    def __init__(self, target_url, download_dir='targets', report_dir='targets', same_domain_only=True, 
                 download_media=False, download_archives=False, download_text=False, threads=15, timeout=20,
                 max_depth=3):  # Set default max_depth to 3
        """
        Initialize the web scanner
        
        Args:
            target_url (str): Target URL to scan
            download_dir (str): Base directory to save downloaded files
            report_dir (str): Base directory to save reports
            same_domain_only (bool): Whether to only scan the same domain
            download_media (bool): Whether to download media files
            download_archives (bool): Whether to download archive files
            download_text (bool): Whether to download text files
            threads (int): Number of threads for concurrent requests
            timeout (int): Request timeout in seconds
            max_depth (int): Maximum depth to crawl (default 1)
        """
        self.target_url = target_url
        self.base_domain = urlparse(target_url).netloc
        self.same_domain_only = same_domain_only
        self.max_depth = 1 if max_depth is None else max_depth
        self.download_media = download_media
        self.download_archives = download_archives
        self.download_text = download_text
        self.threads = threads
        self.timeout = timeout
        
        # Create site-specific directories with timestamp
        timestamp = time.strftime('%Y-%m-%d_%H-%M-%S')
        site_dir = f"{self.base_domain.replace(':', '_')}_{timestamp}"
        
        # Directories setup - everything under targets/sitename_timestamp/
        self.target_dir = os.path.abspath(os.path.join(download_dir, site_dir))
        self.download_dir = os.path.abspath(os.path.join(self.target_dir, 'downloads'))
        self.report_dir = os.path.abspath(os.path.join(self.target_dir, 'reports'))
        
        # Create directories if they don't exist
        os.makedirs(self.download_dir, exist_ok=True)
        os.makedirs(self.report_dir, exist_ok=True)
        
        # Set of visited URLs
        self.visited_urls = set()
        
        # Dictionary of code files and their contents
        self.code_files = {}
        
        # Storage for detected software/library versions
        self.detected_versions = {}
        
        # Storage for API endpoints and routes
        self.api_endpoints = set()
        
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
        
        # Initialize session for cookie handling and connection reuse
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
        # Function call counters
        self.function_calls = {}
        
        # Dictionary to store potential sinks
        self.potential_sinks = []
        
        # Counters for download success/failure
        self.successful_downloads = 0
        self.failed_downloads = 0
        self.failed_files = []
        
    def is_valid_url(self, url):
        """
        Validate if URL is properly formatted and safe for processing
        
        Args:
            url (str): URL to validate
            
        Returns:
            bool: True if URL is valid, False otherwise
        """
        try:
            # Basic URL parsing check
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return False
                
            # Check for dangerous characters that could cause filesystem issues
            dangerous_chars = ['<', '>', '|', '&', '?', '*', ':', '"', '\\']
            path = parsed.path
            
            # Allow some regex chars in paths but reject obvious regex patterns
            if any(char in path for char in dangerous_chars):
                return False
                
            # Reject URLs that look like regex patterns - more strict check
            regex_indicators = [r'\[', r'\]', r'\(', r'\)', r'\^', r'\$', r'\+', r'\*', r'\?', r'\.', r'|', r';', r'=', r',']
            if any(indicator in path for indicator in regex_indicators):
                return False
                
            # Reject URLs with suspicious content that looks like JavaScript
            js_indicators = ['function(', 'return', '.fn.', '$.', 'arguments.length', '/g,', '/i,']
            if any(indicator in path for indicator in js_indicators):
                return False
                
            # Reject URLs that are too long (likely malformed)
            if len(url) > 500:  # Reduced from 2000
                return False
                
            # Reject paths that don't look like real URLs
            if len(path) > 200:  # Path itself shouldn't be too long
                return False
                
            return True
        except Exception:
            return False
    
    def start_scan(self):
        """
        Start the scanning process
        """
        logger.info(f"Starting scan on {self.target_url}")
        logger.info(f"Domain scope: {'Same domain only' if self.same_domain_only else 'All domains'}")
        if self.max_depth is not None:
            logger.info(f"Depth limit: {self.max_depth}")
        logger.info(f"Download settings - Media: {self.download_media}, Archives: {self.download_archives}, Text: {self.download_text}")
        
        start_time = time.time()
        
        # Queue of URLs to scan with their depth
        urls_to_scan = [(self.target_url, 0)]  # (url, depth)
        
        # Track URL depths
        self.url_depths = {self.target_url: 0}
        
        # Start scanning
        while urls_to_scan:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                # Prepare new batch of URLs
                current_batch = urls_to_scan[:100]  # Process 100 URLs at a time
                urls_to_scan = urls_to_scan[100:]
                
                # Process URLs in parallel
                future_to_url = {executor.submit(self.process_url, url, depth): (url, depth) for url, depth in current_batch}
                
                for future in future_to_url:
                    url, current_depth = future_to_url[future]
                    try:
                        new_urls = future.result()
                        self.successful_downloads += 1
                        # Add new discovered URLs to the queue if they haven't been visited
                        next_depth = current_depth + 1
                        
                        # Only add URLs if we haven't reached the max depth
                        if self.max_depth is None or next_depth <= self.max_depth:
                            for new_url in new_urls:
                                if new_url not in self.visited_urls and (new_url not in self.url_depths or next_depth < self.url_depths[new_url]):
                                    self.url_depths[new_url] = next_depth
                                    urls_to_scan.append((new_url, next_depth))
                    except Exception as exc:
                        logger.error(f"Error processing {url}: {exc}")
                        traceback.print_exc()
                        self.failed_downloads += 1
                        self.failed_files.append(url)
        
        # After scanning, analyze the code files
        self.analyze_code_files()
        
        end_time = time.time()
        logger.info(f"Scan completed in {end_time - start_time:.2f} seconds")
        logger.info(f"Visited {len(self.visited_urls)} URLs")
        logger.info(f"Downloaded {len(self.code_files)} code files")
        
        # Print download stats
        print(f"\nDownload phase complete: {self.successful_downloads} files downloaded successfully, {self.failed_downloads} errors.")
        if self.failed_files:
            print("Failed files:")
            for f in self.failed_files:
                print(f"  - {f}")
        
        # Generate final report
        self.generate_final_report()
    
    def process_url(self, url, depth=0):
        """
        Process a single URL
        
        Args:
            url (str): URL to process
            depth (int): Current depth of the URL
            
        Returns:
            list: List of new discovered URLs
        """
        if url in self.visited_urls:
            return []
        
        self.visited_urls.add(url)
        logger.info(f"Processing: {url} (depth: {depth})")
        
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                
                # Check for API endpoints using centralized patterns
                url_path = urlparse(url).path.lower()
                if any(pat in url_path for pat in api_endpoint_patterns):
                    self.api_endpoints.add(url)

                # Extract version information from headers
                self.extract_versions_from_headers(response.headers)
                
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
                    discovered_urls = self.extract_urls(url, response.text)
                    # Also check for JavaScript redirects
                    js_redirects = self.handle_javascript_redirects(url, response.text)
                    discovered_urls.extend(js_redirects)
                    # Check for auto-submitting forms
                    form_urls = self.handle_auto_submit_forms(url, response.text)
                    discovered_urls.extend(form_urls)
                    
                    # Special case: IntraWeb applications detection in HTML
                    if 'IntraWeb' in response.text or 'IW_' in response.text or '/$/' in response.text:
                        intraweb_main = urljoin(url, '/$/') 
                        if self.should_process_url(intraweb_main):
                            discovered_urls.append(intraweb_main)
                            logger.info(f"Detected IntraWeb application in HTML, adding main app URL: {intraweb_main}")
                    
                    return discovered_urls
                
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
            
            except requests.exceptions.RequestException as e:
                retry_count += 1
                if retry_count < max_retries:
                    logger.warning(f"Retry {retry_count}/{max_retries} for {url}: {e}")
                    time.sleep(1)  # Wait 1 second before retrying
                else:
                    logger.error(f"Error processing {url} after {max_retries} retries: {e}")
                    traceback.print_exc()
                    return []
            except Exception as e:
                logger.error(f"Error processing {url}: {e}")
                traceback.print_exc()
                return []
    
    def handle_javascript_redirects(self, url, html_content):
        """
        Check for JavaScript redirects and follow them
        
        Args:
            url (str): Current URL
            html_content (str): HTML content to check for redirects
            
        Returns:
            list: List of URLs discovered from redirects
        """
        discovered_urls = []
        
        # Common JavaScript redirect patterns
        js_redirect_patterns = [
            r'window\.location\.replace\([\'"]([^\'"]+)[\'"]\)',
            r'window\.location\.href\s*=\s*[\'"]([^\'"]+)[\'"]',
            r'location\.replace\([\'"]([^\'"]+)[\'"]\)',
            r'location\.href\s*=\s*[\'"]([^\'"]+)[\'"]',
            r'document\.location\s*=\s*[\'"]([^\'"]+)[\'"]',
        ]
        
        for pattern in js_redirect_patterns:
            matches = re.finditer(pattern, html_content, re.IGNORECASE)
            for match in matches:
                redirect_url = match.group(1)
                absolute_url = urljoin(url, redirect_url)
                if self.should_process_url(absolute_url):
                    discovered_urls.append(absolute_url)
                    logger.info(f"Found JS redirect: {redirect_url} -> {absolute_url}")
        
        return discovered_urls
    
    def handle_auto_submit_forms(self, url, html_content):
        """
        Check for auto-submitting forms and simulate their submission
        
        Args:
            url (str): Current URL
            html_content (str): HTML content to check for forms
            
        Returns:
            list: List of URLs discovered from form submissions
        """
        discovered_urls = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            forms = soup.find_all('form')
            
            logger.info(f"Found {len(forms)} forms in {url}")
            
            for form in forms:
                # Check if form has JavaScript auto-submit (init() function call or f.submit())
                logger.info(f"Checking form: {form}")
                has_auto_submit = 'init()' in html_content or 'submit()' in html_content
                logger.info(f"Auto-submit detected: {has_auto_submit}")
                
                if has_auto_submit:
                    action = form.get('action', '')
                    method = form.get('method', 'get').lower()
                    
                    logger.info(f"Found auto-submit form: action={action}, method={method}")
                    
                    if action:
                        form_url = urljoin(url, action)
                        
                        if method == 'post':
                            # Extract form data
                            form_data = {}
                            for input_tag in form.find_all('input'):
                                name = input_tag.get('name')
                                value = input_tag.get('value', '')
                                if name:
                                    # Set default dimensions for width/height fields
                                    if 'width' in name.lower():
                                        value = '1920'
                                    elif 'height' in name.lower():
                                        value = '1080'
                                    form_data[name] = value
                            
                            logger.info(f"Auto-submitting form POST to {form_url} with data: {form_data}")
                            
                            # Submit the form
                            try:
                                response = self.session.post(form_url, data=form_data, timeout=self.timeout, allow_redirects=True)
                                if response.status_code == 200:
                                    # Check if this is a redirect to another page
                                    if response.url != form_url:
                                        logger.info(f"Form submission redirected to: {response.url}")
                                        discovered_urls.append(response.url)
                                    
                                    # Also check for JS redirects in the response
                                    js_redirects = self.handle_javascript_redirects(response.url, response.text)
                                    discovered_urls.extend(js_redirects)
                                    
                            except Exception as e:
                                logger.warning(f"Error submitting form to {form_url}: {e}")
                        
                        elif method == 'get' and self.should_process_url(form_url):
                            discovered_urls.append(form_url)
        
        except Exception as e:
            logger.warning(f"Error processing forms in {url}: {e}")
        
        return discovered_urls
    
    def sanitize_filename(self, filename):
        """
        Sanitize filename by removing or replacing dangerous characters
        
        Args:
            filename (str): Original filename
            
        Returns:
            str: Sanitized filename safe for filesystem
        """
        # Characters that are invalid in Windows filenames
        invalid_chars = ['<', '>', ':', '"', '|', '?', '*', '\\', '/']
        # Additional problematic chars for URLs that became filenames
        problematic_chars = ['[', ']', '(', ')', '^', '$', '+', '&', '%']
        
        sanitized = filename
        
        # Replace invalid chars with underscore
        for char in invalid_chars + problematic_chars:
            sanitized = sanitized.replace(char, '_')
        
        # Remove multiple underscores
        while '__' in sanitized:
            sanitized = sanitized.replace('__', '_')
            
        # Remove leading/trailing underscores and dots
        sanitized = sanitized.strip('_.')
        
        # Ensure it's not empty
        if not sanitized:
            sanitized = "unknown"
            
        # Limit length to avoid filesystem issues
        if len(sanitized) > 200:
            sanitized = sanitized[:200]
            
        return sanitized
    
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
        
        # Sanitize the path to prevent filesystem issues
        path = self.sanitize_filename(path)
        
        # Handle empty paths or just '/'
        if not path or path == '/':
            path = '/index.html'
        
        # Add domain as subdirectory when downloading from external domains
        domain_dir = ''
        if parsed_url.netloc != self.base_domain:
            domain_dir = self.sanitize_filename(parsed_url.netloc.replace(':', '_')) + '/'
        
        file_path = os.path.join(self.download_dir, domain_dir, path.lstrip('/'))

        # If the path ends with a slash or has no extension, treat as directory and append index.html
        if file_path.endswith('/') or not os.path.splitext(file_path)[1]:
            file_path = os.path.join(file_path, 'index.html')
        # If the path contains a file segment followed by another segment (e.g. .../beacon.min.js/v123), treat as a versioned file and join as beacon.min.js_v123
        path_parts = file_path.split(os.sep)
        if len(path_parts) > 2 and '.' in path_parts[-2] and not '.' in path_parts[-1]:
            # e.g. .../beacon.min.js/v123 -> .../beacon.min.js_v123
            file_path = os.sep.join(path_parts[:-2] + [path_parts[-2] + '_' + path_parts[-1]])
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
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                mode = 'wb' if is_binary else 'w'
                encoding = None if is_binary else 'utf-8'
                
                with open(file_path, mode, encoding=encoding) as f:
                    f.write(content)
                
                logger.info(f"Saved: {url} to {file_path}")
                return  # Success, exit the function
            except Exception as e:
                retry_count += 1
                if retry_count < max_retries:
                    logger.warning(f"Retry {retry_count}/{max_retries} saving {url} to {file_path}: {e}")
                    time.sleep(1)  # Wait 1 second before retrying
                else:
                    logger.error(f"Error saving {url} to {file_path} after {max_retries} retries: {e}")
                    return
    
    def format_code_file(self, file_path, extension):
        """
        Format code files using jsbeautifier for JS, HTML, and CSS.
        """
        try:
            import jsbeautifier
            if extension in ['.js', '.html', '.css']:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                opts = jsbeautifier.default_options()
                opts.indent_size = 2
                formatted = jsbeautifier.beautify(content, opts)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(formatted)
            elif extension == '.php':
                # Optionally, add PHP formatting if a Python solution is found
                pass
        except Exception as e:
            logger.warning(f"Could not format {file_path}: {e}")

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
        # Format the file if it's .js, .php, .html, or .css
        extension = os.path.splitext(file_path)[1].lower()
        if extension in ['.js', '.php', '.html', '.css']:
            self.format_code_file(file_path, extension)
        
        # Store the code for analysis
        rel_path = os.path.relpath(file_path, self.download_dir)
        # Try to read the beautified file
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                beautified_content = f.read()
            self.code_files[rel_path] = beautified_content
        except Exception as e:
            logger.warning(f"Could not read beautified file {file_path}: {e}")
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
        from bs4 import Tag
        discovered_urls = []
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
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
                    if isinstance(element, Tag):
                        url = element.get(attr)
                        # Only process if url is a string
                        if isinstance(url, str):
                            absolute_url = urljoin(base_url, url)
                            if self.should_process_url(absolute_url):
                                discovered_urls.append(absolute_url)
                        # If url is a list (multi-valued attribute), process each string
                        elif isinstance(url, list):
                            for u in url:
                                if isinstance(u, str):
                                    absolute_url = urljoin(base_url, u)
                                    if self.should_process_url(absolute_url):
                                        discovered_urls.append(absolute_url)
            # Extract URLs from JavaScript code
            scripts = soup.find_all('script')
            for script in scripts:
                if isinstance(script, Tag) and script.string:
                    js_urls = self.extract_urls_from_js(base_url, script.string)
                    discovered_urls.extend(js_urls)
            # Extract URLs from inline styles
            styles = soup.find_all('style')
            for style in styles:
                if isinstance(style, Tag) and style.string:
                    css_urls = self.extract_urls_from_css(base_url, style.string)
                    discovered_urls.extend(css_urls)
            # Look for URLs in custom attributes
            for element in soup.find_all():
                if isinstance(element, Tag):
                    for attr in element.attrs:
                        if attr.lower() not in ['href', 'src', 'action']:
                            value = element.get(attr)
                            if isinstance(value, str) and (value.startswith('http') or value.startswith('/')):
                                absolute_url = urljoin(base_url, value)
                                if self.should_process_url(absolute_url):
                                    discovered_urls.append(absolute_url)
                            elif isinstance(value, list):
                                for v in value:
                                    if isinstance(v, str) and (v.startswith('http') or v.startswith('/')):
                                        absolute_url = urljoin(base_url, v)
                                        if self.should_process_url(absolute_url):
                                            discovered_urls.append(absolute_url)
        except Exception as e:
            logger.error(f"Error extracting URLs from {base_url}: {e}")
        # Also try to find URLs in JavaScript and CSS content using regex
        js_css_urls = []
        patterns = html_url_patterns
        for pattern in patterns:
            for match in re.finditer(pattern, html_content):
                url = match.group(1)
                absolute_url = urljoin(base_url, url)
                # Validate URL before processing
                if not url or not self.is_valid_url(urljoin(base_url, url)):
                    continue
        discovered_urls.extend(js_css_urls)
        # Remove duplicates and return
        return list(set(discovered_urls))
    
    def extract_versions_from_headers(self, headers):
        """
        Extract version information from HTTP headers
        
        Args:
            headers (dict): HTTP headers to analyze
        """
        # Headers that might contain version information
        # (imported from patterns.Version_Headers for consistency and coverage)
        
        # Check each relevant header
        for header in version_headers:
            if header in headers:
                value = headers[header]
                # Store the version information
                self.detected_versions[f"Header: {header}"] = value
                
                # Try to extract more specific version information with regex
                if header.lower() == 'server':
                    # Use centralized server_patterns from patterns/Server_Patterns.py
                    for pattern in server_patterns:
                        match = re.search(pattern, value, re.IGNORECASE)
                        if match:
                            software = pattern.split('[')[0]
                            version = match.group(1)
                            self.detected_versions[f"{software.capitalize()} Version"] = version
                
                elif header.lower() == 'x-powered-by':
                    # Use centralized xpowered_patterns from patterns/XPowered_Patterns.py
                    for pattern in xpowered_patterns:
                        match = re.search(pattern, value, re.IGNORECASE)
                        if match:
                            technology = pattern.split('[')[0] if '[' in pattern else pattern
                            technology = technology.replace(r'\\.', '.').capitalize()
                            if match.groups():
                                version = match.group(1)
                                self.detected_versions[f"{technology} Version"] = version
                            else:
                                self.detected_versions[technology] = "Detected (version unknown)"
    
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
        patterns = js_url_patterns
        
        for pattern in patterns:
            for match in re.finditer(pattern, js_content):
                try:
                    # Handle patterns with multiple groups (like axios patterns)
                    groups = match.groups()
                    if len(groups) >= 2:
                        # For patterns like axios with method and URL groups
                        url = groups[-1]  # Take the last group as URL
                    elif len(groups) == 1:
                        url = groups[0]
                    else:
                        continue  # Skip if no capturing groups
                        
                    # Validate URL before processing
                    if not url or not self.is_valid_url(urljoin(base_url, url)):
                        continue
                        
                    absolute_url = urljoin(base_url, url)
                    if self.should_process_url(absolute_url):
                        discovered_urls.append(absolute_url)
                except (IndexError, AttributeError) as e:
                    # Skip malformed patterns
                    continue
        
        # Special case: IntraWeb applications - if we see IntraWeb patterns, try /$/
        if 'IntraWeb' in js_content or 'IW_' in js_content or '/$/' in js_content:
            intraweb_main = urljoin(base_url, '/$/') 
            if self.should_process_url(intraweb_main):
                discovered_urls.append(intraweb_main)
                logger.info(f"Detected IntraWeb application, adding main app URL: {intraweb_main}")
        
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
        patterns = css_url_patterns
        
        for pattern in patterns:
            for match in re.finditer(pattern, css_content):
                try:
                    url = match.group(1)
                    
                    # Validate URL before processing
                    if not url or not self.is_valid_url(urljoin(base_url, url)):
                        continue
                        
                    absolute_url = urljoin(base_url, url)
                    if self.should_process_url(absolute_url):
                        discovered_urls.append(absolute_url)
                except (IndexError, AttributeError):
                    # Skip malformed patterns
                    continue
        
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
        print(f"Analyzing {len(self.code_files)} files...")
        analyzed = 0
        total = len(self.code_files)
        # Progress bar only
        for _ in self.code_files.items():
            analyzed += 1
            percent = int((analyzed / total) * 100)
            print(f"\rAnalysis progress: {analyzed}/{total} ({percent}%)", end="")
        print()  # Newline after progress bar

        # Use SecurityAnalyzer for vulnerability detection
        from .analyzer import SecurityAnalyzer
        analyzer = SecurityAnalyzer()
        security_findings = analyzer.analyze_code(self.code_files)

        # Sink detection: look for dangerous function calls and taint sinks (legacy, for sinks.md)
        for file_path, content in self.code_files.items():
            # Count function calls in JS files
            extension = os.path.splitext(file_path)[1].lower()
            if extension == '.js':
                self.count_js_function_calls(content)
            # Sink detection patterns (keep for sinks.md)
            for sink_pat in sink_patterns:
                for match in re.finditer(sink_pat, content):
                    line_number = content[:match.start()].count('\n') + 1
                    code_line = content.splitlines()[line_number - 1].strip()
                    self.potential_sinks.append({
                        'file': file_path,
                        'line': line_number,
                        'sink': match.group(0),
                        'code': code_line
                    })

        # Generate security report using Reporter class (with improved formatting and Berlin time)
        from .reporter import Reporter
        reporter = Reporter(self.target_url, report_dir=self.report_dir, download_dir=self.download_dir)
        reporter.generate_security_report(security_findings)

        # After generating the security report, also generate a sinks report if sinks exist
        if self.potential_sinks:
            # Sort sinks by score descending using the global sink_score_map loaded from JSON
            sorted_sinks = sorted(self.potential_sinks, key=lambda s: self.get_sink_score(s['sink']), reverse=True)

            sinks_report_path = os.path.join(self.report_dir, 'sinks.md')
            with open(sinks_report_path, 'w', encoding='utf-8') as f:
                f.write("# Potential Sinks (Fuzzing Targets)\n\n")
                f.write(f"Total potential sinks detected: {len(self.potential_sinks)}\n\n")
                f.write("| File | Line | Sink Type | Regex Triggered | Potential Sink Score |\n")
                f.write("|------|------|-----------|-----------------|----------------------|\n")
                for sink in sorted_sinks:
                    file = os.path.basename(sink['file'])
                    line = sink['line']
                    sink_type = sink['sink'].split('(')[0].strip().replace('.', '')
                    regex = sink['sink']
                    score = self.get_sink_score(sink['sink'])
                    f.write(f"| `{file}` | {line} | `{sink_type}` | `{regex}` | **{score}** |\n")
                f.write("\n---\n\n")
                f.write("**Legend:** Higher score = more dangerous sink.\n\n")
                f.write("---\n\n")
                f.write("**This is a summary. For code context, review the source files directly.**\n")
            # Add a reference to sinks.md in the security report for easier navigation
            security_report_path = os.path.join(self.report_dir, 'security_report.md')
            with open(security_report_path, 'a', encoding='utf-8') as f:
                f.write("\n---\n**See [sinks.md](sinks.md) for a summary of potential sink findings.**\n\n")
        # Generate function usage report
        self.generate_function_usage_report()
    
    def get_sink_score(self, sink_name):
        """
        Return the score for a given sink name based on the sink_score_map loaded from JSON.
        """
        for key in sink_score_map:
            if key in sink_name:
                return sink_score_map[key]
        return 5  # Default score if not found
    
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
    
    def generate_endpoints_json(self):
        """
        Generate a JSON file containing all discovered API endpoints
        """
        logger.info("Generating API endpoints JSON dump...")
        
        # Get all discovered endpoints
        endpoints_data = {
            "target_url": self.target_url,
            "base_domain": self.base_domain,
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "endpoints": sorted(list(self.api_endpoints)),
            "count": len(self.api_endpoints)
        }
        
        # Categorize endpoints by path segments
        endpoint_categories = {}
        for endpoint in self.api_endpoints:
            parsed = urlparse(endpoint)
            path = parsed.path
            
            # Group by first part of path after domain
            parts = path.strip('/').split('/')
            if parts:
                category = parts[0] if parts[0] else "root"
                if category not in endpoint_categories:
                    endpoint_categories[category] = []
                endpoint_categories[category].append(endpoint)
        
        endpoints_data["categories"] = endpoint_categories
        
        # Save to JSON file
        json_path = os.path.join(self.report_dir, 'discovered_endpoints.json')
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(endpoints_data, f, indent=4)
        
        logger.info(f"API endpoints JSON dump generated: {json_path}")
        return json_path
    
    def generate_versions_json(self):
        """
        Generate a JSON file containing all discovered software and library versions
        """
        logger.info("Generating software versions JSON dump...")
        
        # Get all discovered versions
        versions_data = {
            "target_url": self.target_url,
            "base_domain": self.base_domain,
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "versions": self.detected_versions,
            "count": len(self.detected_versions)
        }
        
        # Categorize versions
        version_categories = {
            "server": {},
            "framework": {},
            "language": {},
            "database": {},
            "frontend": {},
            "cms": {},
            "other": {}
        }
        
        # Categorize the detected versions
        for software, version in self.detected_versions.items():
            # Server software
            if any(server in software.lower() for server in ['apache', 'nginx', 'iis', 'lighttpd', 'caddy']):
                version_categories['server'][software] = version
            # Frameworks
            elif any(framework in software.lower() for framework in ['laravel', 'symfony', 'django', 'rails', 'express']):
                version_categories['framework'][software] = version
            # Languages
            elif any(language in software.lower() for language in ['php', 'python', 'ruby', 'node', 'asp.net']):
                version_categories['language'][software] = version
            # Databases
            elif any(db in software.lower() for db in ['mysql', 'postgresql', 'mongodb', 'redis', 'oracle']):
                version_categories['database'][software] = version
            # Frontend libraries
            elif any(frontend in software.lower() for frontend in ['jquery', 'bootstrap', 'angular', 'react', 'vue']):
                version_categories['frontend'][software] = version
            # CMS
            elif any(cms in software.lower() for cms in ['wordpress', 'drupal', 'joomla']):
                version_categories['cms'][software] = version
            # Others
            else:
                version_categories['other'][software] = version
        
        versions_data["categories"] = version_categories
        
        # Save to JSON file
        json_path = os.path.join(self.report_dir, 'discovered_versions.json')
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(versions_data, f, indent=4)
        
        logger.info(f"Software versions JSON dump generated: {json_path}")
        return json_path
    
    def generate_files_directories_json(self):
        """
        Generate a JSON file containing all discovered files and directories
        """
        logger.info("Generating files and directories JSON dump...")
        
        # Get all discovered files and directories
        files_dirs = {
            "target_url": self.target_url,
            "base_domain": self.base_domain,
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "visited_urls": list(self.visited_urls),
            "downloaded_files": list(self.code_files.keys()),
            "directories": []
        }
        
        # Create a set of unique directory paths from all downloaded files
        dir_set = set()
        for file_path in self.code_files.keys():
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
        return json_path

    def generate_final_report(self):
        """
        Generate a final comprehensive report
        """
        logger.info("Generating final report...")
        
        # First, generate the JSON dumps
        files_dirs_json = self.generate_files_directories_json()
        endpoints_json = self.generate_endpoints_json()
        versions_json = self.generate_versions_json()
        
        report_path = os.path.join(self.report_dir, 'final_report.md')
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("# WebScann3r Final Report\n\n")
            f.write(f"**Target:** {self.target_url}\n")
            f.write(f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Scan Directory:** {self.target_dir}\n\n")
            
            f.write("## Site Structure\n\n")
            f.write("```\n")
            
            # Create a tree structure of the downloaded files
            def print_tree(dir_path, prefix=""):
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
            
            # Potential Sinks summary
            if self.potential_sinks:
                f.write("## Potential Sinks Summary\n\n")
                f.write(f"**Total Potential Sinks Detected:** {len(self.potential_sinks)}\n\n")
                # Show up to 5 sample sinks
                sample_sinks = self.potential_sinks[:5]
                if sample_sinks:
                    f.write("### Sample Sinks\n\n")
                    for sink in sample_sinks:
                        f.write(f"- `{sink['file']}` (line {sink['line']}): `{sink['sink']}`\n")
                    if len(self.potential_sinks) > 5:
                        f.write(f"\n...and {len(self.potential_sinks) - 5} more. See the detailed security report for more information.\n\n")
            else:
                f.write("## Potential Sinks Summary\n\nNo potential sinks detected.\n\n")

            # Security findings summary (TLDR only)
            security_report_path = os.path.join(self.report_dir, 'security_report.md');
            if os.path.exists(security_report_path):
                with open(security_report_path, 'r', encoding='utf-8') as sr:
                    security_report = sr.read();
                    # Extract just the summary line (total issues found)
                    if "Total issues found:" in security_report:
                        summary_line = [line for line in security_report.splitlines() if line.strip().startswith("Total issues found:")];
                        if summary_line:
                            f.write("## Security Issues Summary\n\n");
                            f.write(f"{summary_line[0]}\n\n");
                            f.write("See the detailed security report for more information.\n\n");
            # Most used functions summary
            function_report_path = os.path.join(self.report_dir, 'function_usage_report.md');
            if os.path.exists(function_report_path):
                f.write("## Most Used Functions\n\n");
                
                # Sort function calls by count (descending) and take top 10
                sorted_functions = sorted(self.function_calls.items(), key=lambda x: x[1], reverse=True)[:10];
                
                if sorted_functions:
                    f.write("| Function | Call Count |\n");
                    f.write("|----------|------------|\n");
                    
                    for function, count in sorted_functions:
                        f.write(f"| `{function}` | {count} |\n");
                    
                    f.write("\nSee the detailed function usage report for more information.\n\n");
                else:
                    f.write("No function calls detected.\n\n");
            
            # API Endpoints summary
            if self.api_endpoints:
                f.write("## API Endpoints Summary\n\n");
                f.write(f"**Total API Endpoints Found:** {len(self.api_endpoints)}\n\n");
                
                # Display up to 10 endpoints
                endpoints_to_show = sorted(list(self.api_endpoints))[:10];
                if endpoints_to_show:
                    f.write("### Sample Endpoints\n\n");
                    for endpoint in endpoints_to_show:
                        f.write(f"- `{endpoint}`\n");
                    
                    if len(self.api_endpoints) > 10:
                        f.write(f"\n...and {len(self.api_endpoints) - 10} more. See the detailed API endpoints JSON file for complete listing.\n\n");
            
            # Software versions summary
            if self.detected_versions:
                f.write("## Software Versions Summary\n\n");
                f.write(f"**Total Software/Library Versions Detected:** {len(self.detected_versions)}\n\n");
                
                # Group by category
                server_versions = {k: v for k, v in self.detected_versions.items() if any(server in k.lower() for server in ['server', 'apache', 'nginx', 'iis'])};
                language_versions = {k: v for k, v in self.detected_versions.items() if any(lang in k.lower() for lang in ['php', 'python', 'ruby', 'node'])};
                framework_versions = {k: v for k, v in self.detected_versions.items() if any(fw in k.lower() for fw in ['laravel', 'symfony', 'django', 'rails', 'express'])};
                
                if server_versions:
                    f.write("### Server Software\n\n");
                    for software, version in server_versions.items():
                        f.write(f"- **{software}:** {version}\n");
                    f.write("\n");
                
                if language_versions:
                    f.write("### Programming Languages\n\n");
                    for software, version in language_versions.items():
                        f.write(f"- **{software}:** {version}\n");
                    f.write("\n");
                
                if framework_versions:
                    f.write("### Frameworks\n\n");
                    for software, version in framework_versions.items():
                        f.write(f"- **{software}:** {version}\n");
                    f.write("\n");
                
                if len(self.detected_versions) > len(server_versions) + len(language_versions) + len(framework_versions):
                    f.write("See the complete software versions JSON file for more details.\n\n");
            
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
        
        # --- Generate sensitive data JSON at the end of the scan ---
        reporter = Reporter(self.target_url, report_dir=self.report_dir, download_dir=self.download_dir)
        reporter.generate_sensitive_data_json(self.code_files, list(self.visited_urls), self.base_domain)
        logger.info("Sensitive data JSON report generated at the end of scan.")
