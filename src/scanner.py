#!/usr/bin/env python3

import os
import re
import threading
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
            max_depth (int): Maximum depth to crawl (default 3)
        """
        self.target_url = target_url
        self.base_domain = urlparse(target_url).netloc
        self.same_domain_only = same_domain_only
        self.max_depth = 3 if max_depth is None else max_depth
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
        
        # Rotate user agents so consecutive scans don't share a fingerprint.
        # Strings sourced from real browser release channels (2024-2025).
        _user_agents = [
            # Chrome — Windows
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
            # Chrome — macOS
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
            # Firefox — Windows
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
            # Firefox — macOS
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0',
            # Safari — macOS
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
            # Edge — Windows
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0',
            # Chrome — Linux
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            # Firefox — Linux
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0',
        ]
        import random
        self.headers = {
            'User-Agent': random.choice(_user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
        }
        logger.info(f"User-Agent: {self.headers['User-Agent']}")
        
        # Initialize session for cookie handling and connection reuse
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
        # Function call counters
        self.function_calls = {}
        
        # Dictionary to store potential sinks
        self.potential_sinks = []
        
        # Fix #5: lock for thread-safe URL deduplication
        self._visited_lock = threading.Lock()

        # Counters for download success/failure
        self.successful_downloads = 0
        self.failed_downloads = 0
        self.failed_files = []

        # Maps relative file path → original URL (used by security_report URL annotations)
        self.file_url_map = {}
        # All forms found during crawl for forms_inventory.md
        self.forms_found = []
        # HTTP security header issues per URL for http_headers_report.md
        self.security_headers_issues = {}
        
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

            # Reject paths containing regex/JS metacharacters that never appear in real URLs
            # (these are literal single characters, NOT escaped sequences)
            regex_indicators = ['[', ']', '(', ')', '^', '|', ';', '{', '}']
            if any(char in path for char in regex_indicators):
                return False

            # Reject URLs with suspicious content that looks like JavaScript
            js_indicators = ['function(', '.fn.', '$.', 'arguments.length', '/g,', '/i,']
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
        # Fix #5: atomic check-and-add prevents two threads processing the same URL
        with self._visited_lock:
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
                # Record missing/weak security headers
                self.check_security_headers(url, response.headers)

                if response.status_code != 200:
                    logger.warning(f"Received status code {response.status_code} for {url}")
                    return []
                
                # Parse the URL
                parsed_url = urlparse(url)
                
                # Check if we should download this file
                content_type = response.headers.get('Content-Type', '').lower()
                file_path = self.get_file_path(url)
                
                # Handle based on content type and extension
                if any(file_path.lower().endswith(ext) for ext in self.code_extensions):
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

                    # Collect all forms for forms_inventory.md
                    self.extract_forms(url, response.text)

                    return discovered_urls
                
                elif any(file in url.lower() for file in self.special_files):
                    # Handle special files like robots.txt
                    self.save_and_store_code(url, response.text, file_path)
                    return []
                
                elif any(file_path.lower().endswith(ext) for ext in self.media_extensions) and self.download_media:
                    # Handle media files if allowed
                    self.save_file(url, response.content, file_path, is_binary=True)
                    return []
                
                elif any(file_path.lower().endswith(ext) for ext in self.archive_extensions) and self.download_archives:
                    # Handle archive files if allowed
                    self.save_file(url, response.content, file_path, is_binary=True)
                    return []
                
                elif any(file_path.lower().endswith(ext) for ext in self.text_extensions) and self.download_text:
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
                # Fix #8: scope to the form element itself, not the entire page
                form_str = str(form)
                has_auto_submit = (
                    form.get('onsubmit') is not None or
                    'submit()' in form_str or
                    'init()' in form_str
                )
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

                # Fix #7: count actual file saves, not URL visits
                self.successful_downloads += 1
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
        self.file_url_map[rel_path] = url  # remember which URL produced this file
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
        # Fix #3: actually append validated URLs instead of silently dropping them
        for pattern in html_url_patterns:
            for match in re.finditer(pattern, html_content):
                url = match.group(1)
                absolute_url = urljoin(base_url, url)
                if not url or not self.is_valid_url(absolute_url):
                    continue
                if self.should_process_url(absolute_url):
                    discovered_urls.append(absolute_url)
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

        # For fully-qualified URLs, run the full path-safety check.
        # This catches garbage URLs (JS regex literals, HTTP header names, etc.)
        # that may have slipped through extraction paths that don't call is_valid_url.
        if parsed_url.netloc and not self.is_valid_url(url):
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
    
    # JS/Python keywords and builtins that are not real function names
    _CALL_NOISE = frozenset([
        'if', 'for', 'while', 'switch', 'catch', 'function', 'return', 'var',
        'let', 'const', 'new', 'this', 'typeof', 'instanceof', 'in', 'of',
        'delete', 'void', 'throw', 'try', 'else', 'do', 'break', 'continue',
        'class', 'extends', 'import', 'export', 'default', 'static', 'super',
        'yield', 'async', 'await', 'true', 'false', 'null', 'undefined',
        'NaN', 'Infinity', 'debugger', 'with', 'case',
    ])

    def count_js_function_calls(self, js_content):
        """Count meaningful function calls in JavaScript, filtering minified noise."""
        pattern = r'(\w+)\s*\('
        for match in re.finditer(pattern, js_content):
            name = match.group(1)
            # Skip: short minified identifiers (n, r, Pe…) and language keywords
            if len(name) < 3 or name in self._CALL_NOISE:
                continue
            self.function_calls[name] = self.function_calls.get(name, 0) + 1
    
    def check_security_headers(self, url, headers):
        """Record missing or weak HTTP security headers for a single response."""
        h = {k.lower(): v for k, v in headers.items()}
        issues = []

        if 'strict-transport-security' not in h:
            issues.append({'header': 'Strict-Transport-Security', 'issue': 'Missing', 'severity': 'High'})

        if 'content-security-policy' not in h:
            issues.append({'header': 'Content-Security-Policy', 'issue': 'Missing', 'severity': 'High'})

        # X-Frame-Options OR CSP frame-ancestors
        has_frame_ancestors = 'frame-ancestors' in h.get('content-security-policy', '')
        if 'x-frame-options' not in h and not has_frame_ancestors:
            issues.append({'header': 'X-Frame-Options', 'issue': 'Missing (no CSP frame-ancestors either)', 'severity': 'Medium'})

        if 'x-content-type-options' not in h:
            issues.append({'header': 'X-Content-Type-Options', 'issue': 'Missing', 'severity': 'Low'})

        if 'referrer-policy' not in h:
            issues.append({'header': 'Referrer-Policy', 'issue': 'Missing', 'severity': 'Low'})

        if 'x-powered-by' in h:
            issues.append({'header': 'X-Powered-By', 'issue': f'Exposed: {h["x-powered-by"]}', 'severity': 'Info'})

        if 'server' in h:
            issues.append({'header': 'Server', 'issue': f'Exposed: {h["server"]}', 'severity': 'Info'})

        # Cookie flags (check raw Set-Cookie header string)
        set_cookie = headers.get('Set-Cookie', '')
        if set_cookie:
            sc_lower = set_cookie.lower()
            if 'secure' not in sc_lower:
                issues.append({'header': 'Set-Cookie', 'issue': 'Missing Secure flag', 'severity': 'Medium'})
            if 'httponly' not in sc_lower:
                issues.append({'header': 'Set-Cookie', 'issue': 'Missing HttpOnly flag', 'severity': 'Medium'})
            if 'samesite' not in sc_lower:
                issues.append({'header': 'Set-Cookie', 'issue': 'Missing SameSite attribute', 'severity': 'Low'})

        if issues:
            self.security_headers_issues[url] = issues

    def extract_forms(self, url, html_content):
        """Extract all HTML forms and their inputs for forms_inventory.md."""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            for form in soup.find_all('form'):
                form_data = {
                    'url': url,
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                for inp in form.find_all(['input', 'select', 'textarea']):
                    name = inp.get('name', '')
                    if not name:
                        continue
                    form_data['inputs'].append({
                        'name': name,
                        'type': inp.get('type', 'text' if inp.name != 'select' else 'select'),
                        'id': inp.get('id', ''),
                    })
                if form_data['inputs']:
                    self.forms_found.append(form_data)
        except Exception as e:
            logger.warning(f"Error extracting forms from {url}: {e}")

    def analyze_code_files(self):
        """
        Analyze downloaded code files for security issues and function usage
        """
        import hashlib
        logger.info("Starting code analysis...")

        # Deduplicate files by content hash — SPA sites (e.g. React) serve the same
        # index.html at every route, producing dozens of identical copies.  Keep only
        # the first path encountered for each unique content hash so findings are not
        # inflated by repeated analysis of the same bytes.
        _seen_content = {}
        code_files = {}
        for path, content in self.code_files.items():
            h = hashlib.md5(content.encode('utf-8', errors='replace')).hexdigest()
            if h not in _seen_content:
                _seen_content[h] = path
                code_files[path] = content
        skipped = len(self.code_files) - len(code_files)
        if skipped:
            logger.info(f"Content dedup: skipped {skipped} duplicate file(s) (identical content)")

        from .analyzer import SecurityAnalyzer
        analyzer = SecurityAnalyzer()
        security_findings = analyzer.analyze_code(code_files)

        # ── Sink detection ─────────────────────────────────────────────────────
        # Deduplicate by (file, sink_text) to avoid minified-bundle floods.
        total_files = len(code_files)
        idx_w = len(str(total_files))
        print(f"[SINKS]    Scanning {total_files} file{'s' if total_files != 1 else ''} for dangerous sinks...")
        _seen_sinks = set()
        for file_idx, (file_path, content) in enumerate(code_files.items(), 1):
            file_name = os.path.basename(file_path)
            # Rolling progress line — overwritten each iteration for clean-file noise suppression
            progress = f"  [{file_idx:>{idx_w}}/{total_files}]  Scanning {file_name}..."
            print(f"{progress:<72}", end="\r", flush=True)

            extension = os.path.splitext(file_path)[1].lower()
            if extension == '.js':
                self.count_js_function_calls(content)
            file_sinks = []
            # Dedup by (basename, sink_text) so SPA sites that serve the same
            # HTML at many routes (e.g. React on every path) don't flood sinks.md
            file_basename = os.path.basename(file_path)
            for sink_pat in sink_patterns:
                for match in re.finditer(sink_pat, content):
                    sink_text = match.group(0).strip().rstrip('(').rstrip()
                    dedup_key = (file_basename, sink_text.lower())
                    if dedup_key in _seen_sinks:
                        continue
                    _seen_sinks.add(dedup_key)
                    line_number = content[:match.start()].count('\n') + 1
                    code_line = content.splitlines()[line_number - 1].strip()
                    self.potential_sinks.append({
                        'file': file_path,
                        'line': line_number,
                        'sink': match.group(0),
                        'code': code_line
                    })
                    file_sinks.append(sink_text)

            if file_sinks:
                # Overwrite the rolling progress line with a permanent finding line
                unique_sinks = list(dict.fromkeys(file_sinks))
                sink_labels = '  '.join(unique_sinks)
                print(f"  [{file_idx:>{idx_w}}/{total_files}]  {file_name:<38}  {len(file_sinks)} sink{'s' if len(file_sinks) > 1 else ''}: {sink_labels[:52]}")

        print(f"{' ' * 72}", end="\r")  # erase last rolling line
        print(f"[SINKS]    Done -- {len(self.potential_sinks)} sink{'s' if len(self.potential_sinks) != 1 else ''} found\n")

        # ── JS library version extraction ──────────────────────────────────────
        print(f"[VERSIONS] Scanning JS/HTML files for library version strings...")
        _js_version_patterns = [
            (r'[Jj][Qq]uery\s+v(\d+\.\d+[\.\d]*)', 'jQuery'),
            (r'"jquery":\s*"(\d+\.\d+[\.\d]*)"', 'jQuery'),
            (r'React\s+v(\d+\.\d+[\.\d]*)', 'React'),
            (r'"react":\s*"(\d+\.\d+[\.\d]*)"', 'React'),
            (r'swagger-ui\s+v?(\d+\.\d+[\.\d]*)', 'Swagger UI'),
            (r'Bootstrap\s+v(\d+\.\d+[\.\d]*)', 'Bootstrap'),
            (r'"bootstrap":\s*"(\d+\.\d+[\.\d]*)"', 'Bootstrap'),
            (r'"angular(?:js)?":\s*"(\d+\.\d+[\.\d]*)"', 'Angular'),
            (r'"vue":\s*"(\d+\.\d+[\.\d]*)"', 'Vue.js'),
            (r'"lodash":\s*"(\d+\.\d+[\.\d]*)"', 'lodash'),
            (r'"axios":\s*"(\d+\.\d+[\.\d]*)"', 'axios'),
            (r'Handlebars\s+v(\d+\.\d+[\.\d]*)', 'Handlebars'),
            (r'Moment\.js\s+v?(\d+\.\d+[\.\d]*)', 'Moment.js'),
        ]
        for file_path, content in code_files.items():
            ext = os.path.splitext(file_path)[1].lower()
            if ext not in ('.js', '.html'):
                continue
            for pattern, lib_name in _js_version_patterns:
                if f"JS: {lib_name}" in self.detected_versions:
                    continue
                m = re.search(pattern, content)
                if m:
                    self.detected_versions[f"JS: {lib_name}"] = m.group(1)
                    logger.info(f"Detected {lib_name} v{m.group(1)} in {file_path}")

        js_versions_found = {k: v for k, v in self.detected_versions.items() if k.startswith('JS:')}
        if js_versions_found:
            for lib, ver in js_versions_found.items():
                print(f"           {lib}: {ver}")
        print(f"[VERSIONS] Done -- {len(js_versions_found)} JS version{'s' if len(js_versions_found) != 1 else ''} detected\n")

        # ── Report generation ──────────────────────────────────────────────────
        print(f"[REPORTS]  Generating reports...")
        from .reporter import Reporter
        reporter = Reporter(self.target_url, report_dir=self.report_dir, download_dir=self.download_dir)
        print(f"           security_report.md", end="  ", flush=True)
        reporter.generate_security_report(security_findings, url_map=self.file_url_map)
        print(f"done")

        if self.potential_sinks:
            print(f"           sinks.md", end="  ", flush=True)
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
                    sink_type = sink['sink'].split('(')[0].strip().rstrip('= ')
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
            print(f"done")

        print(f"           function_usage_report.md", end="  ", flush=True)
        self.generate_function_usage_report()
        print(f"done")

        print(f"           http_headers_report.md", end="  ", flush=True)
        self.generate_headers_report()
        print(f"done")

        print(f"           forms_inventory.md", end="  ", flush=True)
        self.generate_forms_report()
        print(f"done")

        print(f"[REPORTS]  All reports written\n")
    
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
            dir_path = os.path.dirname(file_path)
            # Fix #11a: normalise separator so this works on Windows too
            parts = dir_path.replace('\\', '/').split('/')
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

    def generate_headers_report(self):
        """Generate http_headers_report.md from security header checks collected during crawl."""
        if not self.security_headers_issues:
            return
        report_path = os.path.join(self.report_dir, 'http_headers_report.md')
        severity_order = {'High': 0, 'Medium': 1, 'Low': 2, 'Info': 3}

        # Aggregate: for each header issue, count affected URLs
        header_summary = {}
        for url, issues in self.security_headers_issues.items():
            for issue in issues:
                key = (issue['header'], issue['issue'])
                if key not in header_summary:
                    header_summary[key] = {'severity': issue['severity'], 'count': 0}
                header_summary[key]['count'] += 1

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("# HTTP Security Headers Report\n\n")
            f.write(f"**Target:** {self.target_url}\n")
            f.write(f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**URLs Checked:** {len(self.security_headers_issues)}\n\n")

            f.write("## Summary\n\n")
            f.write("| Header / Issue | Severity | URLs Affected |\n")
            f.write("|----------------|----------|---------------|\n")
            for (header, issue_desc), data in sorted(
                header_summary.items(),
                key=lambda x: (severity_order.get(x[1]['severity'], 4), x[0][0])
            ):
                f.write(f"| `{header}`: {issue_desc} | {data['severity']} | {data['count']} |\n")
            f.write("\n")

            # Show per-URL detail for first 20 URLs only
            f.write("## Details (first 20 URLs)\n\n")
            for url, issues in list(self.security_headers_issues.items())[:20]:
                f.write(f"### `{url}`\n\n")
                f.write("| Header / Issue | Severity |\n")
                f.write("|----------------|----------|\n")
                for issue in sorted(issues, key=lambda x: severity_order.get(x['severity'], 4)):
                    f.write(f"| `{issue['header']}`: {issue['issue']} | {issue['severity']} |\n")
                f.write("\n")

            if len(self.security_headers_issues) > 20:
                f.write(f"*...{len(self.security_headers_issues) - 20} more URLs checked. See summary above.*\n")

        logger.info(f"HTTP headers report: {len(header_summary)} distinct issues across {len(self.security_headers_issues)} URLs")
        logger.info(f"HTTP headers report generated: {report_path}")

    def generate_forms_report(self):
        """Generate forms_inventory.md — deduplicated by (action, method, param names)."""
        if not self.forms_found:
            return
        report_path = os.path.join(self.report_dir, 'forms_inventory.md')

        # Deduplicate: same action + method + param set = one entry (keep first URL seen)
        seen = {}
        unique_forms = []
        for form in self.forms_found:
            key = (
                form['action'].lower().rstrip('/'),
                form['method'],
                tuple(sorted(inp['name'] for inp in form['inputs']))
            )
            if key not in seen:
                seen[key] = True
                unique_forms.append(form)

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("# Forms & Parameters Inventory\n\n")
            f.write(f"**Target:** {self.target_url}\n")
            f.write(f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Unique Forms Found:** {len(unique_forms)}\n\n")
            f.write("> Use this list as your primary fuzzing surface for SQLi, XSS, and CSRF.\n\n")

            for i, form in enumerate(unique_forms, 1):
                action = form['action'] or '(same page)'
                f.write(f"## Form {i}: `{form['method']} {action}`\n\n")
                f.write(f"**Example URL:** `{form['url']}`  \n")
                f.write(f"**Method:** `{form['method']}`  \n")
                f.write(f"**Action:** `{action}`  \n\n")
                f.write("| Parameter | Type | ID |\n")
                f.write("|-----------|------|----|\n")
                for inp in form['inputs']:
                    f.write(f"| `{inp['name']}` | {inp['type']} | {inp.get('id', '')} |\n")
                f.write("\n")

        logger.info(f"Forms inventory: {len(unique_forms)} unique forms ({len(self.forms_found)} total)")
        logger.info(f"Forms inventory generated: {report_path}")

    def generate_final_report(self):
        """
        Generate a final comprehensive report
        """
        logger.info("Generating final report...")
        
        # First, generate the JSON dumps
        files_dirs_json = self.generate_files_directories_json()
        endpoints_json = self.generate_endpoints_json()
        versions_json = self.generate_versions_json()

        # ── API probing phase ──────────────────────────────────────────────────
        from .api_prober import ApiProber
        self._api_prober = ApiProber(
            self.target_url, self.api_endpoints, self.session,
            timeout=self.timeout, threads=self.threads,
        )
        self._api_prober.enrich_from_js(self.code_files)
        self._api_prober.run()
        self._api_prober.generate_report(self.report_dir)
        # Merge API-discovered versions back into the scanner's version map
        for url, vdata in self._api_prober.version_findings.items():
            path = urlparse(url).path
            for k, v in vdata.get('body_versions', {}).items():
                self.detected_versions[f"API {path}: {k}"] = v
            for k, v in vdata.get('header_versions', {}).items():
                self.detected_versions[f"API {path} header {k}"] = v

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
            
            # --- Dynamic recommendations derived from actual findings ---
            issue_types_found = set()
            for fp, fi in self.potential_sinks and {} or {}:
                pass  # placeholder; read from security_findings below
            # Read issue types from security_report.md (already written to disk)
            security_report_path2 = os.path.join(self.report_dir, 'security_report.md')
            if os.path.exists(security_report_path2):
                with open(security_report_path2, 'r', encoding='utf-8') as sr2:
                    for line in sr2:
                        if line.startswith('**Type:**'):
                            issue_types_found.add(line.replace('**Type:**', '').strip().rstrip('  '))

            recs = []
            if 'SQL Injection' in issue_types_found or 'NoSQL Injection' in issue_types_found:
                recs.append("**Parameterized Queries:** SQL/NoSQL injection patterns detected — use prepared statements or an ORM instead of string concatenation.")
            if 'XSS' in issue_types_found or 'Use of Dangerous Functions' in issue_types_found:
                recs.append("**Output Encoding + CSP:** XSS vectors detected — apply context-aware output encoding and add a Content-Security-Policy header.")
            if 'Open Redirect' in issue_types_found or 'Unvalidated Redirects' in issue_types_found:
                recs.append("**Redirect Validation:** Open redirect patterns detected — whitelist allowed destinations server-side.")
            if 'Insecure Crypto' in issue_types_found:
                recs.append("**Cryptography Review:** Weak crypto patterns detected — use AES-GCM for encryption, bcrypt/Argon2 for password hashing.")
            if 'Hardcoded Credentials' in issue_types_found:
                recs.append("**Secrets Management:** Hardcoded credentials detected — move secrets to environment variables or a secrets manager.")
            if 'File Inclusion' in issue_types_found or 'Path Traversal' in issue_types_found:
                recs.append("**Path Validation:** File inclusion/path traversal patterns detected — validate and restrict file paths with a whitelist.")
            if 'CSRF' in issue_types_found:
                recs.append("**CSRF Tokens:** CSRF patterns detected — ensure all state-changing forms include synchroniser tokens.")
            if self.detected_versions:
                recs.append("**Dependency Audit:** Server/library versions fingerprinted — check CVE databases and update vulnerable components.")
            if self.target_url.startswith('http://'):
                recs.append("**Enable HTTPS:** Site is served over plain HTTP — deploy TLS and add Strict-Transport-Security header.")
            if self.security_headers_issues:
                recs.append("**Security Headers:** Missing headers detected — see [http_headers_report.md](http_headers_report.md) for a full list.")
            if self.forms_found:
                recs.append("**Input Validation:** Forms detected — validate and sanitise all inputs server-side; see [forms_inventory.md](forms_inventory.md).")
            if self.potential_sinks:
                recs.append("**Sink Review:** Dangerous sinks detected — review [sinks.md](sinks.md) and test each with user-controlled input.")
            prober = getattr(self, '_api_prober', None)
            if prober:
                if prober.swagger_specs:
                    recs.append(f"**API Spec Exposure:** {len(prober.swagger_specs)} Swagger/OpenAPI spec(s) publicly accessible — verify if intentional and redact internal paths.")
                if prober.auth_findings:
                    recs.append(f"**Unauthenticated API Endpoints:** {len(prober.auth_findings)} endpoint(s) return HTTP 200 without credentials — verify access control. See [api_report.md](api_report.md).")
                if any(x['severity'] == 'High' for x in prober.cors_findings):
                    recs.append(f"**CORS Misconfiguration (High):** Origin reflected with credentials=true — cross-site authenticated reads possible. See [api_report.md](api_report.md).")
                elif prober.cors_findings:
                    recs.append(f"**CORS:** {len(prober.cors_findings)} CORS issue(s) found. See [api_report.md](api_report.md).")
                if prober.version_findings:
                    recs.append(f"**API Version Disclosure:** {len(prober.version_findings)} endpoint(s) expose version/build info — remove or restrict diagnostic endpoints in production.")
                if prober.method_findings:
                    recs.append(f"**Dangerous HTTP Methods:** {len(prober.method_findings)} endpoint(s) accept PUT/DELETE/TRACE — restrict to methods actually required.")
            if not recs:
                recs.append("No specific issues detected. Perform manual review to confirm.")

            f.write("## Recommendations\n\n")
            for n, rec in enumerate(recs, 1):
                f.write(f"{n}. {rec}\n")
            f.write("\n")

            f.write("## Reports Generated\n\n")
            f.write("| Report | Description |\n")
            f.write("|--------|-------------|\n")
            f.write("| [security_report.md](security_report.md) | Detailed security findings with code snippets |\n")
            f.write("| [sinks.md](sinks.md) | Prioritised fuzzing target list |\n")
            f.write("| [discovered_files_dirs.json](discovered_files_dirs.json) | All visited URLs and downloaded files |\n")
            f.write("| [discovered_versions.json](discovered_versions.json) | Detected server/library versions |\n")
            f.write("| [discovered_sensitive_data.json](discovered_sensitive_data.json) | Crypto addresses, IPs, and link map |\n")
            if self.security_headers_issues:
                f.write("| [http_headers_report.md](http_headers_report.md) | Missing/weak HTTP security headers |\n")
            if self.forms_found:
                f.write("| [forms_inventory.md](forms_inventory.md) | All forms and input parameters |\n")
            f.write("| [api_report.md](api_report.md) | API probe — spec exposure, CORS, auth, methods, version disclosure |\n")
            f.write("| [api_details.json](api_details.json) | Raw per-endpoint API probe data |\n")
            f.write("\n")
        
        logger.info(f"Final report generated: {report_path}")
        
        # --- Generate sensitive data JSON at the end of the scan ---
        reporter = Reporter(self.target_url, report_dir=self.report_dir, download_dir=self.download_dir)
        reporter.generate_sensitive_data_json(self.code_files, list(self.visited_urls), self.base_domain)
        logger.info("Sensitive data JSON report generated at the end of scan.")
