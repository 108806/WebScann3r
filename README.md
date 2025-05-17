# WebScann3r

```
 __        __   _     ____                       _____      
 \ \      / /__| |__ / ___|  ___ __ _ _ __  _ __|___ / _ __ 
  \ \ /\ / / _ \ '_ \\___ \ / __/ _` | '_ \| '_ \ |_ \| '__|
   \ V  V /  __/ |_) |___) | (_| (_| | | | | | | |__) | |   
    \_/\_/ \___|_.__/|____/ \___\__,_|_| |_|_| |_|____/|_|   
                                                             
```

A comprehensive web reconnaissance tool for red team assessments. This tool scans and maps a website before an attack phase, helping security professionals to understand the attack surface of a target.

## Features

- **Web Crawling**: Recursively crawls the target website to discover pages and endpoints
- **Resource Mapping**: Creates a directory structure that mirrors the website's organization
- **File Downloading**: Downloads code files (.js, .php, .css, .html) for analysis
- **Deep Analysis**: Scans JavaScript files for additional links and resources
- **Security Analysis**: Checks for potentially dangerous code and security issues
- **Function Usage Tracking**: Reports on how frequently each function is used across the codebase
- **API Endpoint Detection**: Automatically identifies and catalogs API endpoints and routes
- **Technology Stack Identification**: Detects software versions and creates a technology profile
- **Domain Scope Control**: Option to limit scanning to the target domain or include external domains
- **Media Filtering**: Option to skip media files (images, videos) to save space and time
- **Comprehensive Reporting**: Generates detailed reports of the scan findings and security issues
- **JSON Data Exports**: Provides structured JSON files for integration with other tools
- **JSON Dump**: Creates a structured JSON file with all discovered files and directories
- **Target Organization**: Organizes all outputs by target site in a structured directory layout
- **Automatic Code Beautification**: All downloaded `.js`, `.html`, and `.css` files are automatically beautified/pretty-printed before analysis and reporting, making security findings easier to review and learn from.
- **Comprehensive Pattern Documentation**: All vulnerability patterns are now well-documented, with clear descriptions, risk levels, OWASP categories, and mitigation guidance for educational value.
- **Improved URL Handling**: URLs missing a scheme (http/https) are now auto-corrected and a warning is shown in the CLI.
- **Better Error Reporting**: Improved error and warning messages for file handling and BeautifulSoup parsing.
- **Robustness**: Type checks and error handling improved for HTML parsing and code analysis.

## Changelog (Recent Major Improvements)

- Beautified code is now used for all analysis and reporting (not just saved to disk).
- Security pattern coverage and documentation improved for all major vulnerability types.
- CLI and reporting usability enhancements.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/108806/webscann3r.git
   cd webscann3r
   ```

2. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

3. Make the script executable:
   ```bash
   chmod +x webscann3r.py
   ```

## Usage

Basic usage:
```bash
./webscann3r.py https://example.com
```

### Options

```
usage: webscann3r.py [-h] [-d DOWNLOADS] [-r REPORTS] [-a] [-m] [-z] [-t]
                     [-j THREADS] [--timeout TIMEOUT] [-v] [-q]
                     url

WebScann3r - A Web Scanning and Mapping Tool for Red Teams

positional arguments:
  url                   Target URL to scan

options:
  -h, --help            show this help message and exit
  -d DOWNLOADS, --downloads DOWNLOADS
                        Base directory for downloads (default: ./targets)
  -r REPORTS, --reports REPORTS
                        Base directory for reports (default: ./targets)
  -a [DEPTH], --all-domains [DEPTH]
                        Scan all linked domains with specified depth (default: unlimited depth)
  -m, --media           Download media files (images, videos, etc.)
  -z, --archives        Download archive files (zip, tar, etc.)
  -t, --text            Download text files (txt, md, etc.)
  -j THREADS, --threads THREADS
                        Number of concurrent threads (default: 10)
  --timeout TIMEOUT     Request timeout in seconds (default: 30)
  -v, --verbose         Enable verbose output
  -q, --quiet           Suppress all output except errors
```

### Examples

1. Basic scan of a website:
   ```bash
   ./webscann3r.py https://example.com
   ```

2. Scan with more threads for faster operation:
   ```bash
   ./webscann3r.py https://example.com -j 20
   ```

3. Scan and download media files as well:
   ```bash
   ./webscann3r.py https://example.com -m
   ```

4. Scan all linked domains (not just the target):
   ```bash
   ./webscann3r.py https://example.com -a
   ```

5. Scan all linked domains with depth limit of 1 (only direct links):
   ```bash
   ./webscann3r.py https://example.com -a 1
   ```

6. Complete scan with all file types:
   ```bash
   ./webscann3r.py https://example.com -a -m -z -t
   ```

7. Verbose output for debugging:
   ```bash
   ./webscann3r.py https://example.com -v
   ```

## Reports

After scanning, WebScann3r generates several reports in the target-specific reports directory:

1. **security_report.md**: Details all potential security issues found in the code
2. **function_usage_report.md**: Shows how many times each function is called
3. **final_report.md**: A comprehensive summary of the scan results
4. **discovered_files_dirs.json**: A structured JSON file containing all discovered files and directories
5. **discovered_endpoints.json**: A JSON file listing all detected API endpoints and routes
6. **discovered_versions.json**: A JSON file containing all detected software versions and technology stack information

The reports are organized by target site with timestamps in a structure like:
```
targets/
└── example.com_20250515_120000/
    ├── downloads/
    │   └── (downloaded files)
    └── reports/
        ├── final_report.md
        ├── security_report.md
        ├── function_usage_report.md
        ├── discovered_files_dirs.json
        ├── discovered_endpoints.json
        └── discovered_versions.json
```

This structure ensures each scan is isolated and timestamped for better organization.

## Recommendations for Use

- Start with a basic scan to understand the website structure
- Use the `-a` flag cautiously as it may scan external domains
- Review the security report to identify potential vulnerabilities 
- Examine the function usage report to understand the application flow
- Check downloaded code files for additional security issues or attack vectors

## Disclaimer

This tool is created for legitimate security testing purposes. Only use it on websites that you own or have explicit permission to test. Unauthorized scanning may be illegal in your jurisdiction.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
