#!/usr/bin/env python3

import argparse
import logging
import sys
import os
from src.scanner import WebScanner

def main():
    banner = r"""
 __        __   _     ____                       _____      
 \ \      / /__| |__ / ___|  ___ __ _ _ __  _ __|___ / _ __ 
  \ \ /\ / / _ \ '_ \\___ \ / __/ _` | '_ \| '_ \ |_ \| '__|
   \ V  V /  __/ |_) |___) | (_| (_| | | | | | | |__) | |   
    \_/\_/ \___|_.__/|____/ \___\__,_|_| |_|_| |_|____/|_|   
                                                             
    A Web Scanning and Mapping Tool for Red Teams
    --------------------------------------------
    """
    
    print(banner)
    
    parser = argparse.ArgumentParser(description="WebScann3r - A Web Scanning and Mapping Tool for Red Teams")
    
    # Required arguments
    parser.add_argument("url", help="Target URL to scan")
    
    # Optional arguments
    parser.add_argument("-d", "--downloads", help="Base directory for downloads (default: ./targets)", default="targets")
    parser.add_argument("-r", "--reports", help="Base directory for reports (default: ./targets)", default="targets")
    parser.add_argument("-a", "--all-domains", help="Scan all linked domains with specified depth (default: unlimited depth)", type=int, nargs='?', const=None)
    parser.add_argument("-m", "--media", help="Download media files (images, videos, etc.)", action="store_true")
    parser.add_argument("-z", "--archives", help="Download archive files (zip, tar, etc.)", action="store_true")
    parser.add_argument("-t", "--text", help="Download text files (txt, md, etc.)", action="store_true")
    parser.add_argument("--depth", help="Maximum crawling depth for same-domain scanning (default: 3)", type=int, default=3)
    parser.add_argument("-j", "--threads", help="Number of concurrent threads (default: 15)", type=int, default=15)
    parser.add_argument("--timeout", help="Request timeout in seconds (default: 20)", type=int, default=20)
    parser.add_argument("-v", "--verbose", help="Enable verbose output", action="store_true")
    parser.add_argument("-q", "--quiet", help="Suppress all output except errors", action="store_true")
    
    args = parser.parse_args()

    # Auto-correct and warn if URL does not start with http/https
    if not args.url.startswith(('http://', 'https://')):
        print(f"[WARNING] Target address '{args.url}' does not start with http:// or https://. Assuming https://{args.url}")
        args.url = 'https://' + args.url
    
    # Configure logging based on verbosity
    if args.quiet:
        logging.basicConfig(level=logging.ERROR)
    elif args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    # Create output directories if they don't exist
    os.makedirs(args.downloads, exist_ok=True)
    os.makedirs(args.reports, exist_ok=True)
    
    try:
        # Create scanner instance
        scanner = WebScanner(
            target_url=args.url,
            download_dir=args.downloads,
            report_dir=args.reports,
            same_domain_only=args.all_domains is None,
            max_depth=args.all_domains if args.all_domains is not None else args.depth,
            download_media=args.media,
            download_archives=args.archives,
            download_text=args.text,
            threads=args.threads,
            timeout=args.timeout
        )
        
        # Start scanning
        scanner.start_scan()
        
        print(f"\nScan completed successfully!")
        print(f"Results stored in: {scanner.target_dir}")
        print(f"├── Downloaded files: {scanner.download_dir}")
        print(f"└── Reports: {scanner.report_dir}")
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
