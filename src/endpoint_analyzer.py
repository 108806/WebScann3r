#!/usr/bin/env python3

import re
import logging
import json
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

logger = logging.getLogger('WebScann3r.EndpointAnalyzer')

class EndpointAnalyzer:
    def __init__(self):
        """
        Initialize the endpoint analyzer
        """
        # Common API patterns
        self.api_patterns = [
            r'/api/v\d+/',
            r'/v\d+/api/',
            r'/rest/',
            r'/graphql',
            r'/query',
            r'/service/',
            r'/services/',
            r'/app/',
            r'/ajax/',
            r'/ws/',
            r'/rpc',
            r'/endpoint',
            r'/gateway',
            r'/auth/',
            r'/oauth/',
            r'/data/',
            r'/json/',
            r'/xml/',
        ]
        
        # Patterns for sensitive endpoints
        self.sensitive_patterns = [
            r'/admin',
            r'/login',
            r'/signup',
            r'/register',
            r'/reset',
            r'/password',
            r'/auth',
            r'/oauth',
            r'/token',
            r'/jwt',
            r'/dashboard',
            r'/control',
            r'/console',
            r'/phpinfo',
            r'/backup',
            r'/config',
            r'/settings',
            r'/setup',
            r'/install',
            r'/administrator',
            r'/phpmyadmin',
            r'/manager',
            r'/manage',
            r'/jenkins',
            r'/wp-admin',
            r'/user',
            r'/users',
            r'/account',
            r'/profile',
            r'/private',
            r'/secret',
            r'/upload',
            r'/file',
            r'/files',
            r'/download',
            r'/log',
            r'/logs',
            r'/debug',
            r'/test',
            r'/dev',
            r'/staging',
            r'/beta',
            r'/actuator',
            r'/metrics',
            r'/health',
            r'/env',
            r'/trace',
            r'/server-status',
            r'/status',
            r'/.git',
            r'/.svn',
            r'/.env',
            r'/robots.txt',
            r'/sitemap.xml',
            r'/swagger',
            r'/api-docs',
            r'/openapi',
        ]
        
        # Common HTTP methods
        self.http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
        
        # Parameter patterns to identify
        self.parameter_patterns = {
            'Authentication': [
                r'(?i)(?:token|api_?key|auth|jwt|session|csrf|Bearer)',
            ],
            'Personally Identifiable Information': [
                r'(?i)(?:user|username|email|phone|address|name|firstname|lastname|surname|birth|gender|ssn|passport)',
            ],
            'Database Operations': [
                r'(?i)(?:query|sql|select|insert|update|delete|where|table|column|record|database|db|collection)',
            ],
            'File Operations': [
                r'(?i)(?:file|path|directory|folder|upload|download|read|write|append)',
            ],
            'Command Execution': [
                r'(?i)(?:cmd|command|exec|run|system|process|spawn)',
            ],
            'Server Information': [
                r'(?i)(?:server|host|domain|ip|dns|port|url|uri)',
            ],
            'Configuration': [
                r'(?i)(?:config|setting|option|property|env|environment)',
            ],
            'Identifiers': [
                r'(?i)(?:id|guid|uuid|key)',
            ],
            'Secrets': [
                r'(?i)(?:secret|password|pwd|passwd|pass|key|salt|hash)',
            ],
        }
    
    def analyze_endpoints(self, visited_urls):
        """
        Analyze endpoints from visited URLs
        
        Args:
            visited_urls (list): List of visited URLs
            
        Returns:
            dict: Dictionary of endpoint analysis results
        """
        logger.info("Analyzing endpoints from visited URLs...")
        
        api_endpoints = []
        sensitive_endpoints = []
        endpoints_by_method = defaultdict(list)
        parameters_by_type = defaultdict(list)
        
        # Process each URL
        for url in visited_urls:
            parsed_url = urlparse(url)
            path = parsed_url.path
            
            # Extract potential HTTP method from URL path
            # Some URLs follow RESTful patterns like /users/123/GET
            method = 'GET'  # Default method
            path_parts = path.split('/')
            if path_parts and path_parts[-1].upper() in self.http_methods:
                method = path_parts[-1].upper()
                # Remove the method from the path for analysis
                path = '/'.join(path_parts[:-1])
            
            # Check for API endpoints
            if any(re.search(pattern, path, re.IGNORECASE) for pattern in self.api_patterns):
                api_endpoints.append({
                    'url': url,
                    'path': path,
                    'method': method,
                    'query_params': parse_qs(parsed_url.query)
                })
            
            # Check for sensitive endpoints
            if any(re.search(pattern, path, re.IGNORECASE) for pattern in self.sensitive_patterns):
                sensitive_endpoints.append({
                    'url': url,
                    'path': path,
                    'method': method,
                    'query_params': parse_qs(parsed_url.query)
                })
            
            # Group by method
            endpoints_by_method[method].append({
                'url': url,
                'path': path,
                'query_params': parse_qs(parsed_url.query)
            })
            
            # Analyze query parameters
            query_params = parse_qs(parsed_url.query)
            for param_name in query_params:
                for param_type, patterns in self.parameter_patterns.items():
                    if any(re.search(pattern, param_name) for pattern in patterns):
                        parameters_by_type[param_type].append({
                            'url': url,
                            'parameter': param_name,
                            'value': query_params[param_name][0] if query_params[param_name] else ''
                        })
                        break
        
        # Prepare result
        result = {
            'api_endpoints': api_endpoints,
            'sensitive_endpoints': sensitive_endpoints,
            'endpoints_by_method': dict(endpoints_by_method),
            'parameters_by_type': dict(parameters_by_type),
            'summary': {
                'total_api_endpoints': len(api_endpoints),
                'total_sensitive_endpoints': len(sensitive_endpoints),
                'endpoints_by_method_count': {method: len(endpoints) for method, endpoints in endpoints_by_method.items()},
                'parameters_by_type_count': {param_type: len(params) for param_type, params in parameters_by_type.items()}
            }
        }
        
        logger.info(f"Endpoint analysis completed. Found {len(api_endpoints)} API endpoints and {len(sensitive_endpoints)} sensitive endpoints.")
        return result
    
    def extract_urls_from_js(self, js_content):
        """
        Extract hardcoded URLs from JavaScript content
        
        Args:
            js_content (str): JavaScript content
            
        Returns:
            list: List of extracted URLs
        """
        # Patterns to match URLs in JavaScript
        patterns = [
            r'(?:url|URL|href|src|path|endpoint|api):\s*[\'"`]([^\'"`]+)[\'"`]',
            r'(?:url|URL|href|src|path|endpoint|api)\s*=\s*[\'"`]([^\'"`]+)[\'"`]',
            r'(?:fetch|axios\.get|axios\.post|ajax|xhr\.open)\([\'"`]([^\'"`]+)[\'"`]',
            r'\.(?:get|post|put|delete|patch)\([\'"`]([^\'"`]+)[\'"`]',
        ]
        
        extracted_urls = []
        
        for pattern in patterns:
            for match in re.finditer(pattern, js_content):
                extracted_urls.append(match.group(1))
        
        return extracted_urls
    
    def extract_api_schemas(self, js_content):
        """
        Extract potential API schemas from JavaScript content
        
        Args:
            js_content (str): JavaScript content
            
        Returns:
            list: List of potential API schemas
        """
        # Look for patterns that might define API schemas
        schemas = []
        
        # Pattern for object literals with API endpoint definitions
        object_pattern = r'({[^{}]*?(?:url|URL|endpoint|path|api)[^{}]*?})'
        
        for match in re.finditer(object_pattern, js_content):
            schemas.append(match.group(1))
        
        # Pattern for Swagger/OpenAPI definitions
        swagger_pattern = r'(?:swagger|openapi):\s*[\'"`][^\'"`]+[\'"`]'
        
        for match in re.finditer(swagger_pattern, js_content):
            schemas.append(match.group(0))
        
        return schemas
    
    def generate_api_report(self, endpoint_analysis):
        """
        Generate a report on API endpoints and sensitive routes
        
        Args:
            endpoint_analysis (dict): Dictionary of endpoint analysis results
            
        Returns:
            str: Markdown report content
        """
        report = "# API Endpoints and Sensitive Routes Report\n\n"
        
        # Summary
        report += "## Summary\n\n"
        report += f"- Total API endpoints discovered: {endpoint_analysis['summary']['total_api_endpoints']}\n"
        report += f"- Total sensitive endpoints discovered: {endpoint_analysis['summary']['total_sensitive_endpoints']}\n"
        
        # Endpoints by method
        report += "\n### Endpoints by HTTP Method\n\n"
        for method, count in endpoint_analysis['summary']['endpoints_by_method_count'].items():
            report += f"- {method}: {count}\n"
        
        # Parameters by type
        report += "\n### Parameter Types Discovered\n\n"
        for param_type, count in endpoint_analysis['summary']['parameters_by_type_count'].items():
            report += f"- {param_type}: {count}\n"
        
        # API endpoints
        report += "\n## API Endpoints\n\n"
        if endpoint_analysis['api_endpoints']:
            for i, endpoint in enumerate(endpoint_analysis['api_endpoints'][:20]):  # Limit to first 20
                report += f"### {i+1}. {endpoint['method']} {endpoint['path']}\n\n"
                report += f"- Full URL: `{endpoint['url']}`\n"
                
                if endpoint['query_params']:
                    report += "- Query Parameters:\n"
                    for param, values in endpoint['query_params'].items():
                        report += f"  - `{param}`: `{values[0]}`\n"
                
                report += "\n"
            
            if len(endpoint_analysis['api_endpoints']) > 20:
                report += f"*(Showing 20 of {len(endpoint_analysis['api_endpoints'])} endpoints)*\n\n"
        else:
            report += "No API endpoints discovered.\n\n"
        
        # Sensitive endpoints
        report += "\n## Sensitive Endpoints\n\n"
        if endpoint_analysis['sensitive_endpoints']:
            for i, endpoint in enumerate(endpoint_analysis['sensitive_endpoints'][:20]):  # Limit to first 20
                report += f"### {i+1}. {endpoint['method']} {endpoint['path']}\n\n"
                report += f"- Full URL: `{endpoint['url']}`\n"
                
                if endpoint['query_params']:
                    report += "- Query Parameters:\n"
                    for param, values in endpoint['query_params'].items():
                        report += f"  - `{param}`: `{values[0]}`\n"
                
                report += "\n"
            
            if len(endpoint_analysis['sensitive_endpoints']) > 20:
                report += f"*(Showing 20 of {len(endpoint_analysis['sensitive_endpoints'])} endpoints)*\n\n"
        else:
            report += "No sensitive endpoints discovered.\n\n"
        
        # Parameters by type (sensitive first)
        sensitive_param_types = ['Authentication', 'Secrets', 'Personally Identifiable Information']
        
        report += "\n## Sensitive Parameters\n\n"
        for param_type in sensitive_param_types:
            if param_type in endpoint_analysis['parameters_by_type']:
                report += f"### {param_type}\n\n"
                for i, param_info in enumerate(endpoint_analysis['parameters_by_type'][param_type][:10]):  # Limit to first 10
                    report += f"- `{param_info['parameter']}` in `{param_info['url']}`\n"
                
                if len(endpoint_analysis['parameters_by_type'][param_type]) > 10:
                    report += f"*(Showing 10 of {len(endpoint_analysis['parameters_by_type'][param_type])} parameters)*\n"
                
                report += "\n"
        
        # Other parameter types
        report += "\n## Other Parameter Types\n\n"
        for param_type, params in endpoint_analysis['parameters_by_type'].items():
            if param_type not in sensitive_param_types:
                report += f"### {param_type}\n\n"
                for i, param_info in enumerate(params[:10]):  # Limit to first 10
                    report += f"- `{param_info['parameter']}` in `{param_info['url']}`\n"
                
                if len(params) > 10:
                    report += f"*(Showing 10 of {len(params)} parameters)*\n"
                
                report += "\n"
        
        # Recommendations
        report += "\n## Recommendations\n\n"
        report += "Based on the discovered endpoints and parameters, consider the following recommendations:\n\n"
        
        if endpoint_analysis['api_endpoints']:
            report += "1. **API Security:**\n"
            report += "   - Ensure all API endpoints use proper authentication and authorization\n"
            report += "   - Implement rate limiting to prevent abuse\n"
            report += "   - Use HTTPS for all API communications\n"
            report += "   - Validate all input parameters\n"
        
        if endpoint_analysis['sensitive_endpoints']:
            report += "2. **Sensitive Endpoints:**\n"
            report += "   - Review access controls for sensitive endpoints\n"
            report += "   - Implement multi-factor authentication where appropriate\n"
            report += "   - Consider IP-based restrictions for admin interfaces\n"
            report += "   - Implement proper session management\n"
        
        if any(param_type in endpoint_analysis['parameters_by_type'] for param_type in sensitive_param_types):
            report += "3. **Parameter Security:**\n"
            report += "   - Never expose sensitive parameters in URLs\n"
            report += "   - Use POST requests instead of GET for sensitive operations\n"
            report += "   - Implement proper encryption for sensitive data\n"
            report += "   - Use secure cookies with appropriate flags\n"
        
        return report
