#!/usr/bin/env python3

import os
import json
import logging
import time
from datetime import datetime
import base64

logger = logging.getLogger('WebScann3r.HTMLReporter')

class HTMLReporter:
    def __init__(self, target_url, report_dir='reports', download_dir='downloads'):
        """
        Initialize the HTML reporter
        
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
        
        # HTML templates
        self._load_templates()
    
    def _load_templates(self):
        """
        Load HTML templates
        """
        # Main template
        self.main_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebScann3r Report - {target_url}</title>
    <style>
        :root {
            --primary-color: #4a6fa5;
            --secondary-color: #ff6b6b;
            --bg-color: #f8f9fa;
            --card-bg: #ffffff;
            --text-color: #333333;
            --border-color: #e0e0e0;
            --success-color: #28a745;
            --warning-color: #ffc107;
            --danger-color: #dc3545;
            --info-color: #17a2b8;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            margin: 0;
            padding: 0;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background-color: var(--primary-color);
            color: white;
            padding: 20px 0;
            margin-bottom: 30px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }
        
        header .container {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo {
            font-size: 24px;
            font-weight: bold;
        }
        
        .card {
            background-color: var(--card-bg);
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
            overflow: hidden;
        }
        
        .card-header {
            background-color: var(--primary-color);
            color: white;
            padding: 15px 20px;
            font-weight: bold;
            font-size: 18px;
        }
        
        .card-body {
            padding: 20px;
        }
        
        .summary-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background-color: var(--card-bg);
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        
        .stat-card .value {
            font-size: 36px;
            font-weight: bold;
            margin: 10px 0;
            color: var(--primary-color);
        }
        
        .stat-card .label {
            font-size: 14px;
            color: #666;
        }
        
        .chart-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .chart-card {
            background-color: var(--card-bg);
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        
        .chart-title {
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 20px;
            color: var(--primary-color);
        }
        
        .risk-badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 14px;
            font-weight: bold;
            color: white;
        }
        
        .risk-High {
            background-color: var(--danger-color);
        }
        
        .risk-Medium {
            background-color: var(--warning-color);
            color: #333;
        }
        
        .risk-Low {
            background-color: var(--info-color);
        }
        
        .severity-meter {
            display: block;
            width: 100%;
            height: 30px;
            background-color: #e0e0e0;
            border-radius: 15px;
            overflow: hidden;
            margin: 20px 0;
            position: relative;
        }
        
        .severity-fill {
            height: 100%;
            border-radius: 15px;
            background: linear-gradient(90deg, var(--success-color), var(--warning-color), var(--danger-color));
            transition: width 0.5s ease;
        }
        
        .severity-marker {
            position: absolute;
            top: 0;
            height: 100%;
            width: 4px;
            background-color: rgba(0, 0, 0, 0.7);
        }
        
        .severity-score {
            position: absolute;
            top: -25px;
            transform: translateX(-50%);
            font-weight: bold;
            color: var(--text-color);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        
        table th,
        table td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        
        table th {
            background-color: #f1f1f1;
            font-weight: bold;
        }
        
        table tr:hover {
            background-color: #f9f9f9;
        }
        
        .findings-list {
            margin-top: 20px;
        }
        
        .finding-item {
            margin-bottom: 20px;
            padding: 15px;
            border-radius: 8px;
            border-left: 5px solid var(--primary-color);
            background-color: #f9f9f9;
        }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .finding-title {
            font-weight: bold;
            font-size: 16px;
            color: var(--primary-color);
        }
        
        .file-path {
            color: #666;
            font-size: 14px;
            margin-bottom: 10px;
            font-family: monospace;
        }
        
        .code-block {
            background-color: #f1f1f1;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            white-space: pre;
            overflow-x: auto;
            margin: 10px 0;
        }
        
        .tabs {
            display: flex;
            margin-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
        }
        
        .tab {
            padding: 10px 20px;
            cursor: pointer;
            border-bottom: 3px solid transparent;
            transition: all 0.3s ease;
        }
        
        .tab.active {
            border-bottom-color: var(--primary-color);
            color: var(--primary-color);
            font-weight: bold;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .recommendation-card {
            background-color: #f9f9f9;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            border-left: 5px solid var(--primary-color);
        }
        
        .recommendation-title {
            font-weight: bold;
            margin-bottom: 10px;
            color: var(--primary-color);
        }
        
        .recommendation-list {
            margin-left: 20px;
        }
        
        .recommendation-list li {
            margin-bottom: 8px;
        }
        
        footer {
            background-color: var(--primary-color);
            color: white;
            padding: 20px 0;
            text-align: center;
            margin-top: 50px;
        }
        
        .owasp-badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 14px;
            background-color: #5c5c5c;
            color: white;
            margin-right: 5px;
            margin-bottom: 5px;
        }
        
        .library-table {
            width: 100%;
            margin-top: 20px;
        }
        
        .expand-button {
            background-color: var(--primary-color);
            color: white;
            border: none;
            padding: 5px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        
        .hidden {
            display: none;
        }
        
        .expandable {
            margin-top: 10px;
        }
        
        .site-structure {
            font-family: monospace;
            white-space: pre;
            overflow-x: auto;
            background-color: #f1f1f1;
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
        }
        
        /* Progress Bar Styles */
        .progress-container {
            width: 100%;
            background-color: #f1f1f1;
            border-radius: 5px;
            margin: 10px 0;
        }
        
        .progress-bar {
            height: 20px;
            border-radius: 5px;
            text-align: center;
            line-height: 20px;
            color: white;
            font-size: 12px;
            transition: width 0.5s;
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <header>
        <div class="container">
            <div class="logo">WebScann3r Report</div>
            <div class="report-date">{date}</div>
        </div>
    </header>
    
    <div class="container">
        <div class="card">
            <div class="card-header">Scan Summary</div>
            <div class="card-body">
                <p><strong>Target URL:</strong> {target_url}</p>
                <p><strong>Scan Started:</strong> {date}</p>
                <p><strong>Scan Mode:</strong> {scan_mode}</p>
                
                <div class="summary-stats">
                    <div class="stat-card">
                        <div class="label">URLs Visited</div>
                        <div class="value">{urls_visited}</div>
                    </div>
                    <div class="stat-card">
                        <div class="label">Files Downloaded</div>
                        <div class="value">{files_downloaded}</div>
                    </div>
                    <div class="stat-card">
                        <div class="label">Security Issues</div>
                        <div class="value">{total_issues}</div>
                    </div>
                    <div class="stat-card">
                        <div class="label">Overall Risk Score</div>
                        <div class="value">{risk_score}/10</div>
                    </div>
                </div>
                
                <div class="severity-meter">
                    <div class="severity-fill" style="width: {risk_score_percent}%;"></div>
                    <div class="severity-marker" style="left: {risk_score_percent}%;">
                        <div class="severity-score">{risk_score}</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="tabs">
            <div class="tab active" data-tab="overview">Overview</div>
            <div class="tab" data-tab="findings">Security Findings</div>
            <div class="tab" data-tab="recommendations">Recommendations</div>
            <div class="tab" data-tab="structure">Site Structure</div>
        </div>
        
        <div class="tab-content active" id="overview">
            <div class="chart-container">
                <div class="chart-card">
                    <div class="chart-title">Vulnerabilities by Type</div>
                    <canvas id="vulnerabilitiesChart"></canvas>
                </div>
                <div class="chart-card">
                    <div class="chart-title">Vulnerabilities by Risk Level</div>
                    <canvas id="riskLevelChart"></canvas>
                </div>
                <div class="chart-card">
                    <div class="chart-title">OWASP Top 10 Categories</div>
                    <canvas id="owaspChart"></canvas>
                </div>
                <div class="chart-card">
                    <div class="chart-title">Detected Libraries</div>
                    <canvas id="libraryChart"></canvas>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">Top 5 Vulnerabilities</div>
                <div class="card-body">
                    <table>
                        <thead>
                            <tr>
                                <th>Vulnerability Type</th>
                                <th>Count</th>
                                <th>Risk Level</th>
                                <th>OWASP Category</th>
                            </tr>
                        </thead>
                        <tbody>
                            {top_vulnerabilities_rows}
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">Detected Libraries and Versions</div>
                <div class="card-body">
                    <table class="library-table">
                        <thead>
                            <tr>
                                <th>Library</th>
                                <th>Version</th>
                            </tr>
                        </thead>
                        <tbody>
                            {libraries_rows}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <div class="tab-content" id="findings">
            <div class="card">
                <div class="card-header">Security Findings</div>
                <div class="card-body">
                    <div class="findings-list">
                        {findings_content}
                    </div>
                </div>
            </div>
        </div>
        
        <div class="tab-content" id="recommendations">
            <div class="card">
                <div class="card-header">Security Recommendations</div>
                <div class="card-body">
                    <p>Based on the scan results, the following recommendations are provided to improve security:</p>
                    
                    <div class="recommendation-list">
                        {recommendations_content}
                    </div>
                </div>
            </div>
        </div>
        
        <div class="tab-content" id="structure">
            <div class="card">
                <div class="card-header">Site Structure</div>
                <div class="card-body">
                    <p>The following is the directory structure of the downloaded files:</p>
                    
                    <div class="site-structure">
{site_structure}
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <footer>
        <div class="container">
            <p>WebScann3r - A Web Scanning and Mapping Tool for Red Teams</p>
            <p>Report generated on {date}</p>
        </div>
    </footer>
    
    <script>
        // Chart.js Configurations
        document.addEventListener('DOMContentLoaded', function() {
            // Vulnerabilities by Type Chart
            var vulnCtx = document.getElementById('vulnerabilitiesChart').getContext('2d');
            var vulnChart = new Chart(vulnCtx, {
                type: 'bar',
                data: {
                    labels: {vuln_types},
                    datasets: [{
                        label: 'Number of Findings',
                        data: {vuln_counts},
                        backgroundColor: 'rgba(74, 111, 165, 0.7)',
                        borderColor: 'rgba(74, 111, 165, 1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                precision: 0
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            });
            
            // Risk Level Chart
            var riskCtx = document.getElementById('riskLevelChart').getContext('2d');
            var riskChart = new Chart(riskCtx, {
                type: 'doughnut',
                data: {
                    labels: {risk_labels},
                    datasets: [{
                        data: {risk_counts},
                        backgroundColor: [
                            'rgba(220, 53, 69, 0.7)',
                            'rgba(255, 193, 7, 0.7)',
                            'rgba(23, 162, 184, 0.7)'
                        ],
                        borderColor: [
                            'rgba(220, 53, 69, 1)',
                            'rgba(255, 193, 7, 1)',
                            'rgba(23, 162, 184, 1)'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'right'
                        }
                    }
                }
            });
            
            // OWASP Categories Chart
            var owaspCtx = document.getElementById('owaspChart').getContext('2d');
            var owaspChart = new Chart(owaspCtx, {
                type: 'polarArea',
                data: {
                    labels: {owasp_labels},
                    datasets: [{
                        data: {owasp_counts},
                        backgroundColor: [
                            'rgba(74, 111, 165, 0.7)',
                            'rgba(255, 107, 107, 0.7)',
                            'rgba(77, 189, 116, 0.7)',
                            'rgba(255, 193, 7, 0.7)',
                            'rgba(138, 78, 192, 0.7)',
                            'rgba(23, 162, 184, 0.7)',
                            'rgba(92, 92, 92, 0.7)',
                            'rgba(232, 62, 140, 0.7)',
                            'rgba(108, 117, 125, 0.7)',
                            'rgba(0, 123, 255, 0.7)'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'right'
                        }
                    }
                }
            });
            
            // Library Chart
            var libCtx = document.getElementById('libraryChart').getContext('2d');
            var libChart = new Chart(libCtx, {
                type: 'bar',
                data: {
                    labels: {library_names},
                    datasets: [{
                        label: 'Detected Libraries',
                        data: {library_counts},
                        backgroundColor: 'rgba(77, 189, 116, 0.7)',
                        borderColor: 'rgba(77, 189, 116, 1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                precision: 0
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            });
            
            // Tab switching functionality
            document.querySelectorAll('.tab').forEach(tab => {
                tab.addEventListener('click', () => {
                    // Remove active class from all tabs
                    document.querySelectorAll('.tab').forEach(t => {
                        t.classList.remove('active');
                    });
                    
                    // Hide all tab content
                    document.querySelectorAll('.tab-content').forEach(content => {
                        content.classList.remove('active');
                    });
                    
                    // Add active class to clicked tab
                    tab.classList.add('active');
                    
                    // Show corresponding tab content
                    const tabId = tab.getAttribute('data-tab');
                    document.getElementById(tabId).classList.add('active');
                });
            });
            
            // Expandable content
            document.querySelectorAll('.expand-button').forEach(button => {
                button.addEventListener('click', () => {
                    const target = button.getAttribute('data-target');
                    const content = document.getElementById(target);
                    
                    if (content.classList.contains('hidden')) {
                        content.classList.remove('hidden');
                        button.textContent = 'Hide Details';
                    } else {
                        content.classList.add('hidden');
                        button.textContent = 'Show Details';
                    }
                });
            });
        });
    </script>
</body>
</html>"""
        
        # Finding item template
        self.finding_template = """<div class="finding-item">
    <div class="finding-header">
        <div class="finding-title">{issue_type}</div>
        <div class="risk-badge risk-{risk_level}">{risk_level} Risk</div>
    </div>
    <div class="file-path">{file_path}</div>
    <div class="owasp-badge">{owasp_category}</div>
    <p>{description}</p>
    <div>
        <button class="expand-button" data-target="details-{finding_id}">Show Details</button>
        <div id="details-{finding_id}" class="expandable hidden">
            <p><strong>Line {line}:</strong> {code}</p>
            <div class="code-block">{context}</div>
            <p><strong>Mitigation:</strong></p>
            <ul>
                {mitigation_items}
            </ul>
        </div>
    </div>
</div>"""
        
        # Recommendation template
        self.recommendation_template = """<div class="recommendation-card">
    <div class="recommendation-title">{vuln_type} ({count} findings)</div>
    <ul class="recommendation-list">
        {recommendation_items}
    </ul>
</div>"""
    
    def generate_html_report(self, scan_info, security_findings, enhanced_data):
        """
        Generate HTML report
        
        Args:
            scan_info (dict): Dictionary of scan information
            security_findings (dict): Dictionary of security findings
            enhanced_data (dict): Dictionary of enhanced report data
            
        Returns:
            str: Path to the generated HTML report
        """
        logger.info("Generating HTML report...")
        
        report_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        report_path = os.path.join(self.report_dir, 'report.html')
        
        # Prepare chart data
        vuln_types = []
        vuln_counts = []
        
        risk_labels = []
        risk_counts = []
        
        owasp_labels = []
        owasp_counts = []
        
        library_names = []
        library_counts = []
        
        # Process vulnerability types
        for vuln_type, count in enhanced_data.get('top_vulnerabilities', []):
            vuln_types.append(vuln_type)
            vuln_counts.append(count)
        
        # Process risk levels
        for risk_level, count in enhanced_data.get('risk_distribution', {}).items():
            risk_labels.append(risk_level)
            risk_counts.append(count)
        
        # Process OWASP categories
        for owasp_category, count in enhanced_data.get('owasp_distribution', {}).items():
            owasp_labels.append(owasp_category)
            owasp_counts.append(count)
        
        # Process libraries
        libraries = enhanced_data.get('detected_libraries', {})
        for lib, version in libraries.items():
            library_names.append(lib)
            library_counts.append(1)  # Just counting presence, not frequency
        
        # Generate top vulnerabilities table rows
        top_vulnerabilities_rows = ""
        for vuln_type, count in enhanced_data.get('top_vulnerabilities', []):
            owasp_category = ""
            risk_level = "Medium"
            
            # Get first item from security findings to get the OWASP category and risk level
            for file_path, file_findings in security_findings.items():
                if file_path == '__summary__':
                    continue
                
                if vuln_type in file_findings:
                    owasp_category = file_findings[vuln_type][0].get('owasp_category', "")
                    risk_level = file_findings[vuln_type][0].get('risk_level', "Medium")
                    break
            
            top_vulnerabilities_rows += f"""
                            <tr>
                                <td>{vuln_type}</td>
                                <td>{count}</td>
                                <td><span class="risk-badge risk-{risk_level}">{risk_level}</span></td>
                                <td>{owasp_category}</td>
                            </tr>"""
        
        # Generate libraries table rows
        libraries_rows = ""
        for lib, version in libraries.items():
            libraries_rows += f"""
                            <tr>
                                <td>{lib}</td>
                                <td>{version}</td>
                            </tr>"""
        
        # Generate findings content
        findings_content = ""
        finding_id = 0
        
        for file_path, file_findings in security_findings.items():
            if file_path == '__summary__':
                continue
            
            for issue_type, matches in file_findings.items():
                for match in matches:
                    finding_id += 1
                    
                    # Generate mitigation items
                    mitigation_items = ""
                    for step in match.get('mitigation', []):
                        mitigation_items += f"<li>{step}</li>"
                    
                    # Fill finding template
                    findings_content += self.finding_template.format(
                        finding_id=finding_id,
                        issue_type=issue_type,
                        risk_level=match.get('risk_level', 'Medium'),
                        file_path=file_path,
                        owasp_category=match.get('owasp_category', 'Unknown'),
                        description=match.get('description', ''),
                        line=match.get('line', ''),
                        code=match.get('code', '').replace('<', '&lt;').replace('>', '&gt;'),
                        context=match.get('context', '').replace('<', '&lt;').replace('>', '&gt;'),
                        mitigation_items=mitigation_items
                    )
        
        # Generate recommendations content
        recommendations_content = ""
        for recommendation in enhanced_data.get('recommendations', []):
            recommendation_items = ""
            for step in recommendation.get('mitigation_steps', []):
                recommendation_items += f"<li>{step}</li>"
            
            recommendations_content += self.recommendation_template.format(
                vuln_type=recommendation.get('vulnerability_type', ''),
                count=recommendation.get('count', 0),
                recommendation_items=recommendation_items
            )
        
        # Generate site structure
        site_structure = self._generate_site_structure(self.download_dir)
        
        # Calculate risk score for meter
        risk_score = enhanced_data.get('overall_risk_score', 0)
        risk_score_percent = risk_score * 10
        
        # Fill main template
        html_content = self.main_template.format(
            target_url=self.target_url,
            date=report_date,
            scan_mode="Same domain only" if scan_info.get('same_domain_only', True) else "All domains",
            urls_visited=scan_info.get('urls_visited', 0),
            files_downloaded=scan_info.get('files_downloaded', 0),
            total_issues=security_findings.get('__summary__', {}).get('total_issues', 0),
            risk_score=risk_score,
            risk_score_percent=risk_score_percent,
            vuln_types=json.dumps(vuln_types),
            vuln_counts=json.dumps(vuln_counts),
            risk_labels=json.dumps(risk_labels),
            risk_counts=json.dumps(risk_counts),
            owasp_labels=json.dumps(owasp_labels),
            owasp_counts=json.dumps(owasp_counts),
            library_names=json.dumps(library_names),
            library_counts=json.dumps(library_counts),
            top_vulnerabilities_rows=top_vulnerabilities_rows,
            libraries_rows=libraries_rows,
            findings_content=findings_content,
            recommendations_content=recommendations_content,
            site_structure=site_structure
        )
        
        # Write to file
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {report_path}")
        return report_path
    
    def _generate_site_structure(self, dir_path, prefix=""):
        """
        Generate a text representation of the site structure
        
        Args:
            dir_path (str): Directory path
            prefix (str): Prefix for indentation
            
        Returns:
            str: Text representation of the site structure
        """
        if not os.path.exists(dir_path):
            return "No files downloaded"
            
        result = ""
        entries = os.listdir(dir_path)
        entries.sort()
        
        for i, entry in enumerate(entries):
            entry_path = os.path.join(dir_path, entry)
            is_last = i == len(entries) - 1
            
            result += f"{prefix}{'+-- ' if is_last else '+-- '}{entry}\n"
            
            if os.path.isdir(entry_path):
                result += self._generate_site_structure(
                    entry_path, 
                    prefix + ('    ' if is_last else '|   ')
                )
        
        return result
