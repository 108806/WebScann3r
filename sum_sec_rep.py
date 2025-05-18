#!/usr/bin/env python3
import sys
import re
from collections import Counter, defaultdict

# Usage: python3 sum_sec_rep.py /path/to/security_report.md
report_path = sys.argv[1] if len(sys.argv) > 1 else 'security_report.md'

# Data structures
counter = Counter()
regex_map = defaultdict(str)

type_pat = re.compile(r'\*\*Type:\*\* (.+)')
pattern_code_pat = re.compile(r'\*\*Pattern:\*\*\n```\n([\s\S]+?)\n```')
pattern_na_pat = re.compile(r'\*\*Pattern:\*\* _Pattern not available \(matched: (.*?)\)_')

with open(report_path, encoding='utf-8') as f:
    content = f.read()

# Split into issues
issues = content.split('-------------------- ISSUE ')
for issue in issues:
    if not issue.strip():
        continue
    type_match = type_pat.search(issue)
    if not type_match:
        continue
    issue_type = type_match.group(1).strip()
    pat_match = pattern_code_pat.search(issue)
    if pat_match:
        pat = pat_match.group(1).strip()
    else:
        pat_na = pattern_na_pat.search(issue)
        pat = pat_na.group(1).strip() if pat_na else 'N/A'
    key = (issue_type, pat)
    counter[key] += 1

# Print sorted summary
print(f"{'Count':>6}  {'Type':<22}  Pattern/Match")
print('-'*60)
for (issue_type, pat), count in counter.most_common():
    print(f"{count:6}  {issue_type:<22}  {pat}")
