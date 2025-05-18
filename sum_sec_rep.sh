#!/bin/sh
# Usage: ./sum_sec_rep.sh /path/to/security_report.md

REPORT="${1:-security_report.md}"

awk '
/\*\*Type:\*\*/ { type=$2; pat="" }
/\*\*Pattern:\*\*\n```/ { getline; pat=$0; gsub(/^[ \t]+|[ \t]+$/, "", pat) }
/\*\*Pattern:\*\* _Pattern not available \(matched: / {
  m = $0
  sub(/.*_Pattern not available \(matched: /, "", m)
  sub(/\)_.*$/, "", m)
  key = type "|" (pat ? pat : m)
  count[key]++
  pat = ""
}
/\*\*Code:\*\*/ { if (pat) { key = type "|" pat; count[key]++; pat="" } }
END {
  for (k in count) print count[k], k
}
' "$REPORT" | sort -nr | awk -F'\\|' '{printf "%5d  %-20s  %s\n", $1, $2, $3}'