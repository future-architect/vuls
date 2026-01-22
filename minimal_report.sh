#!/bin/bash
# Minimal Report Mode - Fast CVE reporting without enrichment
# Usage: ./minimal_report.sh

echo "=== Running Vuls in Minimal Report Mode ==="
echo "This mode skips:"
echo "  - NVD CVE details"
echo "  - Exploit database queries"
echo "  - Metasploit queries"
echo "  - Known Exploited Vulnerabilities (KEV)"
echo "  - Cyber Threat Intelligence (CTI)"
echo "  - CWE database queries"
echo ""
echo "Output includes only:"
echo "  - CVE ID"
echo "  - Affected Package/Product"
echo "  - Fixed-in KB number (Windows)"
echo ""

# Run vuls report with minimal mode and JSON format
./vuls report -minimal -format-json -to-localfile

echo ""
echo "=== Report Complete ==="
echo "Check results directory for JSON output with minimal CVE data"
