#!/bin/bash

# Default values
LIMIT=10
QUERY="inurl:/bug bounty"

# Parse command-line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --limit) LIMIT="$2"; shift ;;  # User-defined limit
        --query) QUERY="$2"; shift ;;  # User-defined query
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# Check if googlesearch-python is installed
if ! python3 -c "import googlesearch" &>/dev/null; then
    echo "Installing googlesearch-python..."
    pip install googlesearch-python
fi

# Check if tldextract is installed
if ! python3 -c "import tldextract" &>/dev/null; then
    echo "Installing tldextract..."
    pip install tldextract
fi

# Python script to fetch Google results and extract main domains
python3 - <<EOF
from googlesearch import search
import tldextract

# User input
query = "$QUERY"
num_results = int("$LIMIT")

# Perform search
results = search(query, num_results=num_results)

# Save and filter main domains
unique_domains = set()
for url in results:
    extracted = tldextract.extract(url)
    main_domain = f"{extracted.domain}.{extracted.suffix}"  # Extract main domain
    if main_domain not in unique_domains:
        unique_domains.add(main_domain)

# Print and save results
with open("bug_bounty_domains.txt", "w") as f:
    for domain in unique_domains:
        print(domain)
        f.write(domain + "\n")
EOF

echo "Extraction complete! Check 'bug_bounty_domains.txt'"


echo "==================================="
echo "💀 Salaar Bug Bounty Automation 💀"
echo "==================================="
# 2️⃣ Enumerate subdomains using multiple tools
echo "[+] Enumerating subdomains..."
subfinder -dL bug_bounty_domains.txt >> subs-temp.txt
amass enum -df bug_bounty_domains.txt -o amass-subs.txt
cat bug_bounty_domains.txt | assetfinder --subs-only >> subs-temp.txt
cat bug_bounty_domains.txt | while read domain; do curl -s "https://crt.sh/?q=%.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g'; done | sort -u >> subs-temp.txt
cat bug_bounty_domains.txt | chaos -silent -key >> subs-temp.txt

# Merge and sort unique subdomains
cat amass-subs.txt subs-temp.txt | sort -u | tee subdomains.txt

# Filtering out Dead Domains
subs-temp.txt | httpx | tee live-subdomains.txt 

