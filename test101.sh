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
mkdir /opt/

echo "==================================="
echo "💀 Salaar Bug Bounty Automation 💀"
echo "==================================="
# 2️⃣ Enumerate subdomains using multiple tools
echo "[+] Enumerating subdomains..."
subfinder -dL bug_bounty_domains.txt >> subs-temp.txt
#amass enum -df bug_bounty_domains.txt -o amass-subs.txt
cat bug_bounty_domains.txt | assetfinder --subs-only >> subs-temp.txt
cat bug_bounty_domains.txt | while read domain; do curl -s "https://crt.sh/?q=%.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g'; done | sort -u >> subs-temp.txt
cat bug_bounty_domains.txt | chaos -silent -key 6aa57816-004b-429c-a02b-d1344c1abeb7 >> subs-temp.txt

# Merge and sort unique subdomains
cat amass-subs.txt subs-temp.txt | sort -u | shuf | tee subdomains.txt
rm amass-subs.txt subs-temp.txt

# Filtering out Dead Domains
cat subs-temp.txt | httpx | tee live-subdomains.txt 


# Crawl URLs and extract parameters & JS files
cat subdomains.txt | katana -d 5 >> /opt/katana-urls.txt
cat /opt/katana-urls.txt | grep = | qsreplace salaar >> /opt/katana-params.txt
cat /opt/katana-urls.txt | grep .js >> /opt/katana-js-files.txt
cat /opt/katana-urls.txt | grep -Ei "token=|key=|apikey=|access_token=|secret=|auth=|password=|session=|jwt=|bearer=|Authorization=|Bearer |eyJ|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY" >> /opt/katana-kong.txt
cat /opt/katana-urls.txt | grep -Ei "wp-content|wp-login|wp-admin|wp-includes|wp-json|xmlrpc.php|wordpress|wp-config|wp-cron.php" >> /opt/katana-wordpress.txt
rm /opt/katana-urls.txt

#cat subdomains.txt | urlfinder >> /opt/urlfinder-urls.txt
#cat /opt/urlfinder-urls.txt | grep = | qsreplace salaar >> /opt/urlfinder-params.txt
#cat /opt/urlfinder-urls.txt | grep .js >> /opt/urlfinder-js-files.txt
#cat /opt/urlfinder-urls.txt | grep -Ei "token=|key=|apikey=|access_token=|secret=|auth=|password=|session=|jwt=|bearer=|Authorization=|Bearer |eyJ|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY" >> /opt/urlfinder-kong.txt
#cat /opt/urlfinder-urls.txt | grep -Ei "wp-content|wp-login|wp-admin|wp-includes|wp-json|xmlrpc.php|wordpress|wp-config|wp-cron.php" >> /opt/urlfinder-wordpress.txt
#rm /opt/urlfinder-urls.txt

#cat /opt/katana-params.txt /opt/urlfinder-params.txt | sort -u >> /opt/help1-params.txt 
#rm  /opt/katana-params.txt /opt/urlfinder-params.txt

#cat /opt/katana-js-files.txt /opt/urlfinder-js-files.txt | sort -u >> /opt/help1-js-files.txt
#rm  /opt/katana-js-files.txt /opt/urlfinder-js-files.txt

#cat /opt/katana-kong.txt /opt/urlfinder-kong.txt | sort -u >> /opt/help1-js-files.txt

cat live-subdomains.txt | hakrawler -u -i -insecure >> /opt/hakrawler-urls.txt
cat /opt/hakrawler-urls.txt | grep = | qsreplace salaar >> /opt/hakrawler-params.txt
cat /opt/hakrawler-urls.txt | grep .js >> /opt/hakrawler-js-files.txt
cat /opt/hakrawler-urls.txt | grep -Ei "token=|key=|apikey=|access_token=|secret=|auth=|password=|session=|jwt=|bearer=|Authorization=|Bearer |eyJ|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY" >> /opt/hakrawler-kong.txt
cat /opt/hakrawler-urls.txt | grep -Ei "wp-content|wp-login|wp-admin|wp-includes|wp-json|xmlrpc.php|wordpress|wp-config|wp-cron.php" >> /opt/hakrawler-wordpress.txt
rm /opt/hakrawler-urls.txt

#for domain in $(cat subdomains.txt); do  
#    curl -s "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original" | sort -u >> /opt/wayback-urls.txt  
#    sleep $((RANDOM % 5 + 3))  # Random delay (3-7 seconds)
#done

#cat /opt/wayback-urls.txt   | grep = | qsreplace salaar >> /opt/way-params.txt
#cat /opt/wayback-urls.txt   | grep .js >> /opt/way-js-files.txt
#cat /opt/wayback-urls.txt   | grep -Ei "token=|key=|apikey=|access_token=|secret=|auth=|password=|session=|jwt=|bearer=|Authorization=|Bearer |eyJ|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY" >> /opt/way-kong.txt
#cat /opt/wayback-urls.txt   | grep -Ei "wp-content|wp-login|wp-admin|wp-includes|wp-json|xmlrpc.php|wordpress|wp-config|wp-cron.php" >> /opt/way-wordpress.txt
#rm  /opt/wayback-urls.txt

#cat live-subdomains.txt | gau >> /opt/hakrawler-urls.txt
#cat /opt/gau-urls.txt   | grep = | qsreplace salaar >> /opt/gau-params.txt
#cat /opt/gau-urls.txt   | grep .js >> /opt/gau-js-files.txt
#cat /opt/gau-urls.txt   | grep -Ei "token=|key=|apikey=|access_token=|secret=|auth=|password=|session=|jwt=|bearer=|Authorization=|Bearer |eyJ|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY" >> /opt/gau-kong.txt
#cat /opt/gau-urls.txt   | grep -Ei "wp-content|wp-login|wp-admin|wp-includes|wp-json|xmlrpc.php|wordpress|wp-config|wp-cron.php" >> /opt/gau-wordpress.txt
#rm /opt/gau-urls.txt

# Separating js Files, PArameters 
cat /opt/katana-params.txt /opt/urlfinder-params.txt /opt/hakrawler-params.txt /opt/way-params.txt /opt/gau-params.txt | sort -u >> params.txt
rm /opt/katana-params.txt /opt/urlfinder-params.txt /opt/hakrawler-params.txt /opt/way-params.txt /opt/gau-params.txt

cat /opt/katana-js-files.txt /opt/urlfinder-params.txt /opt/hakrawler-params.txt /opt/way-js-files.txt /opt/gau-js-files.txt | sort -u >> js-files.txt
rm /opt/katana-js-files.txt /opt/urlfinder-params.txt /opt/hakrawler-params.txt /opt/way-js-files.txt /opt/gau-js-files.txt

cat /opt/katana-kong.txt /opt/urlfinder-kong.txt /opt/hakrawler-kong.txt /opt/way-kong.txt /opt/gau-kong.txt | sort -u >> key-urls.txt
rm /opt/katana-kong.txt /opt/urlfinder-kong.txt /opt/hakrawler-kong.txt /opt/way-kong.txt /opt/gau-kong.txt

cat /opt/katana-wordpress.txt /opt/urlfinder-wordpress.txt /opt/hakrawler-wordpress.txt /opt/way-wordpress.txt /opt/gau-wordpress.txt | sort -u >> wordpress-urls.txt
rm /opt/katana-wordpress.txt /opt/urlfinder-wordpress.txt /opt/hakrawler-wordpress.txt /opt/way-wordpress.txt /opt/gau-wordpress.txt 


# Fuzzing Js Files 
cat js-files.txt | nuclei -t /root/nuclei-templates/http/exposures/ -nh >> nuclei-js-results.txt
cat js-files.txt | mantra >> js-mantra-results.txt

# Fuzzing Params for XSS
cat params.txt | qsreplace '<u>hyper</u>' | while read host do ; do curl --silent --path-as-is -L --insecure "$host" | grep -qs "<u>hyper" && echo "$host"; done | tee htmli.txt 

# Fuzzing Params for HTMli
cat params.txt | qsreplace 'https://example.com/' | while read host do ; do curl -s -L $host  | grep "<title>Example Domain</title>" && echo "$host" ; done | tee open-redirects.txt

# Fuzzing Params for SSTi
#cat params.txt | while read url; do tplmap -u "$url"; done


# Command Injection

# LFI

# 





# Fuzzing Domains
cat live-subdomains.txt  | nuclei -t /root/nuclei-templates/ -s low -rl 3 -c 2 >> nuclei.txt
cat live-subdomains.txt  | nuclei -t /root/nuclei-templates/ -s medium -rl 3 -c 2 >> nuclei.txt
cat live-subdomains.txt  | nuclei -t /root/nuclei-templates/ -s unknown -rl 3 -c 2 >> nuclei.txt
cat live-subdomains.txt  | nuclei -t /root/nuclei-templates/ -s high -rl 3 -c 2 >> nuclei.txt
cat live-subdomains.txt  | nuclei -t /root/nuclei-templates/ -s critical -rl 3 -c 2 >> nuclei.txt

# SQLMAP
#cat params.txt | grep -Ei 'select|report|role|update|query|user|name|sort|where|search|params|process|row|view|table|from|sel|results|sleep|fetch|order|keyword|column|field|delete|string|number|filter' | python3 /opt/sqlmap/sqlmap.py --batch --banner



