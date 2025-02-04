# Cyber-security---Phishing-link-Scanner-ChatGPT

A phishing link scanner is a cybersecurity tool designed to detect and analyze potentially malicious URLs that cybercriminals use for phishing attacks. These scanners help protect users from scams, malware, and credential theft by identifying suspicious links before they are accessed.

import re
import requests
from urllib.parse import urlparse

def is_suspicious_url(url):
    # Heuristic checks for suspicious URLs
    phishing_patterns = [
        r"login.*", r"update.*", r"verify.*", r"account.*",
        r"secure.*", r"webscr.*", r"banking.*", r"ebayisapi.*"
    ]
    
    for pattern in phishing_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    return False

def check_url_blacklist(url):
    # Check URL against OpenPhish or PhishTank (simulated here)
    blacklist = ["badwebsite.com", "phishingsite.net", "malicious.co"]
    parsed_url = urlparse(url).netloc
    return parsed_url in blacklist

def get_domain_reputation(url):
VirusTotal (replace 'your_api_key' with an actual key)
    api_key = "your_api_key"
    vt_url = f"https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key}
    data = {"url": url}
    
    response = requests.post(vt_url, headers=headers, data=data)
    if response.status_code == 200:
        result = response.json()
        return result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return None

def scan_url(url):
    print(f"Scanning URL: {url}\n")
    
    if check_url_blacklist(url):
        print("Warning! The URL is blacklisted.")
        return
    
    if is_suspicious_url(url):
        print("Caution! The URL contains suspicious patterns.")
    
    reputation = get_domain_reputation(url)
    if reputation:
        print("Reputation Analysis:", reputation)
    else:
        print("Could not retrieve reputation analysis.")

if __name__ == "__main__":
    test_url = input("Enter a URL to scan: ")
    scan_url(test_url)
    
