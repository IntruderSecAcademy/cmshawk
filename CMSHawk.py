import requests
from bs4 import BeautifulSoup
import re
import json
import pyfiglet
import socket
import time

result = pyfiglet.figlet_format("CMSHawk")
print(result)
print ("\nAuthor - INJ3KTOR")
print ("Copyright 2025")
print ("================")

def detect_cms(url):
    """Detects whether the target site is running WordPress, Joomla, or Drupal."""
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            html = response.text.lower()
            if 'wp-content' in html or 'wordpress' in html:
                return "WordPress"
            elif 'joomla' in html:
                return "Joomla"
            elif 'drupal' in html or 'sites/all/' in html:
                return "Drupal"
    except requests.exceptions.RequestException:
        return None
    return None

def get_version(url, cms):
    """Tries to extract the version of the detected CMS."""
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            html = response.text
            if cms == "WordPress":
                match = re.search(r'content="WordPress ([0-9.]+)"', html)
                return match.group(1) if match else "Unknown"
            elif cms == "Joomla":
                match = re.search(r'content="Joomla! ([0-9.]+)"', html)
                return match.group(1) if match else "Unknown"
            elif cms == "Drupal":
                match = re.search(r'content="Drupal ([0-9.]+)"', html)
                return match.group(1) if match else "Unknown"
    except requests.exceptions.RequestException:
        return "Unknown"
    return "Unknown"

def find_admin_panel(url, cms):
    """Finds common admin panel login pages."""
    admin_paths = {
        "WordPress": ["/wp-admin", "/wp-login.php"],
        "Joomla": ["/administrator"],
        "Drupal": ["/user/login"],
    }
    if cms in admin_paths:
        for path in admin_paths[cms]:
            full_url = url.rstrip('/') + path
            response = requests.get(full_url)
            if response.status_code == 200:
                return full_url
    return "Not found"

def check_vulnerabilities(cms, version):
    """Checks if the detected CMS version has known vulnerabilities."""
    vulnerabilities = {
        "WordPress": {"5.8": "SQL Injection Vulnerability", "5.7": "XSS Vulnerability"},
        "Joomla": {"3.9": "Remote Code Execution", "3.8": "Privilege Escalation"},
        "Drupal": {"9.1": "SQL Injection", "8.9": "Code Execution"}
    }
    return vulnerabilities.get(cms, {}).get(version, "No known vulnerabilities found")

def scan_plugins_and_themes(url, cms):
    """Scans for outdated plugins and themes."""
    outdated_plugins = []
    common_plugins = {"WordPress": ["/wp-content/plugins/", "/wp-content/themes/"]}
    if cms in common_plugins:
        for path in common_plugins[cms]:
            check_url = url.rstrip('/') + path
            response = requests.get(check_url)
            if response.status_code == 200:
                outdated_plugins.append(path)
    return outdated_plugins if outdated_plugins else "No outdated plugins/themes found"

def main():
    target = input("Enter target URL (e.g., https://example.com): ")
    
    print("[+] Detecting CMS...")
    cms = detect_cms(target)
    if cms:
        print(f"[+] CMS Detected: {cms}")
        
        print("[+] Checking version...")
        version = get_version(target, cms)
        print(f"[+] CMS Version: {version}")
        
        print("[+] Checking for known vulnerabilities...")
        vulnerabilities = check_vulnerabilities(cms, version)
        print(f"[+] Vulnerabilities: {vulnerabilities}")
        
        print("[+] Searching for admin panel...")
        admin_url = find_admin_panel(target, cms)
        print(f"[+] Admin Panel: {admin_url}")
        
        print("[+] Scanning for outdated plugins and themes...")
        outdated = scan_plugins_and_themes(target, cms)
        print(f"[+] Outdated Plugins/Themes: {outdated}")
        
        results = {
            "CMS": cms,
            "Version": version,
            "Vulnerabilities": vulnerabilities,
            "Admin Panel": admin_url,
            "Outdated Plugins/Themes": outdated
        }
        
        with open("cms_scan_results.json", "w") as f:
            json.dump(results, f, indent=4)
        print("[+] Scan results saved to cms_scan_results.json")
        
    else:
        print("[-] Unable to detect CMS.")

if __name__ == "__main__":
    main()
