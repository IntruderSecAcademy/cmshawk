# CMSHawk 🦅 – Advanced CMS Exploit Scanner

CMSHawk is an automated vulnerability scanner that detects and analyzes security flaws in popular Content Management Systems (**WordPress, Joomla, Drupal**). It scans for outdated plugins, misconfigurations, admin panel exposure, and known exploits.

## 🚀 Features
✅ **CMS Detection** – Identifies whether the target is running WordPress, Joomla, or Drupal.  
✅ **Version Enumeration** – Extracts the CMS version and checks if it's outdated.  
✅ **Vulnerability Scanner** – Matches detected versions with known security flaws.  
✅ **Admin Panel Finder** – Locates login pages and exposed admin panels.  
✅ **Outdated Plugin & Theme Scanner** – Detects insecure plugins and themes.  
✅ **Exploit Database Integration** – Checks for public exploits based on vulnerabilities.  
✅ **JSON Report Generation** – Saves scan results for analysis and documentation.  

## 📦 Installation
Clone the repository and install dependencies:
```bash
# Clone the repo
git clone https://github.com/IntruderSecAcademy/cmshawk.git  
cd CMSHawk  

# Install dependencies
pip install -r requirements.txt  
```

## 🛠️ Usage
Run CMSHawk to scan a website:
```bash
python CMSHawk.py
```
Enter the target website URL when prompted.

## 🔍 Example Output
```
[+] Detecting CMS...
[+] CMS Detected: WordPress
[+] Checking version...
[+] CMS Version: 5.8
[+] Checking for known vulnerabilities...
[+] Vulnerabilities: SQL Injection Vulnerability
[+] Searching for admin panel...
[+] Admin Panel: https://example.com/wp-admin
[+] Scanning for outdated plugins and themes...
[+] Outdated Plugins/Themes: Found
[+] Scan results saved to cms_scan_results.json
```

## ⚠️ Disclaimer
CMSHawk is intended for **ethical security research and penetration testing only**. Unauthorized scanning of websites **without permission** is illegal and punishable under cybersecurity laws. Use responsibly.

## 🤝 Contributions & Issues
Contributions are welcome! Feel free to submit **feature requests**, **bug reports**, or **pull requests**.

## 📜 License
This project is licensed under the **MIT License**.

## 🌐 Connect
📧 Email: support@intrudersec.in  
🐦 Twitter: [@IntruderSec](https://twitter.com/IntruderSec)
