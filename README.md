
# 🔥 RedHunter XSS Scanner - Advanced Automated XSS Detection

> **The most powerful open-source XSS scanner** with 300+ payloads and WAF bypass techniques


## 🌟 Features

- **300+ Curated Payloads** - All major XSS vectors covered  
- **WAF Evasion** - Specialized bypasses for Cloudflare, Akamai, etc.  
- **Multi-Threaded** - Lightning fast scanning  
- **Smart Detection** - Advanced reflection analysis  
- **Professional Reports** - Detailed `xss_bypasses.txt` output  
- **Stealth Mode** - Random delays and realistic user agents  

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/0xwanted/RedHunter-XSS-Scanner.git
cd RedHunter-XSS-Scanner

# Install dependencies
pip install -r requirements.txt

# Run the scanner
python3 redhunter.py
```


## 🎯 Use Cases

- **Bug Bounty Hunting** - Find XSS vulnerabilities faster  
- **Penetration Testing** - Comprehensive web app security audits  
- **CTF Challenges** - Perfect for web security competitions  
- **Security Research** - Study advanced XSS techniques  

## 📝 Sample Report

```text
[+] XSS FOUND!
[*] Parameter: search
[*] Type: SVG Vector
[*] Payload: <svg onload=alert(document.domain)>
[*] URL: https://example.com/search?q=%3Csvg%20onload%3Dalert%28document.domain%29%3E
[+] Vulnerability confirmed!
```

## 🛠️ Advanced Usage

```bash
# Scan with custom timeout (default: 6 seconds)
python3 redhunter.py --timeout 10

# Use proxy for scanning
python3 redhunter.py --proxy http://127.0.0.1:8080

# Save results to custom file
python3 redhunter.py --output custom_report.txt
```

## ⚠️ Legal Disclaimer

This tool is intended for:  
- Authorized security testing  
- Educational purposes  
- Ethical hacking research  

**Never** use it against systems you don't own or have explicit permission to test.

---

💻 **Happy Hunting!** Visit [0xwanted.wtf](https://0xwanted.wtf) for more .
```
