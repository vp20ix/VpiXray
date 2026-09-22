# 🩻 VpiXray

> X-ray for the web. Nothing hides.

Web vulnerability scanner + recon suite in Python.

## Features

### Vulnerability Scanner (21 checks)
- SQL Injection (Error/Time/Blind)
- NoSQL Injection
- Command Injection
- SSTI (Server-Side Template Injection)
- SSRF, XXE, LFI
- Reflected XSS, CRLF Injection
- Host Header Injection, CORS Misconfig
- CSRF, IDOR, Directory Listing
- Open Redirect, Security Headers
- JWT Analyzer, Sensitive Files, Tech Fingerprint

### Recon Suite (8 checks)
- IP & Geolocation
- DNS Records
- WHOIS
- SSL/TLS Info
- Server Info + CDN detection
- HTTP Methods
- Port Scan (18 ports)
- Subdomain Enumeration (crt.sh)

## Quick Start

Step 1: Clone the repo

    git clone https://github.com/vp20ix/VpiXray.git
    cd VpiXray

Step 2: Setup virtual environment

    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

Step 3: Run

    python3 vpixray.py -u https://target.com --all
    python3 vpixray.py -u https://target.com --recon
    python3 vpixray.py -u https://target.com --recon --all
    python3 vpixray.py -u https://target.com --all -o report.json

## Legal Disclaimer

For authorized security testing ONLY.

Never scan targets without written permission.

Safe targets for testing:
- scanme.nmap.org
- Your own servers and domains
- DVWA (local)
- PortSwigger Web Security Academy

## Author

vp20ix - https://github.com/vp20ix

## License

MIT License - see LICENSE file.
