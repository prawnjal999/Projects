# Web Security Scanner

A Python-based web security tool that analyzes a target system by scanning open ports, checking SSL/TLS configuration, inspecting HTTP security headers, and generating structured risk assessment reports.

---

## Features

* Port Scanning (common ports like 80, 443, 22, 21)
* SSL/TLS Detection (checks if HTTPS is enabled)
* Security Header Analysis:

  * Content-Security-Policy (CSP)
  * Strict-Transport-Security (HSTS)
  * X-Frame-Options
  * X-Content-Type-Options
* Risk Classification (Low / Medium / High)
* Automated Report Generation

---

## Tech Stack

* Python
* Socket Programming
* Requests Library
* SSL Module

---

## Project Structure

```
web-security-scanner/
│
├── main.py
├── requirements.txt
├── .gitignore
├── README.md
│
├── modules/
│   ├── port_scanner.py
│   ├── ssl_check.py
│   └── headers_check.py
```

---

## How to Run

```bash
cd web-security-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  (for linux)

# Install dependencies
pip install -r requirements.txt

# Run the scanner
python main.py
```

---

## Sample Output

<img width="748" height="417" alt="01-ouput" src="https://github.com/user-attachments/assets/7393c6ec-2690-482d-bdc5-bb076de35565" />

Example:

```
[+] Target set to: google.com

[+] Scanning ports...
[+] Port 80 is OPEN
[+] Port 443 is OPEN

[+] Checking SSL...
[+] SSL is ENABLED

[+] Checking security headers...
[!] Missing: Content-Security-Policy
[!] Missing: Strict-Transport-Security

[!] Risk Level: MEDIUM

[+] Report saved to reports/google.com_report.txt
```

---

## How It Works

1. Scans the target for open ports
2. Checks SSL/TLS availability
3. Analyzes HTTP security headers
4. Calculates a risk score based on findings
5. Generates a structured report

---

## Legal Disclaimer

This tool is intended for educational purposes only.
Use it only on systems you own or have explicit permission to test.
---

Your Name
