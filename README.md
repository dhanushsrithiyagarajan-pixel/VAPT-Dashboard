# VAPT-Lab: Vulnerability Assessment Dashboard

## Overview

This project is a Flask-based Vulnerability Assessment and Penetration Testing (VAPT) Dashboard developed for educational purposes in a controlled laboratory environment.

The dashboard allows users to upload Nmap XML scan results, analyze discovered hosts, display open ports and services, classify risk levels, and generate security assessment results.

> **Disclaimer:** This project is intended only for legal testing in a lab environment using intentionally vulnerable systems such as DVWA and Metasploitable 2.

---

## Features

- Upload Nmap XML Scan Reports
- Automatic XML Parsing
- Display Target IP Address
- Display Open Ports
- Display Running Services
- Risk Classification
- Professional Dashboard
- Flask Web Interface

---

## Tools Used

- Kali Linux
- VMware Workstation
- Flask
- Python
- Nmap
- Burp Suite Professional
- OWASP ZAP
- DVWA
- Metasploitable 2

---

## Folder Structure

```text
app.py
templates/
static/
scans/
docs/
screenshots/
reports/
```

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/VAPT-Lab.git

cd VAPT-Lab

python3 -m venv venv

source venv/bin/activate

pip install -r requirements.txt

python app.py
```

## Author

Dhanushsri Thiyagarajan

B.E Computer Science (Cyber Security)

Internship Project
