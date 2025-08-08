# AI Centre Security Assessment

This repository contains the security assessment report, Python scripts, and evidence files for the security testing of `ai-centre.pk`.  
The assessment was performed as part of a cybersecurity internship task, focusing on **Passive Reconnaissance** and **Safe Active Reconnaissance**.

---

## 📌 Project Overview
The purpose of this assessment was to identify potential security weaknesses in the target website using non-intrusive techniques and publicly available information.  
The tasks included WHOIS lookups, DNS enumeration, HTTP header analysis, clickjacking testing, and directory listing checks.

---

## 🛠 Tools & Technologies Used
- **Python 3**
  - whois
  - dnspython
  - requests
  - python-nmap
- **Burp Suite Community Edition**
- **Browser Developer Tools** (Chrome/Firefox)
- **Online Tools:** crt.sh, whois.com

---

## 📂 Repository Structure

│
├── report.docx # Security assessment report
├── scripts/ # Python scripts used for the assessment
├── findings/ # Collected evidence files (headers.json, whois.txt, etc.)
├── screenshots/ # Screenshots for findings
└── README.md # Project overview and documentation


---

## 🔍 Findings Summary
1. **Missing X-Frame-Options Header** – Potential for clickjacking attacks.
2. **Missing Content-Security-Policy (CSP)** – Risk of XSS and data injection.
3. **Missing Strict-Transport-Security (HSTS)** – Risk of HTTPS downgrade attacks.

---

## 📸 Evidence
Evidence for each finding is included in the `screenshots/` folder and referenced in the report.

---

## 📜 Author
**Name:** Hafsa Munir  
**Role:** Cybersecurity Intern (Red Team : Nebula ) 
**Date:** August 8, 2025

