# 🔍 Python Advanced Port Scanner

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-green.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

---

## 📖 Overview

Python Advanced Port Scanner is a command-line tool built using Python socket programming and multithreading.

It scans a target IP or hostname, detects open TCP ports, identifies services, and optionally grabs service banners.

This tool is made for **educational purposes and authorized security testing only**.
## 🚀 Installation & Run

### 1️⃣ Clone Repository
```bash
git clone https://github.com/adityainfose/Python-Port-Scanner.git
cd Python-Port-Scanner
python3 port_scanner.py

---

## 🎯 Features

- Multithreaded port scanning  
- Detect open TCP ports  
- Service identification using built-in port list  
- Banner grabbing (optional)  
- Quick scan, custom range scan, and full scan  
- Export results to JSON and CSV  
- Colored terminal output  
- Graceful exit using Ctrl+C  

---

## 📌 Scan Options

1 → Quick Scan (common ports)  
2 → Custom Range Scan (example: 1-1000)  
3 → Full Scan (1-65535)

**Extra options:**
- Enable banner grabbing  
- Set number of threads  
- Export results in JSON or CSV  

---

## 🛠 Technologies Used

- Python 3  
- Socket Programming  
- Threading  
- Queue Module  
- JSON & CSV Handling  

---

## 📂 Project Structure---

## 🌐 Common Ports

| Port | Service |
|------|---------|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 110 | POP3 |
| 143 | IMAP |
| 443 | HTTPS |
| 3306 | MySQL |
| 3389 | RDP |

---

## ⚠️ Disclaimer

This tool is developed for educational purposes only.  

Use it only on systems you own or have explicit permission to test.  

Unauthorized scanning is illegal.

---

## 👨‍💻 Author

**Aditya**  
Cybersecurity Enthusiast  

GitHub: https://github.com/adityainfose
