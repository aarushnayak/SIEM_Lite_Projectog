# 🛡️ SIEM Lite — Security Information & Event Management System

> A lightweight, Python-based SIEM system that monitors network logs, detects brute-force attacks in real time, and visualizes security alerts through a Flask web dashboard.

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-Web%20Dashboard-black?style=flat-square&logo=flask)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![CI](https://github.com/aarushnayak/SIEM_Lite_Projectog/actions/workflows/python-package.yml/badge.svg)

---

## 📌 Table of Contents. 

- [Overview](#-overview)
- [Features](#-features)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Usage](#-usage)
- [Input & Output](#-input--output)
- [Dashboard](#-dashboard)
- [Technologies Used](#-technologies-used)
- [Author](#-author)

---

## 🔍 Overview

**SIEM Lite** is a cybersecurity project that simulates a real-world Security Information and Event Management (SIEM) system. It parses authentication logs, detects malicious activity such as brute-force login attempts, stores alerts in a local SQLite database, and displays everything on a live web dashboard.


## ✨ Features

- 🔐 **Real-time Log Parsing** — Reads and parses authentication log files
- 🚨 **Brute-Force Detection** — Automatically detects IPs with repeated failed login attempts
- 📊 **Flask Web Dashboard** — Visual interface to view and manage security alerts
- 🗄️ **SQLite Database** — Persistent storage of all parsed logs and alerts
- 📦 **Fake Log Generator** — Simulates real-world login traffic for testing
- 🌐 **Packet Sniffer** — Live network traffic monitoring using Scapy
- ✅ **CI/CD with GitHub Actions** — Automated testing on every push

---

## 📁 Project Structure

```
SIEM_Lite_Project/
│
├── scripts/
│   ├── siem_lite.py              # Core SIEM engine — log parsing & alert detection
│   ├── siem_lite_v2.py           # Improved version with enhanced detection
│   ├── flask_app.py              # Web dashboard backend (Flask)
│   ├── siem_db.py                # Database models and queries (SQLite)
│   ├── log_generator.py          # Fake log generator for testing
│   ├── log_generator_v2.py       # Enhanced log generator
│   ├── packet_sniffer.py         # Live network packet capture (Scapy)
│   ├── alerts_viewer.py          # CLI-based alerts viewer
│   ├── check_db.py               # Database inspection utility
│   ├── windows_log_collector.py  # Windows Event Log collector
│   ├── requirements.txt          # Python dependencies
│   └── templates/
│       ├── dashboard.html        # Main web dashboard UI
│       └── map_test.html         # IP geolocation map view
│
├── logs/
│   ├── auth_dummy.log            # Sample authentication log file
│   ├── alerts.csv                # Exported alerts in CSV format
│   ├── alerts_viewed.csv         # Viewed alerts tracker
│   ├── parsed_logs.csv           # All parsed log entries
│   └── siem_lite.db              # SQLite database
│
├── .github/
│   └── workflows/
│       └── python-package.yml    # GitHub Actions CI/CD pipeline
│
└── .venv/                        # Python virtual environment
```

---

## ⚙️ Installation

### Prerequisites

- Python 3.11+
- Git
- pip

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/aarushnayak/SIEM_Lite_Projectog.git
cd SIEM_Lite_Projectog

# 2. Create virtual environment
python3 -m venv .venv

# 3. Activate virtual environment
# macOS/Linux:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

# 4. Install dependencies
pip install -r scripts/requirements.txt
```

---

## 🚀 Usage

### Run the Core SIEM Engine
```bash
python scripts/siem_lite.py
```

### Launch the Web Dashboard
```bash
python scripts/flask_app.py
```
Then open your browser and go to: `http://localhost:5000`

### Generate Fake Logs (for testing)
```bash
python scripts/log_generator.py
```

### View Alerts via CLI
```bash
python scripts/alerts_viewer.py
```

### Inspect the Database
```bash
python scripts/check_db.py
```

### Run Packet Sniffer (requires sudo on macOS/Linux)
```bash
sudo python scripts/packet_sniffer.py
```

---

## 📥 Input & Output

### 📥 Input

| Source | Description |
|--------|-------------|
| `logs/auth_dummy.log` | Authentication log file with login events |
| Live network traffic | Captured via Scapy packet sniffer |
| Fake generated logs | Simulated via `log_generator.py` |

**Sample Input Log Format:**
```
2026-10-10T12:51:58 118.172.155.122 FailedLogin
2026-10-10T12:51:59 118.172.155.122 FailedLogin
2026-10-10T12:52:00 42.113.204.11  SuccessfulLogin
```

---

### 📤 Output

| Output | Description |
|--------|-------------|
| Terminal logs | Real-time parsed events and alerts |
| `logs/alerts.csv` | All detected security alerts |
| `logs/parsed_logs.csv` | All parsed log entries |
| `logs/siem_lite.db` | SQLite database with full history |
| Web Dashboard | Visual alert management at `localhost:5000` |

**Sample Terminal Output:**
```
PARSED: 2026-10-10T12:51:58  118.172.155.122  FailedLogin
PARSED: 2026-10-10T12:51:59  118.172.155.122  FailedLogin
ALERT:  BruteForce - 118.172.155.122 - 5 failed logins within 60s
ALERT:  BruteForce - 118.172.155.122 - 21 failed logins within 60s
```

**Detection Logic:**
- ⚠️ Alert triggered when **5+ failed logins** from the same IP within **60 seconds**
- 🔴 Critical alert at **20+ failed logins** within 60 seconds

---

## 📊 Dashboard

The Flask web dashboard provides:

- 📋 Live table of all security alerts
- 🌍 IP geolocation map view
- ✅ Mark alerts as viewed
- 📁 Export alerts to CSV
- 🔍 Filter by IP, time, or severity

---

## 🛠️ Technologies Used

| Technology | Purpose |
|------------|---------|
| Python 3.11 | Core programming language |
| Flask | Web dashboard framework |
| Scapy | Packet sniffing & network monitoring |
| SQLite | Local database for alert storage |
| Faker | Fake log data generation |
| GitHub Actions | CI/CD automation |
| HTML/CSS | Dashboard frontend |

---

## 👨‍💻 Author

**Aarush Nayak**  
🔗 [GitHub](https://github.com/aarushnayak)

---

> ⭐ If you found this project useful, consider giving it a star on GitHub!
