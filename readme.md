# 🛡️ Intelligent Security Audit System

An intelligent, automated auditing platform built using **Python** and **Next.js** for real-time vulnerability scanning and risk analysis across routers, PCs, and web servers. It provides actionable reports and an interactive dashboard to help system administrators strengthen their IT infrastructure.

---

## 🚀 Features

- 🔍 **Automated Security Audits**: Scans routers, personal computers, and web servers for vulnerabilities.
- 📊 **Real-Time Dashboard**: Visualizes audit results, threat levels, and system alerts.
- 🧠 **Intelligent Reporting**: Generates detailed reports with security scores and improvement recommendations.
- 🔐 **Role-Based Access Control (RBAC)**: Manages access for admins, auditors, and viewers.
- 📁 **Encrypted Logs**: Stores audit logs securely with data encryption.

---

## 🛠️ Tech Stack

| Technology      | Purpose                      |
|----------------|------------------------------|
| Python          | Backend logic, audit scripts |
| Next.js         | Frontend UI (React-based)    |
| Nmap/Scapy      | Network scanning & analysis  |
| MongoDB/PostgreSQL | Data storage (configurable) |
| Tailwind CSS    | UI styling                   |
| JWT/Auth        | Authentication & RBAC        |

---

## 📦 Installation

### Prerequisites

- Python 3.8+
- Node.js 16+
- MongoDB/PostgreSQL
- Nmap (for network scanning)

### Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # or .\venv\Scripts\activate on Windows
pip install -r requirements.txt
python app.py
