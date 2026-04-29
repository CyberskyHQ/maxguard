# maxguard
A network security scanner for PCI-DSS compliance in retail environments. Built with Python 3.11, Scapy, OpenAI gpt-4o-mini, and Streamlit. Captures live network traffic, flags PCI-DSS violations, and delivers AI-powered threat analysis via an interactive dashboard.
# Max-Guard: PCI-DSS Network Security Scanner

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Scapy](https://img.shields.io/badge/Scapy-2.7.0-green)
![Streamlit](https://img.shields.io/badge/Streamlit-1.56.0-red)
![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4o--mini-purple)

## Overview
Max-Guard is an AI-driven network security scanner designed to detect PCI-DSS v4.0 compliance threats in retail environments. It captures live network traffic, identifies unencrypted protocol violations, and uses GPT-4o-mini to generate professional compliance analysis reports.

## Features
- Live packet capture using Scapy
- Real-time PCI-DSS v4.0 violation detection
- AI-powered threat analysis using GPT-4o-mini
- Interactive Streamlit dashboard with charts and metrics
- Severity scoring and affected device identification
- Step-by-step investigation and remediation guides
- Export reports as JSON, CSV, and executive summary
- Cloud deployment via Streamlit Cloud
- Docker support for portable deployment

## Tech Stack
- **Python 3.11**
- **Scapy** — packet capture and network analysis
- **OpenAI GPT-4o-mini** — AI threat analysis
- **Streamlit** — interactive dashboard
- **Pandas** — data processing
- **Plotly** — charts and visualizations
- **Docker** — containerized deployment

## Project Structure
## Installation

### Local Setup
```bash
git clone https://github.com/ahmadalkhoudeir/maxguard.git
cd maxguard
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Environment Setup
Create a `.env` file in the root directory:
### Run the Dashboard
```bash
streamlit run dashboard/app.py
```

### Run with Docker
```bash
docker build -t maxguard:v1 .
docker run -d --name maxguard-app -p 8501:8501 -e OPENAI_API_KEY=your-key maxguard:v1
```

## Usage
1. Run as Administrator (required for packet capture)
2. Open the dashboard at http://localhost:8501
3. Click Start Live Scan or upload a scan_results.json file
4. View real-time violations, charts, and AI analysis
5. Export compliance reports

## PCI-DSS Violations Detected
| Protocol | Port | PCI-DSS Requirement |
|----------|------|---------------------|
| FTP | 21 | 4.2.1 |
| Telnet | 23 | 4.2.1 |
| HTTP | 80 | 4.2.1 |
| POP3 | 110 | 4.2.1 |
| IMAP | 143 | 4.2.1 |
| RDP | 3389 | 1.3.2 |
| HTTP-Alt | 8080 | 4.2.1 |

## Team
| Name | Role |
|------|------|
| Ahmad | Security Lead |
| Diana | Threat Researcher & Coder |
| Jaiden | System Architect & Coder |
| Nana | Security Support Analyst |
| Kenneth | Project Manager |

## Legal Disclaimer
Max-Guard is designed for authorized network security testing only. All scanning must be performed exclusively on networks you own or have explicit written permission to scan. Unauthorized network scanning may violate the Computer Fraud and Abuse Act (CFAA) and other applicable laws. The Max-Guard team is not responsible for any misuse of this tool.

## Academic Context
This project was developed as part of a cybersecurity course at Central Connecticut State University (CCSU). Deadline: May 11, 2026.