# 🛡️ Cybersecurity Log Analyzer & Threat Detection Dashboard

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask-green.svg)](https://flask.palletsprojects.org/)
[![Testing](https://img.shields.io/badge/Testing-Pytest-orange.svg)](https://docs.pytest.org/)
[![Security](https://img.shields.io/badge/Domain-Cybersecurity%20%26%20Log%20Forensics-red.svg)](https://csrc.nist.gov/)

A modern, web-based Cybersecurity Log Analyzer and Threat Detection Engine built with **Python & Flask**. Designed for security analysts, incident responders, and system administrators to parse raw server logs, detect anomalous behavioral patterns (brute-force attacks, unauthorized access attempts, error spikes), and visualize security metrics on an interactive web dashboard.

---

## 🌟 Key Features

- **Multi-Format Log Parser**: Automatically parses Apache/Nginx web logs, Syslog, auth logs, and generic application log formats.
- **Automated Anomaly & Threat Detection**:
  - Brute-force authentication attempt identification.
  - IP reputation and request rate-limiting alerts.
  - High error rate spikes (HTTP 4xx / 5xx responses).
  - Suspicious user-agents and payload indicators.
- **Interactive Web Dashboard**:
  - Live upload for raw `.log` and `.txt` files.
  - Instant bundled sample log demonstration mode.
  - Interactive statistical charts and severity breakdown cards.
- **Data Export & Reporting**: Download forensic analysis reports in JSON and CSV formats.
- **Configurable Anomaly Thresholds**: Custom query parameters and threshold tuning for specific log volumes.
- **Automated Unit Testing Suite**: Pytest suite ensuring parser and analyzer accuracy.

---

## 🏗️ Project Architecture

```
Log Analyzer/
├── app.py              # Flask web application & REST API routes
├── log_analyzer.py     # Log analyzer core engine & anomaly detection algorithms
├── log_parser.py       # Multi-format log line parser
├── requirements.txt    # Python dependencies (Flask, Flask-CORS, Pytest)
├── sample_logs/        # Bundled sample log datasets for testing & demonstration
│   └── sample.log
├── static/             # Frontend assets (CSS styles & JavaScript interactivity)
├── templates/          # Jinja2 HTML templates for the dashboard UI
│   └── index.html
└── tests/              # Unit tests for parser and detection engine
```

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.9+** installed on your system.
- `pip` (Python package manager).

### Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/eman2005fatima/Log-Analyzer.git
   cd Log-Analyzer
   ```

2. **Create and Activate Virtual Environment** (Optional but recommended):
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## ⚡ Running the Application

Launch the Flask server locally:

```bash
python app.py
```

Then open your browser and navigate to:  
👉 `http://127.0.0.1:5000`

---

## 🧪 Running Unit Tests

To run the automated test suite with Pytest:

```bash
pytest
```

---

## 👤 Author

Developed by **Eman Fatima**  
📧 Email: [emanmubashir2005@gmail.com](mailto:emanmubashir2005@gmail.com)  
🌐 GitHub: [@eman2005fatima](https://github.com/eman2005fatima)

---

## 📄 License

This project is licensed under the MIT License for educational and cybersecurity research purposes.
