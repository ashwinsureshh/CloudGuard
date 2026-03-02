# ⬡ CloudGuard — Cloud Intrusion Detection System

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.1-black?style=flat-square&logo=flask)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react)
![XGBoost](https://img.shields.io/badge/XGBoost-ML-orange?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

> A real-time network intrusion detection system for cloud environments — powered by XGBoost, streamed via Kafka, and visualized through a live React dashboard.

---

## 📌 Project Overview

CloudGuard is a full-stack cloud security project built for the **Cloud Computing (B22EF0604)** course. It detects network intrusions in real time by:

- Training an **XGBoost ML model** on the CIC-IDS2017 dataset (7 attack types)
- Streaming live network flows through **Apache Kafka**
- Serving predictions via a **Flask REST API + WebSockets**
- Visualizing alerts on a **React real-time dashboard**
- Deploying everything with **Docker Compose**

---

## 🎯 Attack Types Detected

| Attack | Description |
|---|---|
| DDoS | Distributed Denial of Service flood |
| PortScan | Network reconnaissance scanning |
| BruteForce | Repeated login attempts |
| Infiltration | Unauthorized access attempts |
| Web Attacks | SQL Injection, XSS |
| Botnet | Command & control traffic |
| BENIGN | Normal traffic |

---

## 🏗️ Architecture

```
CIC-IDS2017 Dataset
       ↓
Python ETL Pipeline (Person 1)
       ↓
XGBoost ML Model (96% F1-Score)
       ↓
Kafka Stream (simulates live traffic)
       ↓
Flask REST API + WebSockets (Person 2)
       ↓
React Dashboard — Live Alerts + Charts (Person 3)
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Machine Learning | Python, XGBoost, Scikit-learn, SMOTE |
| Data Processing | Pandas, NumPy |
| Streaming | Apache Kafka |
| Backend API | Flask, Flask-SocketIO, Flask-CORS |
| Frontend | React, Recharts, Chart.js |
| Monitoring | Prometheus, Grafana |
| DevOps | Docker, Docker Compose |
| Dataset | CIC-IDS2017 (Canadian Institute for Cybersecurity) |

---

## 📁 Project Structure

```
CloudGuard/
│
├── ml/                      # Machine Learning Pipeline
│   ├── preprocess.py        # Data cleaning & feature engineering
│   ├── train_model.py       # XGBoost training & evaluation
│   ├── requirements.txt
│   ├── data/                # Place dataset CSV files here
│   └── model/               # Trained model files (via Google Drive)
│
├── backend/                 # Flask REST API
│   ├── app.py               # Main API server
│   ├── kafka_producer.py    # Live traffic stream simulator
│   ├── requirements.txt
│   └── model/               # Receive model files from ML team
│
├── frontend/                # React Dashboard
│   ├── src/
│   │   ├── Dashboard.jsx    # Main dashboard component
│   │   └── App.js
│   └── package.json
│
├── docker-compose.yml       # One-command full deployment
├── .gitignore
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.11+
- Node.js 18+
- Docker Desktop
- Git

---

### 1. Clone the Repository

```bash
git clone https://github.com/ashwinsureshh/CloudGuard.git
cd CloudGuard
```

---

### 2. ML Pipeline (Person 1)

```bash
cd ml
pip install -r requirements.txt

# Place CIC-IDS2017 CSV files in ml/data/
python preprocess.py
python train_model.py

# Share model files with Person 2 via Google Drive:
# model.pkl, scaler.pkl, label_encoder.pkl, feature_list.pkl
```

---

### 3. Backend API (Person 2)

```bash
cd backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate        # Mac
venv\Scripts\activate           # Windows

pip install -r requirements.txt

# Place model files from Person 1 into backend/model/
python app.py
# API runs at http://localhost:5001
```

**API Endpoints:**

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Server status check |
| GET | `/api/alerts` | Last 20 detected alerts |
| GET | `/api/stats` | Detection statistics |
| GET | `/api/attack-types` | Attack breakdown for charts |

**WebSocket Events:**

| Event | Description |
|---|---|
| `new_alert` | Fires on every new detection |
| `stats_update` | Fires with updated counts |

---

### 4. Frontend Dashboard (Person 3)

```bash
cd frontend
npm install
npm start
# Dashboard runs at http://localhost:3000
```

Update the API base URL in `Dashboard.jsx`:
```javascript
// Replace with Person 2's local IP
const API_BASE = "http://192.168.x.x:5001/api";
```

---

### 5. Run Everything with Docker

```bash
# From root folder
docker-compose up --build
```

| Service | URL |
|---|---|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:5001 |
| Kafka | localhost:9092 |

---

## 👥 Team

| Role | Responsibility |
|---|---|
| **Person 1 — ML Engineer** | Dataset preprocessing, XGBoost model training, SMOTE balancing |
| **Person 2 — Backend Engineer** | Flask API, Kafka stream, WebSocket, Docker setup |
| **Person 3 — Frontend Engineer** | React dashboard, real-time charts, ELK stack, Kibana |

---

## 📊 Model Performance

| Metric | Score |
|---|---|
| Weighted F1-Score | ~96% |
| Dataset | CIC-IDS2017 |
| Algorithm | XGBoost |
| Features Used | 20 flow-level features |
| Class Imbalance | Handled with SMOTE |

---

## 📅 Development Timeline

| Week | Milestone |
|---|---|
| Week 1-2 | Dataset exploration & preprocessing |
| Week 3 | XGBoost model training |
| Week 4 | Flask API + Kafka pipeline |
| Week 5 | React dashboard + API integration |
| Week 6 | Docker Compose + ELK stack |
| Week 7 | End-to-end testing |
| Week 8 | Final demo + report |

---

## 📂 Dataset

This project uses the **CIC-IDS2017** dataset by the Canadian Institute for Cybersecurity.

- Source: [UNB CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
- GitHub reference: [noushinpervez/Intrusion-Detection-CICIDS2017](https://github.com/noushinpervez/Intrusion-Detection-CICIDS2017)

> ⚠️ Dataset CSV files are NOT included in this repo due to size. Download separately and place in `ml/data/`

---

## 📜 License

MIT License — feel free to use this project for learning purposes.

---

## 🙏 Acknowledgements

- Canadian Institute for Cybersecurity for the CIC-IDS2017 dataset
- Cloud Computing Course — B22EF0604
