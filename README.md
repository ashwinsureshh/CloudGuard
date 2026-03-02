# CloudGuard 🛡️

CloudGuard is a real-time network intrusion detection system powered by machine learning and streaming analytics.

## Architecture

```
CloudGuard/
├── ml/          → Model training & preprocessing (Person 1)
├── backend/     → Flask API + Kafka producer (Person 2)
├── frontend/    → React dashboard (Person 3)
└── docker-compose.yml
```

## Components

| Component | Description |
|-----------|-------------|
| **ML** | Preprocesses network traffic data and trains an intrusion detection model |
| **Backend** | Flask + SocketIO API serving real-time alerts; Kafka producer for streaming |
| **Frontend** | React dashboard displaying live traffic stats and attack alerts |

## Getting Started

### Prerequisites
- Python 3.9+
- Node.js 18+
- Docker & Docker Compose
- Apache Kafka

### Run with Docker
```bash
docker-compose up --build
```

### Run individually

**Backend:**
```bash
cd backend
pip install -r requirements.txt
python app.py
```

**Frontend:**
```bash
cd frontend
npm install
npm start
```

## Dataset
The dataset used for training is too large for GitHub. Download it separately and place it in `ml/data/`.

## Model Files
Model files are shared via Google Drive. Place them in `backend/model/` and `ml/model/`.

## Team
- Person 1 — ML & Data Pipeline
- Person 2 — Backend API & Kafka
- Person 3 — Frontend Dashboard
