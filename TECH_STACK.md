# CloudGuard — Tech Stack

## Backend (Person 2)

| Technology | Version | Purpose |
|------------|---------|---------|
| Python | 3.11 | Runtime |
| Flask | 3.0.3 | REST API framework |
| Flask-SocketIO | 5.3.6 | WebSocket server for real-time events |
| Flask-CORS | 4.0.1 | Cross-origin request handling |
| eventlet | 0.36.1 | Async worker for SocketIO |
| kafka-python | 2.0.2 | Kafka consumer and producer client |
| scikit-learn | 1.4.2 | Loading and running the trained ML model |
| pandas | 2.1.4 | Flow data handling |
| numpy | 1.26.4 | Numerical operations for inference |
| SQLite | built-in | Alert persistence (via Python `sqlite3`) |
| gunicorn | 22.0.0 | Production WSGI server |

### Key files
```
backend/
├── app.py             # Flask app, SocketIO events, startup logic
├── database.py        # SQLite init, save_alert, get_alerts, get_stats
├── model.py           # Load model artefacts, predict(), mock fallback
├── kafka_consumer.py  # Kafka consumer daemon thread, Kafka fallback
├── kafka_producer.py  # Simulated traffic producer
├── Dockerfile
└── requirements.txt
```

---

## ML Pipeline (Person 1)

| Technology | Version | Purpose |
|------------|---------|---------|
| Python | 3.9+ | Runtime |
| pandas | 2.1.4 | Loading and cleaning the CIC-IDS dataset |
| numpy | 1.26.4 | Numerical operations |
| scikit-learn | 1.4.2 | Model training (`RandomForestClassifier`), `StandardScaler`, `LabelEncoder` |
| imbalanced-learn | 0.12.3 | Handling class imbalance in traffic dataset |
| matplotlib | 3.8.4 | Training result visualisation |
| seaborn | 0.13.2 | Training result visualisation |

### Key files
```
ml/
├── preprocess.py      # Data loading, cleaning, label encoding
├── train_model.py     # Model training, exports artefacts to backend/model/
├── data/              # Place CIC-IDS dataset CSV here (not in repo)
└── requirements.txt
```

### Model artefacts (saved to `backend/model/` after training)
| File | Contents |
|------|----------|
| `model.pkl` | Trained `RandomForestClassifier` |
| `scaler.pkl` | Fitted `StandardScaler` |
| `label_encoder.pkl` | Fitted `LabelEncoder` (maps class indices to attack names) |
| `feature_cols.pkl` | List of feature column names the model expects |

> **Important:** The feature column names in `feature_cols.pkl` must match the field names in the Kafka flow messages produced by `kafka_producer.py`. Coordinate with the backend person before finalising feature selection.

---

## Frontend (Person 3)

| Technology | Version | Purpose |
|------------|---------|---------|
| Node.js | 18+ | Runtime |
| React | 18.2.0 | UI framework |
| react-scripts | 5.0.1 | Build toolchain (Create React App) |
| socket.io-client | 4.7.4 | WebSocket client — connects to backend SocketIO |
| recharts | 2.12.4 | Bar chart and pie chart components |
| axios | 1.6.8 | HTTP client for REST API calls |

### Key files
```
frontend/
├── src/
│   ├── App.js         # SocketIO connection, state management
│   └── Dashboard.jsx  # All UI components (stat cards, charts, alert table)
├── public/
│   └── index.html
└── package.json
```

### SocketIO events (received from backend)
| Event | Payload | Description |
|-------|---------|-------------|
| `new_alert` | Alert object | Fired for every classified flow |
| `stats_update` | Stats object | Updated aggregated stats after every flow |

### REST endpoints available
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Service health, model status, Kafka status |
| GET | `/api/alerts?limit=N&offset=N` | Paginated alert history from DB |
| GET | `/api/stats` | Aggregated totals and attack breakdown |
| GET | `/api/attack-types` | Attack type counts |

### Alert object shape
```json
{
  "id":          "14:32:01_192.168.1.101_443",
  "timestamp":   "14:32:01",
  "src_ip":      "192.168.1.101",
  "dst_ip":      "10.0.0.42",
  "src_port":    52341,
  "dst_port":    443,
  "protocol":    "TCP",
  "attack_type": "DDoS",
  "confidence":  0.97,
  "severity":    "HIGH",
  "is_attack":   true
}
```

### Stats object shape
```json
{
  "total_flows":      1500,
  "attacks_detected": 320,
  "benign_count":     1180,
  "attack_breakdown": {
    "DDoS":        120,
    "PortScan":     95,
    "BruteForce":   70,
    "Infiltration": 35
  }
}
```

---

## Infrastructure

| Technology | Version | Purpose |
|------------|---------|---------|
| Docker | Latest | Container runtime |
| Docker Compose | 3.8 | Multi-container orchestration |
| Apache Kafka | 7.4.0 (Confluent) | Message broker for network flow streaming |
| Zookeeper | 7.4.0 (Confluent) | Kafka coordination service |

### Ports
| Service | Internal Port | Host Port |
|---------|--------------|-----------|
| Backend API | 5001 | 5001 |
| Frontend | 3000 | 3000 |
| Kafka (containers) | 9092 | 9092 |
| Kafka (host machine) | 29092 | 29092 |
| Zookeeper | 2181 | 2181 |

### Running the full stack
```bash
docker-compose up --build
```

### Running services individually (without Docker)
```bash
# Backend
cd backend && pip install -r requirements.txt && python app.py

# Frontend
cd frontend && npm install && npm start

# ML training
cd ml && pip install -r requirements.txt && python train_model.py
```

> When running without Docker, Kafka will not be available. The backend automatically falls back to the traffic simulator.
