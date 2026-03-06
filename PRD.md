# CloudGuard — Product Requirements Document (PRD)

## 1. Overview

**Product Name:** CloudGuard
**Type:** Real-Time Network Intrusion Detection System (IDS)
**Version:** 1.0

CloudGuard is a machine-learning-powered network intrusion detection system that monitors network traffic in real time, classifies flows as benign or malicious, and surfaces live alerts and statistics through an interactive web dashboard.

---

## 2. Problem Statement

Traditional network security tools rely on signature-based detection that fails against novel or evolving attack patterns. Security teams also lack real-time visibility into traffic anomalies. CloudGuard addresses both gaps by applying a trained ML model to a live stream of network flows and presenting results instantly to operators.

---

## 3. Goals

| Goal | Description |
|------|-------------|
| Real-time detection | Classify network flows within seconds of capture |
| Multi-class classification | Distinguish between BENIGN, DDoS, PortScan, BruteForce, and Infiltration traffic |
| Live visibility | Push alerts and statistics to a web dashboard the moment they occur |
| Resilience | System must continue producing output (via simulation fallback) even when Kafka or the ML model is unavailable |
| Cross-platform | Must run on macOS and Windows via Docker |

---

## 4. Users

| User | Description |
|------|-------------|
| Network Security Analyst | Primary user — monitors the dashboard for active threats |
| System Administrator | Deploys and maintains the Docker stack |
| ML Engineer (internal) | Trains and updates the detection model |

---

## 5. Functional Requirements

### 5.1 ML Pipeline

| ID | Requirement |
|----|-------------|
| ML-01 | Ingest and preprocess the CIC-IDS2017 network traffic dataset (CSV format) |
| ML-02 | Remove duplicates, infinite values, and null rows |
| ML-03 | Encode attack-type labels with a `LabelEncoder` |
| ML-04 | Normalise features with `StandardScaler` |
| ML-05 | Train a `RandomForestClassifier` with stratified 80/20 train-test split |
| ML-06 | Export four artefacts: `model.pkl`, `scaler.pkl`, `label_encoder.pkl`, `feature_cols.pkl` |
| ML-07 | Artefacts must be saved to `backend/model/` so the backend can load them without manual copying |
| ML-08 | Feature columns in `feature_cols.pkl` must match the field names sent in Kafka flow messages |

### 5.2 Backend API

| ID | Requirement |
|----|-------------|
| BE-01 | Expose a REST API on port `5001` |
| BE-02 | `GET /api/health` — return service status, model load status, and Kafka connection status |
| BE-03 | `GET /api/alerts?limit=N&offset=N` — return paginated alerts from the database |
| BE-04 | `GET /api/stats` — return aggregated totals: total flows, attacks detected, benign count, breakdown by attack type |
| BE-05 | `GET /api/attack-types` — return attack type counts |
| BE-06 | Consume network flow events from the Kafka topic `network-traffic` |
| BE-07 | Classify each consumed flow using the trained ML model |
| BE-08 | Fall back to mock traffic simulation when Kafka is unavailable |
| BE-09 | Fall back to weighted-random mock predictions when model artefacts are missing |
| BE-10 | Persist every classified alert to a SQLite database (`cloudguard.db`) |
| BE-11 | Emit `new_alert` and `stats_update` events over SocketIO to all connected clients |
| BE-12 | Replay the last 15 alerts to a client immediately on SocketIO connection |
| BE-13 | All endpoints must return structured JSON error responses on failure |
| BE-14 | Use Python `logging` (not `print`) for all runtime output |

### 5.3 Kafka Producer

| ID | Requirement |
|----|-------------|
| KP-01 | Publish network flow events to the `network-traffic` Kafka topic |
| KP-02 | Each event must include fields that match the feature columns expected by the ML model |
| KP-03 | Events must be JSON-serialised |

### 5.4 Frontend Dashboard

| ID | Requirement |
|----|-------------|
| FE-01 | Connect to the backend SocketIO server on startup |
| FE-02 | Display a live connection status indicator (Live / Disconnected) |
| FE-03 | Show stat cards: Total Flows, Attacks Detected, Benign Traffic, Detection Rate (%) |
| FE-04 | Show a bar chart of attack type counts |
| FE-05 | Show a pie chart of traffic distribution (attacks vs benign) |
| FE-06 | Show a live alert feed table: Time, Source IP, Destination Port, Attack Type, Confidence, Severity |
| FE-07 | Highlight attack rows in the alert table |
| FE-08 | Update all UI components in real time as SocketIO events arrive |
| FE-09 | Use `REACT_APP_API_URL` environment variable to configure the backend URL |

---

## 6. Non-Functional Requirements

| Category | Requirement |
|----------|-------------|
| Latency | Alert must appear on the dashboard within 2 seconds of being produced |
| Persistence | Alerts must survive a backend restart (SQLite volume-mounted on the host) |
| Portability | Full stack must run with a single `docker-compose up --build` on macOS and Windows |
| Fallback | Backend must remain operational without Kafka or model files present |
| Scalability | Not a requirement for v1.0 — single-broker, single-backend deployment is sufficient |

---

## 7. System Architecture

```
┌─────────────────┐        ┌───────────────┐        ┌──────────────────┐
│  kafka_producer │──────▶ │  Apache Kafka │──────▶ │  kafka_consumer  │
│  (flow source)  │        │  :9092        │        │  (backend thread) │
└─────────────────┘        └───────────────┘        └────────┬─────────┘
                                                             │
                                                    ┌────────▼─────────┐
                                                    │    model.py      │
                                                    │  (ML inference)  │
                                                    └────────┬─────────┘
                                                             │
                                              ┌──────────────▼──────────────┐
                                              │         Flask API            │
                                              │   + SocketIO  + SQLite DB   │
                                              │         :5001                │
                                              └──────────────┬──────────────┘
                                                             │
                                                    ┌────────▼─────────┐
                                                    │  React Dashboard  │
                                                    │      :3000        │
                                                    └──────────────────┘
```

---

## 8. Out of Scope (v1.0)

- User authentication / login
- Multiple Kafka brokers or partitions
- Model versioning or A/B testing
- Historical trend analysis beyond what SQLite stores
- Packet capture integration (e.g. tcpdump, Suricata) — flows are produced by the Kafka producer
- Alerting integrations (email, Slack, PagerDuty)

---

## 9. Team

| Person | Responsibility |
|--------|---------------|
| Person 1 | ML pipeline — `ml/preprocess.py`, `ml/train_model.py` |
| Person 2 | Backend API — `backend/app.py`, `backend/kafka_consumer.py`, `backend/model.py`, `backend/database.py` |
| Person 3 | Frontend dashboard — `frontend/src/App.js`, `frontend/src/Dashboard.jsx` |
