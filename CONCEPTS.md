# CloudGuard — Full Project Breakdown & Concept Guide

This file explains every part of the CloudGuard project from first principles.
Read it top to bottom and you will understand not just what the code does,
but *why* it is built this way and what every technology means.

---

## Table of Contents

1. [What Problem Are We Solving?](#1-what-problem-are-we-solving)
2. [System Architecture — The Big Picture](#2-system-architecture--the-big-picture)
3. [Concept: Network Intrusion Detection](#3-concept-network-intrusion-detection)
4. [Component 1 — ML Pipeline (`ml/`)](#4-component-1--ml-pipeline-ml)
5. [Concept: Machine Learning for Security](#5-concept-machine-learning-for-security)
6. [Component 2 — Apache Kafka](#6-component-2--apache-kafka)
7. [Component 3 — Backend API (`backend/`)](#7-component-3--backend-api-backend)
8. [Concept: REST APIs and WebSockets](#8-concept-rest-apis-and-websockets)
9. [Component 4 — Frontend Dashboard (`frontend/`)](#9-component-4--frontend-dashboard-frontend)
10. [Component 5 — Docker & Docker Compose](#10-component-5--docker--docker-compose)
11. [End-to-End Data Flow](#11-end-to-end-data-flow)
12. [Current State vs. Final Vision](#12-current-state-vs-final-vision)
13. [Key Terms Glossary](#13-key-terms-glossary)

---

## 1. What Problem Are We Solving?

Modern cloud applications run on networks. Every request, login attempt, and
file transfer is a **network flow** — a packet of data travelling between
machines. Most traffic is normal (browsing, API calls), but some is malicious:

- **DDoS** — Attacker floods the server with millions of fake requests to crash it
- **PortScan** — Attacker probes your machine to find open doors (ports)
- **BruteForce** — Attacker tries thousands of passwords per second
- **Infiltration** — Attacker who has partial access tries to move deeper

A **firewall** blocks known bad IPs. But modern attacks come from unknown
sources, use legitimate-looking traffic patterns, and evolve constantly.

CloudGuard's approach: **train a machine learning model** on millions of
historical network flows (labelled as attack/benign), then run that model
on live traffic and alert in real time.

---

## 2. System Architecture — The Big Picture

```
┌─────────────────────────────────────────────────────────────┐
│                     CloudGuard Pipeline                      │
│                                                             │
│  CIC-IDS2017         ml/              backend/    frontend/ │
│  Dataset CSV  ──►  preprocess.py  ──► app.py  ──► Dashboard │
│                        │                 ▲                  │
│                   train_model.py         │                  │
│                        │           kafka_producer.py        │
│                   model.pkl ────────────┘                   │
│                                    ▲                        │
│                               Apache Kafka                  │
│                            (message broker)                 │
└─────────────────────────────────────────────────────────────┘
```

In plain English:
1. **ML team** downloads a dataset of network flows, trains a model, exports it
2. **Kafka producer** generates (or reads real) network flows and streams them
3. **Backend** receives those flows via Kafka, runs the ML model on each one,
   pushes alerts to the frontend over WebSocket
4. **Frontend** displays everything live in a browser dashboard

---

## 3. Concept: Network Intrusion Detection

### What is a "network flow"?

A network flow is a summary of a connection between two machines. Instead of
logging every byte, you log statistics about the connection:

```
src_ip      = "192.168.1.101"   # Who sent it
dst_port    = 22                # Which service (22 = SSH)
duration    = 0.003             # How long the connection lasted
fwd_packets = 450               # Packets sent by attacker
bwd_packets = 2                 # Packets sent back (server barely responded)
```

A BruteForce SSH attack looks like: many short connections to port 22,
lots of forward packets, almost no replies (wrong password = connection reset).
A human logging in looks like: one connection, a few packets each way, then
a longer session.

The ML model learns these statistical fingerprints for each attack type.

### What is the CIC-IDS2017 dataset?

Created by the **Canadian Institute for Cybersecurity**. It contains:
- ~2.8 million labelled network flows
- 7 attack categories + benign traffic
- 80+ features per flow (packet size stats, timing, flag counts, etc.)

This is the "textbook" dataset used in academic intrusion detection research.

---

## 4. Component 1 — ML Pipeline (`ml/`)

### `ml/preprocess.py` — Cleaning Raw Data

Raw CSV data from CIC-IDS2017 is messy. This script fixes it:

```python
def clean_data(df):
    df = df.drop_duplicates()              # Remove exact duplicate rows
    df = df.replace([np.inf, -np.inf], np.nan)  # Infinity → NaN
    df = df.dropna()                       # Drop rows with missing values
    return df
```

**Why do infinite values appear?**
Some features are ratios (e.g., bytes per second). If duration is 0, you get
division by zero → infinity. These rows are unusable and must be dropped.

```python
def encode_labels(df, label_col="Label"):
    le = LabelEncoder()
    df["label_encoded"] = le.fit_transform(df[label_col])
    return df, le
```

**LabelEncoder** converts text labels to numbers:
```
"BENIGN"      → 0
"BruteForce"  → 1
"DDoS"        → 2
"Infiltration"→ 3
"PortScan"    → 4
```
ML models only understand numbers — not strings.

```python
def scale_features(X_train, X_test):
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)  # Note: only transform, not fit
    return X_train_scaled, X_test_scaled, scaler
```

**StandardScaler** normalises features to mean=0, std=1.
Without this, a feature like `packet_size` (range 0–65535) would overpower
a feature like `flag_count` (range 0–5) even if flag_count is more informative.

**Critical detail:** `scaler.fit_transform(X_train)` computes the mean/std
from training data. `scaler.transform(X_test)` uses *those same* values on
test data — it does NOT recompute. This prevents "data leakage" (using
future information to scale past data).

---

### `ml/train_model.py` — Training the Model

```python
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
```

**Train/test split:** 80% of data to train the model, 20% held out to
evaluate it honestly. `stratify=y` ensures each attack class appears in
both splits proportionally (important when DDoS is 15% and Infiltration is 5%).

```python
clf = RandomForestClassifier(
    n_estimators=100,   # 100 decision trees
    max_depth=20,       # Each tree can be at most 20 levels deep
    n_jobs=-1,          # Use all CPU cores in parallel
    random_state=42     # Reproducible results
)
clf.fit(X_train, y_train)
```

**What is a Random Forest?**
A Random Forest is an ensemble of Decision Trees.

A single **Decision Tree** splits data by asking yes/no questions:
```
Is dst_port == 22?
  YES → Is fwd_packets > 300?
          YES → BruteForce (90% confidence)
          NO  → BENIGN (75% confidence)
  NO  → ...
```

A **Random Forest** builds 100 such trees, each trained on a random subset
of the data and a random subset of features. For a new flow, all 100 trees
vote, and the majority wins. This reduces overfitting dramatically.

```python
# Save model artifacts
with open("model/model.pkl", "wb") as f:
    pickle.dump(clf, f)       # The trained model
with open("model/scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)    # The scaler (needed to scale live data the same way)
with open("model/label_encoder.pkl", "wb") as f:
    pickle.dump(le, f)        # To convert predicted number back to attack name
```

**Why save the scaler and label encoder too?**
At inference time (live traffic), you MUST scale new data using the exact
same mean/std used during training. If you refit the scaler on new data,
predictions will be garbage. Saving and reloading these objects guarantees
consistency.

---

## 5. Concept: Machine Learning for Security

### Classification vs. Anomaly Detection

There are two broad approaches to IDS:

| Approach | How it works | Pros | Cons |
|---|---|---|---|
| **Signature-based** | Block known bad patterns (like antivirus) | No false positives for known attacks | Misses new attacks |
| **Anomaly-based** | Flag anything unusual | Can catch new attacks | High false positive rate |
| **ML Classification** (CloudGuard) | Learn from labelled examples | High accuracy, catches known types | Needs labelled data, misses novel attacks |

### Key ML Metrics

After training, `classification_report` prints:

```
              precision  recall  f1-score

BENIGN           0.99     0.99      0.99
DDoS             0.97     0.95      0.96
PortScan         0.98     0.99      0.98
BruteForce       0.94     0.92      0.93
```

- **Precision:** Of all flows we called DDoS, how many actually were? (avoids false alarms)
- **Recall:** Of all actual DDoS flows, how many did we catch? (avoids missing attacks)
- **F1-Score:** Harmonic mean of precision and recall — the single best number to optimise

In security, **recall matters more** than precision. Missing a real attack
(false negative) is worse than a false alarm (false positive).

### Pickle — Saving Python Objects

`.pkl` files are Python's way of serialising (freezing) any object to disk:
```python
import pickle
pickle.dump(obj, open("file.pkl", "wb"))   # Save
obj = pickle.load(open("file.pkl", "rb"))  # Load back
```
The loaded object behaves exactly as it did when saved — same `.predict()`,
same `.transform()`, etc.

---

## 6. Component 2 — Apache Kafka

### What is Kafka?

Apache Kafka is a **distributed message broker** — a high-speed pipeline for
streaming data between systems. Think of it as a postal system for data:

```
Producer (writes letters) → Kafka Topic (post box) → Consumer (reads letters)
```

### Why not just use a database or REST API?

| Method | Problem at scale |
|---|---|
| REST API (HTTP request per flow) | Server overloaded at 100k flows/sec |
| Database polling (check every second) | Slow, adds DB load |
| **Kafka** | Handles millions of events/sec, consumers read at their own pace |

### Core Concepts

**Topic** — a named channel. Like a subreddit. Producers post to it,
consumers subscribe to it.
```
Topic: "network-flows"
  - kafka_producer.py writes here
  - backend/app.py (future) reads from here
```

**Partition** — Kafka splits a topic into partitions for parallel processing.
Multiple consumers can each read a different partition simultaneously.

**Offset** — Kafka remembers where each consumer left off. If the backend
crashes and restarts, it resumes from where it stopped — no data lost.

**Broker** — A Kafka server. In our docker-compose, one broker on port 9092.

**Zookeeper** — Manages the Kafka cluster (leader election, metadata).
Older Kafka needed Zookeeper; newer versions have KRaft mode (built-in).

### Our `kafka_producer.py`

```python
producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)
```

`bootstrap_servers` — which Kafka broker to connect to.
`value_serializer` — converts Python dict → JSON string → bytes.
Kafka only stores bytes; serialisation is your responsibility.

```python
flow = {
    "flow_id": counter,
    "src_ip": random.choice(IPS),
    "dst_port": random.choice(PORTS),
    "attack_type": attack,
    "features": [round(random.uniform(0, 1000), 2) for _ in range(20)],
}
producer.send(TOPIC, value=flow)
```

`features` is a list of 20 floats — simulating the 20 flow-level features
that the trained ML model would expect as input.

---

## 7. Component 3 — Backend API (`backend/`)

### `backend/app.py` — The Flask Server

**Flask** is a lightweight Python web framework. It maps URL routes to
Python functions:

```python
app = Flask(__name__)

@app.route('/api/health')
def health():
    return jsonify({"status": "ok"})
```

When a browser or curl hits `GET /api/health`, Flask calls `health()` and
returns the JSON response.

### CORS — Cross-Origin Resource Sharing

```python
CORS(app)
```

Browsers block JavaScript from calling APIs on a different domain/port for
security (called the Same-Origin Policy). Since the frontend runs on
`localhost:3000` and the backend on `localhost:5001`, they are different
"origins". `flask-cors` adds the HTTP headers that tell the browser:
"it's OK, the backend allows this."

```
Access-Control-Allow-Origin: *
```

### Threading — Running Two Things at Once

```python
thread = threading.Thread(target=simulate_traffic, daemon=True)
thread.start()
socketio.run(app, ...)
```

Python normally runs one thing at a time. Here we need:
- The Flask server to handle HTTP requests
- `simulate_traffic()` to run in an infinite loop generating alerts

`threading.Thread` runs `simulate_traffic` in a background thread.
`daemon=True` means: if the main program exits, kill this thread too
(don't keep the process alive just for the background worker).

### WebSockets via Flask-SocketIO

HTTP is **request-response**: client asks, server answers, connection closes.
For a live dashboard, the server needs to *push* data without being asked.

**WebSocket** is a persistent two-way connection:
```
Client connects → handshake → connection stays open
Server can push data at any time → Client updates UI
```

```python
socketio = SocketIO(app, cors_allowed_origins="*")

# Server pushes to all connected clients:
socketio.emit('new_alert', alert)
socketio.emit('stats_update', stats)

# Server handles client connection event:
@socketio.on('connect')
def handle_connect():
    emit('stats_update', stats)   # Send current state immediately on connect
```

`emit('event_name', data)` sends data to the frontend. The frontend
listens for `'new_alert'` and `'stats_update'` events and updates the UI.

### In-Memory Store

```python
recent_alerts = []     # List of last 100 alerts
stats = {
    "total_flows": 0,
    "attacks_detected": 0,
    ...
}
```

Data is stored in Python variables (RAM), not a database. This is fast
but **not persistent** — restarting the server wipes all data. For a
production system you'd use Redis or a time-series database like InfluxDB.

```python
recent_alerts.append(alert)
if len(recent_alerts) > 100:
    recent_alerts.pop(0)   # Keep only the last 100 alerts (sliding window)
```

---

## 8. Concept: REST APIs and WebSockets

### REST API

**REST** (Representational State Transfer) is a convention for building APIs
over HTTP. The key rules:

| Rule | Example |
|---|---|
| Use HTTP methods correctly | GET = read, POST = create, DELETE = remove |
| URLs identify resources | `/api/alerts` = the alerts resource |
| Stateless | Each request carries all the info needed; server doesn't remember previous requests |
| Return JSON | Standard data format for APIs |

CloudGuard's REST endpoints:
```
GET /api/health       → {"status": "ok"}
GET /api/stats        → {"total_flows": 100, "attacks_detected": 23, ...}
GET /api/alerts       → {"alerts": [...], "total": 85}
GET /api/attack-types → {"DDoS": 10, "PortScan": 8, ...}
```

These are used for initial page load. WebSocket handles live updates.

### HTTP vs WebSocket

```
HTTP (polling every second — BAD for real-time):
  Client: "Any new alerts?"  → Server: "Yes, here are 3"
  [1 second later]
  Client: "Any new alerts?"  → Server: "No"
  [1 second later]
  Client: "Any new alerts?"  → Server: "Yes, here is 1"

WebSocket (push — GOOD for real-time):
  [Connection established once]
  Server: "New alert!"       → Client updates instantly
  [500ms later]
  Server: "New alert!"       → Client updates instantly
  Server: "Stats updated!"   → Client updates instantly
```

WebSocket eliminates unnecessary polling and gives true real-time updates
with much lower latency and server load.

---

## 9. Component 4 — Frontend Dashboard (`frontend/`)

### React — Component-Based UI

**React** is a JavaScript library for building UIs. The core idea:
- UI is made of **components** (reusable pieces)
- Each component has **state** (data it tracks) and **props** (data passed in)
- When state changes, React automatically re-renders only the affected part

```
App (manages state: stats, alerts, connected)
 └── Dashboard (receives stats, alerts, connected as props)
      ├── StatCard × 4
      ├── BarChart (attack breakdown)
      ├── PieChart (traffic distribution)
      └── AlertsTable (live feed)
```

### `useState` and `useEffect` — React Hooks

```javascript
const [stats, setStats] = useState({ total_flows: 0, attacks_detected: 0, ... });
const [alerts, setAlerts] = useState([]);
const [connected, setConnected] = useState(false);
```

`useState` creates a reactive variable. Calling `setStats(newData)` updates
the variable AND tells React to re-render the component with new data.
You never mutate state directly (`stats.total_flows = 5` would NOT trigger a re-render).

```javascript
useEffect(() => {
    const socket = io(API_URL);   // Connect to backend WebSocket

    socket.on('connect', () => setConnected(true));
    socket.on('disconnect', () => setConnected(false));
    socket.on('stats_update', (data) => setStats(data));
    socket.on('new_alert', (alert) => {
        setAlerts((prev) => [alert, ...prev].slice(0, 50));
    });

    return () => socket.disconnect();   // Cleanup when component unmounts
}, []);   // [] = run only once on mount
```

`useEffect` runs side effects (things outside the React render cycle, like
network connections, timers). The empty array `[]` means "run this once
when the component mounts." The returned function is a cleanup — it runs
when the component is removed (disconnects the socket).

`[alert, ...prev].slice(0, 50)` — prepend new alert to the front of the array,
keep only the latest 50. `...prev` is the **spread operator** (expands the array).

### Recharts — Data Visualisation

```javascript
import { BarChart, Bar, XAxis, YAxis, PieChart, Pie, Cell } from 'recharts';
```

Recharts is a React charting library built on SVG. You describe charts
declaratively:

```jsx
<BarChart data={attackData}>
    <XAxis dataKey="name" />
    <YAxis />
    <Bar dataKey="value" fill="#6366f1" />
</BarChart>
```

`attackData` looks like:
```javascript
[
  { name: "DDoS",      value: 42 },
  { name: "PortScan",  value: 31 },
  { name: "BruteForce", value: 17 }
]
```

When `stats` state updates, `attackData` is recomputed and the chart
re-renders automatically — that's React's power.

### Environment Variables

```javascript
const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';
```

`process.env.REACT_APP_API_URL` reads from the environment at build time.
In `docker-compose.yml`:
```yaml
environment:
  - REACT_APP_API_URL=http://localhost:5001
```

This lets you change the backend URL without editing source code — just
change an environment variable. The `|| 'http://localhost:5001'` is a
fallback for local development.

---

## 10. Component 5 — Docker & Docker Compose

### What is Docker?

A **container** is a lightweight isolated environment — like a virtual machine
but much faster and smaller. It packages:
- Your application code
- All dependencies (Python, Node, libraries)
- A mini OS filesystem

The same container runs identically on any machine — no "it works on my
laptop" problems.

**Image** = the blueprint (built from a `Dockerfile`)
**Container** = a running instance of an image

### `docker-compose.yml` — Orchestrating Multiple Containers

CloudGuard needs 4 services running together. Docker Compose defines them all:

```yaml
services:
  zookeeper:        # Kafka's coordination service
  kafka:            # The message broker
  backend:          # Flask API
  frontend:         # React app
```

```yaml
kafka:
  depends_on:
    - zookeeper     # Start zookeeper first, then kafka
  ports:
    - "9092:9092"   # host_port:container_port (expose to your machine)
  environment:
    KAFKA_BROKER_ID: 1
    KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181   # Use service name as hostname
```

Inside Docker Compose, services talk to each other by **service name**
(e.g., `zookeeper:2181`). Docker's internal DNS resolves `zookeeper` to
the correct container IP.

```yaml
backend:
  build: ./backend        # Build image from ./backend/Dockerfile
  volumes:
    - ./backend/model:/app/model   # Mount local folder into container
```

**Volume mount** — links a folder on your Mac to a folder inside the container.
Changes on either side are reflected immediately. Used here to pass the
trained model files into the backend container.

```
One command to run everything:
$ docker-compose up --build
```

---

## 11. End-to-End Data Flow

Here is exactly what happens from dataset to dashboard:

```
Step 1 — TRAIN (runs once, offline)
──────────────────────────────────
CIC-IDS2017 CSV
    → preprocess.py cleans and scales it
    → train_model.py trains RandomForest on 80% of data
    → Saves model.pkl, scaler.pkl, label_encoder.pkl to ml/model/
    → Copy those .pkl files to backend/model/

Step 2 — STREAM (runs continuously)
────────────────────────────────────
kafka_producer.py generates a fake flow every ~1 second:
  {src_ip, dst_port, features: [f1..f20], attack_type, ...}
    → producer.send("network-flows", flow)
    → Kafka stores this message in the "network-flows" topic

Step 3 — INFER (runs continuously, not yet implemented)
─────────────────────────────────────────────────────────
backend/app.py (future Kafka consumer):
  consumer.poll() → gets new flow from Kafka
    → scaler.transform([flow.features])   # scale to match training data
    → model.predict(scaled_features)      # → e.g., 2 (DDoS)
    → label_encoder.inverse_transform([2]) # → "DDoS"
    → Build alert dict with result
    → socketio.emit('new_alert', alert)

Step 4 — DISPLAY (runs in browser)
────────────────────────────────────
React App.js:
  socket.on('new_alert', alert → setAlerts([alert, ...prev]))
  socket.on('stats_update', data → setStats(data))
    → Dashboard re-renders with new data
    → Charts animate, table updates, counters tick up
```

**Currently:** Steps 2 and 3 are simulated — `backend/app.py` generates
random alerts instead of consuming from Kafka and running real ML inference.
This lets the frontend and API work end-to-end while the ML pipeline is
still being built.

---

## 12. Current State vs. Final Vision

| Layer | Current (Simulation) | Final Vision |
|---|---|---|
| Traffic source | `random.choices()` in `app.py` | `kafka_producer.py` → Kafka topic |
| ML inference | `random.uniform(0.85, 0.99)` confidence | Load `model.pkl`, run `.predict()` |
| Attack labels | Randomly assigned | Model output via `label_encoder` |
| Backend reads | Internal loop | Kafka consumer polling `network-flows` |
| Data persistence | In-memory list (lost on restart) | Redis or InfluxDB |
| Monitoring | None | Prometheus + Grafana |
| Logging | Print statements | ELK Stack (Elasticsearch, Logstash, Kibana) |

**What you need to do to complete the pipeline:**
1. Download CIC-IDS2017 dataset → place CSVs in `ml/data/`
2. Run `python preprocess.py` then `python train_model.py`
3. Copy `ml/model/*.pkl` → `backend/model/`
4. Add a Kafka consumer to `backend/app.py` that reads flows and calls the model
5. Write `Dockerfile` for backend and frontend

---

## 13. Key Terms Glossary

| Term | Definition |
|---|---|
| **IDS** | Intrusion Detection System — monitors network for malicious activity |
| **Network flow** | Statistical summary of a network connection (not raw packets) |
| **CIC-IDS2017** | Standard academic dataset of labelled network flows |
| **Random Forest** | Ensemble of decision trees that vote on a classification |
| **LabelEncoder** | Converts text class names to integers for ML |
| **StandardScaler** | Normalises features to mean=0, std=1 |
| **Overfitting** | Model memorises training data but fails on new data |
| **Train/test split** | Holding out data the model never sees, to measure real accuracy |
| **Pickle** | Python's way of saving/loading objects to/from disk |
| **Kafka** | Distributed message broker for high-throughput event streaming |
| **Topic** | Named channel in Kafka (like a queue) |
| **Producer** | Writes messages to a Kafka topic |
| **Consumer** | Reads messages from a Kafka topic |
| **Zookeeper** | Coordinates Kafka brokers in a cluster |
| **Flask** | Lightweight Python web framework |
| **REST API** | Convention for building HTTP APIs using standard methods |
| **CORS** | Browser security policy; Flask-CORS adds headers to allow cross-origin requests |
| **WebSocket** | Persistent connection allowing server-to-client push |
| **Socket.IO** | Library that wraps WebSocket with automatic reconnection and events |
| **React** | JavaScript library for building component-based UIs |
| **useState** | React hook to store and update component data |
| **useEffect** | React hook to run side effects (network, timers) |
| **Props** | Data passed from a parent component to a child component |
| **Docker** | Containerisation — packages app + dependencies into isolated unit |
| **Docker Compose** | Tool to define and run multiple containers together |
| **Volume mount** | Links a host folder into a container so files are shared |
| **Environment variable** | Config value set outside the code (port, API URL, etc.) |
| **Daemon thread** | Background thread that dies when the main program exits |
| **In-memory store** | Data kept in RAM (fast, but lost on restart) |
| **Serialiser** | Converts data to bytes for transmission (JSON → bytes) |
| **F1-Score** | Combined precision/recall metric; best single number for classifier quality |
| **Precision** | Of predicted positives, fraction that are truly positive |
| **Recall** | Of actual positives, fraction that were correctly predicted |
| **Data leakage** | Accidentally using test/future data during training, inflating accuracy |
| **SMOTE** | Synthetic Minority Oversampling — generates fake samples of rare classes |
