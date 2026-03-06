"""
app.py — CloudGuard Flask + SocketIO API server.

Start-up order:
  1. Initialise SQLite database
  2. Try to load ML model artefacts (falls back to mock if missing)
  3. Try to connect Kafka consumer (falls back to traffic simulator if unavailable)
  4. Serve REST API + SocketIO
"""

import logging
import os
import random
import threading
import time
from datetime import datetime

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit

from database import get_alerts, get_stats, get_total_count, init_db, save_alert
from kafka_consumer import is_kafka_connected, start_consumer
from model import is_model_loaded, load_model, predict

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── Flask / SocketIO ───────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# ── Config (overridable via environment variables) ─────────────────────────────
KAFKA_BROKER = os.environ.get("KAFKA_BROKER", "localhost:9092")
KAFKA_TOPIC  = "network-traffic"

# Recent alerts kept in memory for instant SocketIO replay on reconnect.
_recent_alerts: list[dict] = []
_recent_lock   = threading.Lock()

# ── Core flow processing ───────────────────────────────────────────────────────

def process_flow(flow: dict):
    """Classify one network flow, persist it, and push to connected clients."""
    prediction = predict(flow)
    ts = flow.get("timestamp", datetime.now().strftime("%H:%M:%S"))

    alert = {
        "timestamp":   ts,
        "src_ip":      flow.get("src_ip",  "unknown"),
        "dst_ip":      flow.get("dst_ip",  "unknown"),
        "src_port":    flow.get("src_port"),
        "dst_port":    flow.get("dst_port"),
        "protocol":    flow.get("protocol"),
        "attack_type": prediction["attack_type"],
        "confidence":  prediction["confidence"],
        "severity":    prediction["severity"],
        "is_attack":   prediction["is_attack"],
        # Stable unique key for React — avoids undefined key={a.id} in Dashboard.jsx
        "id":          f"{ts}_{flow.get('src_ip', '')}_{flow.get('dst_port', '')}",
    }

    try:
        save_alert(alert)
    except Exception as e:
        logger.error(f"DB write failed: {e}")

    with _recent_lock:
        _recent_alerts.append(alert)
        if len(_recent_alerts) > 100:
            _recent_alerts.pop(0)

    socketio.emit("new_alert",    alert)
    socketio.emit("stats_update", get_stats())


# ── Traffic simulator (Kafka fallback) ────────────────────────────────────────
_SIM_IPS = ["192.168.1.101", "10.0.0.55", "172.16.0.20", "192.168.2.15"]


def _simulate_traffic():
    """Generate synthetic flows when Kafka is not available."""
    logger.info("Traffic simulator started (Kafka fallback mode).")
    while True:
        flow = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "src_ip":    random.choice(_SIM_IPS),
            "dst_ip":    f"10.0.0.{random.randint(1, 254)}",
            "src_port":  random.randint(1024, 65535),
            "dst_port":  random.choice([80, 443, 22, 8080, 3389]),
            "protocol":  random.choice(["TCP", "UDP"]),
        }
        process_flow(flow)
        time.sleep(random.uniform(0.5, 1.5))


# ── REST API ───────────────────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({
        "status":       "ok",
        "model_loaded": is_model_loaded(),
        "kafka_active": is_kafka_connected(),
        "kafka_broker": KAFKA_BROKER,
    })


@app.route("/api/alerts")
def api_alerts():
    try:
        limit  = max(1, min(int(request.args.get("limit",  20)), 200))
        offset = max(0,     int(request.args.get("offset",  0)))
        alerts = get_alerts(limit=limit, offset=offset)
        return jsonify({
            "alerts": alerts,
            "total":  get_total_count(),
            "limit":  limit,
            "offset": offset,
        })
    except Exception as e:
        logger.error(f"GET /api/alerts failed: {e}")
        return jsonify({"error": "Failed to retrieve alerts"}), 500


@app.route("/api/stats")
def api_stats():
    try:
        return jsonify(get_stats())
    except Exception as e:
        logger.error(f"GET /api/stats failed: {e}")
        return jsonify({"error": "Failed to retrieve stats"}), 500


@app.route("/api/attack-types")
def api_attack_types():
    try:
        return jsonify(get_stats()["attack_breakdown"])
    except Exception as e:
        logger.error(f"GET /api/attack-types failed: {e}")
        return jsonify({"error": "Failed to retrieve attack types"}), 500


# ── SocketIO events ────────────────────────────────────────────────────────────

@socketio.on("connect")
def handle_connect():
    logger.info("Frontend client connected via SocketIO")
    try:
        emit("stats_update", get_stats())
        # Replay recent alerts so a freshly opened dashboard isn't empty
        with _recent_lock:
            for alert in _recent_alerts[-15:]:
                emit("new_alert", alert)
    except Exception as e:
        logger.error(f"Error during client connect handler: {e}")


@socketio.on("disconnect")
def handle_disconnect():
    logger.info("Frontend client disconnected")


# ── Application start-up ───────────────────────────────────────────────────────

def _startup():
    # 1. Database
    init_db()

    # 2. ML model (non-blocking — simulation handles the gap)
    load_model()

    # 3. Kafka consumer
    start_consumer(KAFKA_BROKER, KAFKA_TOPIC, process_flow)

    # Wait briefly to see if Kafka connects before deciding on fallback
    _kafka_ready = is_kafka_connected()
    for _ in range(10):          # up to ~5 s
        if is_kafka_connected():
            _kafka_ready = True
            break
        time.sleep(0.5)

    if not _kafka_ready:
        logger.warning("Kafka not available — starting traffic simulator.")
        sim = threading.Thread(target=_simulate_traffic, daemon=True, name="simulator")
        sim.start()
    else:
        logger.info("Kafka consumer active — simulator disabled.")


if __name__ == "__main__":
    _startup()
    logger.info("CloudGuard API running at http://0.0.0.0:5001")
    socketio.run(app, host="0.0.0.0", port=5001, debug=False)
