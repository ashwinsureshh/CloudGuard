"""
app.py — CloudGuard Flask + SocketIO API server.

Topics demonstrated:
  Web Technology:
    - REST API (Flask), WebSockets (Socket.IO), CORS, SPA backend
    - Rate limiting (Flask-Limiter) — prevents brute-force / DoS
    - HTTP security headers — HSTS, CSP, X-Frame-Options, etc.
  Cryptography & Network Security:
    - RSA-2048 digital signatures on every alert (non-repudiation)
    - AES-256-GCM encryption of IP fields at rest (see database.py)
    - HMAC-SHA256 alert integrity (see auth.py)
    - JWT bearer-token authentication (see auth.py)
  Cloud Computing:
    - Redis distributed cache (cache-aside pattern) for stats
    - Environment-variable driven config (12-factor app)
    - Kafka consumer with graceful simulator fallback
    - /api/health endpoint for load-balancer health checks
"""

import logging
import os
import random
import threading
import time
from datetime import datetime

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit

from auth import check_credentials, generate_token, require_auth, sign_alert
from cache import get_cached_stats, init_cache, invalidate_stats, is_cache_available
from crypto import get_public_key_pem, rsa_sign
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
CORS(app, resources={r"/api/*": {"origins": os.environ.get("CORS_ORIGIN", "*")}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── Rate Limiter (Web Technology) ──────────────────────────────────────────────
# Uses Redis as storage backend when available, in-memory otherwise.
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per minute"],
    storage_uri=REDIS_URL,
    storage_options={"socket_connect_timeout": 2},
)

# ── Config ─────────────────────────────────────────────────────────────────────
KAFKA_BROKER = os.environ.get("KAFKA_BROKER", "localhost:9092")
KAFKA_TOPIC  = "network-traffic"

# Recent alerts in memory for instant SocketIO replay on reconnect.
_recent_alerts: list[dict] = []
_recent_lock   = threading.Lock()


# ── HTTP Security Headers (Web Technology) ─────────────────────────────────────
@app.after_request
def add_security_headers(response):
    """
    Add OWASP-recommended security headers to every response.
    These protect against XSS, clickjacking, MIME sniffing, and data leakage.
    """
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]          = "DENY"
    response.headers["X-XSS-Protection"]         = "1; mode=block"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"]   = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' ws: wss:;"
    )
    return response


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
    }

    # HMAC-SHA256 — symmetric integrity proof (anyone with the key can verify)
    alert["hmac_sig"] = sign_alert(alert)

    # RSA-2048 — asymmetric digital signature (only this server can sign)
    signing_payload = {
        "timestamp":   str(alert["timestamp"]),
        "src_ip":      str(alert["src_ip"]),
        "dst_ip":      str(alert["dst_ip"]),
        "dst_port":    str(alert["dst_port"]),
        "attack_type": str(alert["attack_type"]),
        "confidence":  str(alert["confidence"]),
    }
    alert["rsa_sig"] = rsa_sign(signing_payload)

    try:
        alert["id"] = save_alert(alert)  # IPs encrypted with AES-256-GCM in DB
    except Exception as e:
        logger.error(f"DB write failed: {e}")
        alert["id"] = time.time_ns()

    # Invalidate Redis stats cache so next read reflects the new alert
    invalidate_stats()

    with _recent_lock:
        _recent_alerts.append(alert)
        if len(_recent_alerts) > 100:
            _recent_alerts.pop(0)

    socketio.emit("new_alert",    alert)
    socketio.emit("stats_update", get_cached_stats(get_stats))


# ── Traffic simulator (Kafka fallback) ────────────────────────────────────────
_SIM_IPS = ["192.168.1.101", "10.0.0.55", "172.16.0.20", "192.168.2.15"]


def _simulate_traffic():
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
    """Public endpoint — used by Nginx / cloud load-balancer health checks."""
    return jsonify({
        "status":        "ok",
        "model_loaded":  is_model_loaded(),
        "kafka_active":  is_kafka_connected(),
        "kafka_broker":  KAFKA_BROKER,
        "cache_active":  is_cache_available(),
    })


@app.route("/api/login", methods=["POST"])
@limiter.limit("10 per minute")  # brute-force protection
def api_login():
    """
    Issue a JWT after verifying credentials.
    Rate-limited to 10 attempts/minute per IP.
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    if not check_credentials(username, password):
        logger.warning("Failed login attempt for user: %s", username)
        return jsonify({"error": "Invalid credentials"}), 401

    token = generate_token(username)
    logger.info("User '%s' authenticated successfully", username)
    return jsonify({"token": token, "username": username, "expires_in": 3600})


@app.route("/api/public-key")
def api_public_key():
    """
    Expose the RSA-2048 public key in PEM format.
    Any client can download this key and independently verify alert RSA signatures,
    demonstrating asymmetric cryptography / non-repudiation.
    """
    return jsonify({"public_key": get_public_key_pem()})


@app.route("/api/alerts")
@require_auth
@limiter.limit("60 per minute")
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
@require_auth
@limiter.limit("120 per minute")
def api_stats():
    try:
        # Cache-aside: serve from Redis if available, fall back to DB
        return jsonify(get_cached_stats(get_stats))
    except Exception as e:
        logger.error(f"GET /api/stats failed: {e}")
        return jsonify({"error": "Failed to retrieve stats"}), 500


@app.route("/api/attack-types")
@require_auth
@limiter.limit("120 per minute")
def api_attack_types():
    try:
        return jsonify(get_cached_stats(get_stats)["attack_breakdown"])
    except Exception as e:
        logger.error(f"GET /api/attack-types failed: {e}")
        return jsonify({"error": "Failed to retrieve attack types"}), 500


# ── SocketIO events ────────────────────────────────────────────────────────────

@socketio.on("connect")
def handle_connect():
    logger.info("Frontend client connected via SocketIO")
    try:
        emit("stats_update", get_cached_stats(get_stats))
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
    init_db()
    init_cache()
    load_model()
    start_consumer(KAFKA_BROKER, KAFKA_TOPIC, process_flow)

    _kafka_ready = False
    for _ in range(10):
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
    socketio.run(app, host="0.0.0.0", port=5001, debug=False, allow_unsafe_werkzeug=True)
