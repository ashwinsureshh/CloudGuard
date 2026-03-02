from flask import Flask, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import threading
import time
import random
from datetime import datetime

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# In-memory store
recent_alerts = []
stats = {
    "total_flows": 0,
    "attacks_detected": 0,
    "benign_count": 0,
    "attack_breakdown": {}
}

def simulate_traffic():
    counter = 0
    attacks = ["BENIGN", "DDoS", "PortScan", "BruteForce", "Infiltration"]
    ips = ["192.168.1.101", "10.0.0.55", "172.16.0.20", "192.168.2.15"]

    while True:
        attack = random.choices(attacks, weights=[60, 15, 12, 8, 5])[0]
        is_attack = attack != "BENIGN"

        alert = {
            "id": counter,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "src_ip": random.choice(ips),
            "dst_port": random.choice([80, 443, 22, 8080, 3389]),
            "attack_type": attack,
            "confidence": round(random.uniform(0.85, 0.99), 2),
            "severity": "HIGH" if is_attack and random.random() > 0.5 else "MEDIUM" if is_attack else "NONE",
            "is_attack": is_attack
        }

        stats["total_flows"] += 1
        if is_attack:
            stats["attacks_detected"] += 1
            stats["attack_breakdown"][attack] = stats["attack_breakdown"].get(attack, 0) + 1
        else:
            stats["benign_count"] += 1

        recent_alerts.append(alert)
        if len(recent_alerts) > 100:
            recent_alerts.pop(0)

        socketio.emit('new_alert', alert)
        socketio.emit('stats_update', stats)

        counter += 1
        time.sleep(random.uniform(0.5, 1.5))


@app.route('/api/health')
def health():
    return jsonify({"status": "ok"})

@app.route('/api/alerts')
def get_alerts():
    return jsonify({"alerts": recent_alerts[-20:], "total": len(recent_alerts)})

@app.route('/api/stats')
def get_stats():
    return jsonify(stats)

@app.route('/api/attack-types')
def get_attack_types():
    return jsonify(stats["attack_breakdown"])

@socketio.on('connect')
def handle_connect():
    print("Frontend connected!")
    emit('stats_update', stats)


if __name__ == '__main__':
    thread = threading.Thread(target=simulate_traffic, daemon=True)
    thread.start()
    print("🚀 CloudGuard API running at http://localhost:5001")
    socketio.run(app, host='0.0.0.0', port=5001, debug=False)
