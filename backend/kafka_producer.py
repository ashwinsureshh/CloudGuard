from kafka import KafkaProducer
import json
import time
import random
from datetime import datetime

# Connect to Kafka
producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

TOPIC = "network-flows"

# Simulated network flows
ATTACKS = ["BENIGN", "DDoS", "PortScan", "BruteForce", "Infiltration"]
IPS     = ["192.168.1.101", "10.0.0.55", "172.16.0.20", "192.168.2.15", "10.10.1.33"]
PORTS   = [80, 443, 22, 8080, 3389]

print("🚀 Kafka Producer started — streaming network flows...")
print(f"📡 Sending to topic: {TOPIC}")
print("Press Ctrl+C to stop\n")

counter = 0
while True:
    attack = random.choices(ATTACKS, weights=[60, 15, 12, 8, 5])[0]

    flow = {
        "flow_id": counter,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "src_ip": random.choice(IPS),
        "dst_port": random.choice(PORTS),
        "attack_type": attack,
        "features": [round(random.uniform(0, 1000), 2) for _ in range(20)],
        "is_attack": attack != "BENIGN"
    }

    producer.send(TOPIC, value=flow)
    print(f"[{flow['timestamp']}] Sent flow #{counter} → {attack} from {flow['src_ip']}")

    counter += 1
    time.sleep(random.uniform(0.5, 1.5))