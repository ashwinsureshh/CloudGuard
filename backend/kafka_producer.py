"""
kafka_producer.py — Kafka Traffic Event Producer for CloudGuard
Reads network flow data and streams events to a Kafka topic.
"""

from kafka import KafkaProducer
import json
import time
import random
from datetime import datetime

KAFKA_BROKER = "localhost:9092"
TOPIC = "network-traffic"

def create_producer():
    return KafkaProducer(
        bootstrap_servers=KAFKA_BROKER,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        retries=5
    )

def generate_flow():
    attacks = ["BENIGN", "DDoS", "PortScan", "BruteForce", "Infiltration"]
    ips = ["192.168.1.101", "10.0.0.55", "172.16.0.20", "192.168.2.15"]
    return {
        "timestamp": datetime.now().isoformat(),
        "src_ip": random.choice(ips),
        "dst_ip": f"10.0.0.{random.randint(1, 254)}",
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([80, 443, 22, 8080, 3389]),
        "protocol": random.choice(["TCP", "UDP"]),
        "duration": round(random.uniform(0.001, 5.0), 4),
        "fwd_packets": random.randint(1, 100),
        "bwd_packets": random.randint(0, 50),
        "label": random.choices(attacks, weights=[60, 15, 12, 8, 5])[0]
    }

def run():
    print(f"[*] Connecting to Kafka at {KAFKA_BROKER}...")
    producer = create_producer()
    print(f"[+] Sending flows to topic '{TOPIC}'...")
    count = 0
    while True:
        flow = generate_flow()
        producer.send(TOPIC, value=flow)
        count += 1
        if count % 10 == 0:
            print(f"[+] Sent {count} flows...")
        time.sleep(random.uniform(0.3, 1.0))

if __name__ == "__main__":
    run()
