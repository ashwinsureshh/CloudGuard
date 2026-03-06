"""
kafka_consumer.py — Kafka consumer for CloudGuard.

Consumes network flow events from the Kafka topic and passes them to a
callback (process_flow in app.py).  If Kafka is unavailable the thread
exits cleanly and app.py falls back to the traffic simulator.
"""

import json
import logging
import threading

logger = logging.getLogger(__name__)

# Set by _consume_loop when a real broker connection is established.
_kafka_connected = threading.Event()


def is_kafka_connected() -> bool:
    return _kafka_connected.is_set()


def start_consumer(broker: str, topic: str, on_flow_callback) -> threading.Thread:
    """
    Spawn a daemon thread that reads from Kafka and invokes on_flow_callback
    for every message.  Returns the thread so the caller can probe is_alive().
    """
    thread = threading.Thread(
        target=_consume_loop,
        args=(broker, topic, on_flow_callback),
        daemon=True,
        name="kafka-consumer",
    )
    thread.start()
    logger.info(f"Kafka consumer thread started (broker={broker}, topic={topic})")
    return thread


def _consume_loop(broker: str, topic: str, on_flow_callback):
    try:
        from kafka import KafkaConsumer
        from kafka.errors import NoBrokersAvailable

        try:
            consumer = KafkaConsumer(
                topic,
                bootstrap_servers=broker,
                value_deserializer=lambda v: json.loads(v.decode("utf-8")),
                auto_offset_reset="latest",
                enable_auto_commit=True,
                group_id="cloudguard-backend",
                # Surface broker unavailability quickly instead of waiting 30 s
                request_timeout_ms=10_000,
                api_version_auto_timeout_ms=5_000,
            )
        except NoBrokersAvailable:
            logger.warning(f"No Kafka brokers available at {broker}. Consumer disabled.")
            return

        _kafka_connected.set()
        logger.info(f"Kafka consumer connected — consuming from '{topic}'")

        for message in consumer:
            try:
                on_flow_callback(message.value)
            except Exception as e:
                logger.error(f"Error processing Kafka message: {e}")

    except ImportError:
        logger.warning("kafka-python not installed. Consumer disabled.")
    except Exception as e:
        logger.warning(f"Kafka consumer error: {e}. Consumer disabled.")
