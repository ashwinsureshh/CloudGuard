"""
database.py — SQLite persistence layer for CloudGuard alerts and stats.
"""

import sqlite3
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).parent / "cloudguard.db"


def init_db():
    """Create tables if they don't exist."""
    conn = sqlite3.connect(DB_PATH)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                src_ip      TEXT,
                dst_ip      TEXT,
                src_port    INTEGER,
                dst_port    INTEGER,
                protocol    TEXT,
                attack_type TEXT    NOT NULL,
                confidence  REAL,
                severity    TEXT,
                is_attack   INTEGER NOT NULL DEFAULT 0,
                hmac_sig    TEXT,
                created_at  TEXT    DEFAULT (datetime('now'))
            )
        """)
        conn.commit()
        logger.info(f"Database initialised at {DB_PATH}")
    finally:
        conn.close()


def save_alert(alert: dict) -> int:
    """Persist an alert and return its auto-assigned integer ID."""
    conn = sqlite3.connect(DB_PATH)
    try:
        c = conn.cursor()
        c.execute("""
            INSERT INTO alerts
                (timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                 attack_type, confidence, severity, is_attack, hmac_sig)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.get("timestamp"),
            alert.get("src_ip"),
            alert.get("dst_ip"),
            alert.get("src_port"),
            alert.get("dst_port"),
            alert.get("protocol"),
            alert.get("attack_type"),
            alert.get("confidence"),
            alert.get("severity"),
            1 if alert.get("is_attack") else 0,
            alert.get("hmac_sig"),
        ))
        conn.commit()
        return c.lastrowid  # SQLite auto-increment ID
    except Exception as e:
        logger.error(f"save_alert failed: {e}")
        raise
    finally:
        conn.close()


def get_alerts(limit: int = 20, offset: int = 0) -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        c = conn.cursor()
        c.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return [dict(row) for row in c.fetchall()]
    finally:
        conn.close()


def get_total_count() -> int:
    conn = sqlite3.connect(DB_PATH)
    try:
        return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    finally:
        conn.close()


def get_stats() -> dict:
    conn = sqlite3.connect(DB_PATH)
    try:
        c = conn.cursor()
        total   = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        attacks = c.execute("SELECT COUNT(*) FROM alerts WHERE is_attack = 1").fetchone()[0]
        benign  = c.execute("SELECT COUNT(*) FROM alerts WHERE is_attack = 0").fetchone()[0]
        rows    = c.execute(
            "SELECT attack_type, COUNT(*) FROM alerts WHERE is_attack = 1 GROUP BY attack_type"
        ).fetchall()
        return {
            "total_flows":      total,
            "attacks_detected": attacks,
            "benign_count":     benign,
            "attack_breakdown": dict(rows),
        }
    finally:
        conn.close()
