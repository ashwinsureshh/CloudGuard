"""
auth.py — JWT authentication and HMAC-SHA256 alert integrity for CloudGuard.

Cryptographic concepts demonstrated:
  1. SHA-256 hashing   — secure password storage (never store plaintext)
  2. JWT / HS256       — stateless bearer-token authentication
  3. HMAC-SHA256       — per-alert integrity signing to detect tampering
  4. Timing-safe compare — prevents timing-based side-channel attacks
"""

import hashlib
import hmac as _hmac
import json
import logging
import os
import time
from functools import wraps

import jwt  # PyJWT
from flask import jsonify, request

logger = logging.getLogger(__name__)

# ── Secret keys (override via environment variables in production) ─────────────
SECRET_KEY   = os.environ.get("SECRET_KEY", "cloudguard-jwt-secret-change-in-production")
HMAC_KEY     = os.environ.get("HMAC_KEY",   "cloudguard-hmac-secret-change-in-production")
JWT_EXPIRY_S = int(os.environ.get("JWT_EXPIRY_S", 3600))  # 1 hour

# ── Demo user store — passwords stored as SHA-256 hashes (never plaintext) ────
_USERS = {
    "admin":   hashlib.sha256(b"admin123").hexdigest(),
    "analyst": hashlib.sha256(b"analyst123").hexdigest(),
}


# ── JWT ────────────────────────────────────────────────────────────────────────

def generate_token(username: str) -> str:
    """Issue a signed JWT valid for JWT_EXPIRY_S seconds."""
    payload = {
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXPIRY_S,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def verify_token(token: str):
    """Decode and validate a JWT. Returns the payload dict or None."""
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        logger.warning("JWT expired")
    except jwt.InvalidTokenError as e:
        logger.warning("Invalid JWT: %s", e)
    return None


def check_credentials(username: str, password: str) -> bool:
    """Timing-safe credential check against stored SHA-256 hash."""
    hashed = hashlib.sha256(password.encode()).hexdigest()
    stored = _USERS.get(username, "")
    return _hmac.compare_digest(hashed, stored)


# ── Flask auth decorator ───────────────────────────────────────────────────────

def require_auth(f):
    """Route decorator — rejects requests without a valid Bearer token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorisation required"}), 401
        if verify_token(auth_header[7:]) is None:
            return jsonify({"error": "Token expired or invalid"}), 401
        return f(*args, **kwargs)
    return decorated


# ── HMAC-SHA256 alert integrity signing ───────────────────────────────────────

def sign_alert(alert: dict) -> str:
    """
    Compute HMAC-SHA256 over the alert's immutable fields.

    The canonical JSON is deterministic (sort_keys=True) so the same
    alert always produces the same digest. Any modification to the
    signed fields will produce a completely different digest, making
    tampering immediately detectable.
    """
    canonical = json.dumps({
        "timestamp":   str(alert.get("timestamp",   "")),
        "src_ip":      str(alert.get("src_ip",      "")),
        "dst_ip":      str(alert.get("dst_ip",      "")),
        "dst_port":    str(alert.get("dst_port",    "")),
        "attack_type": str(alert.get("attack_type", "")),
        "confidence":  str(alert.get("confidence",  "")),
    }, sort_keys=True)
    return _hmac.new(HMAC_KEY.encode(), canonical.encode(), hashlib.sha256).hexdigest()


def verify_alert_hmac(alert: dict, sig: str) -> bool:
    """Constant-time comparison to prevent timing side-channel attacks."""
    return _hmac.compare_digest(sign_alert(alert), sig)
