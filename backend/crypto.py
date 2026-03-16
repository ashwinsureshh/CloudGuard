"""
crypto.py — AES-256-GCM encryption and RSA-2048 digital signatures.

Cryptography & Network Security topics demonstrated:
  1. AES-256-GCM  — authenticated symmetric encryption of sensitive DB fields
  2. RSA-2048     — asymmetric digital signatures for non-repudiation
  3. Key management — persistent key storage, separation of key types
"""

import base64
import json
import logging
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

KEY_DIR = Path(__file__).parent / "keys"
KEY_DIR.mkdir(exist_ok=True)

# ── AES-256-GCM key (32 bytes) ─────────────────────────────────────────────────

_AES_KEY_PATH = KEY_DIR / "aes.key"

def _load_or_generate_aes_key() -> bytes:
    if _AES_KEY_PATH.exists():
        key = base64.b64decode(_AES_KEY_PATH.read_text().strip())
        logger.info("AES-256 key loaded from disk.")
        return key
    key = os.urandom(32)  # 256 bits
    _AES_KEY_PATH.write_text(base64.b64encode(key).decode())
    logger.info("AES-256 key generated and saved to keys/aes.key")
    return key

_AES_KEY = _load_or_generate_aes_key()

def aes_encrypt(plaintext: str) -> str:
    """
    Encrypt a string with AES-256-GCM.
    Returns base64-encoded nonce (12 bytes) + ciphertext + auth tag.
    GCM mode provides both confidentiality AND integrity.
    """
    if not plaintext:
        return plaintext
    aesgcm = AESGCM(_AES_KEY)
    nonce = os.urandom(12)  # 96-bit nonce — unique per message
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")

def aes_decrypt(token: str) -> str:
    """Decrypt an AES-256-GCM encrypted string."""
    if not token:
        return token
    try:
        raw = base64.b64decode(token)
        nonce, ciphertext = raw[:12], raw[12:]
        aesgcm = AESGCM(_AES_KEY)
        return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
    except Exception:
        return token  # graceful fallback for legacy plaintext rows


# ── RSA-2048 key pair ──────────────────────────────────────────────────────────

_PRIVATE_KEY_PATH = KEY_DIR / "rsa_private.pem"
_PUBLIC_KEY_PATH  = KEY_DIR / "rsa_public.pem"

def _load_or_generate_rsa_keys():
    if _PRIVATE_KEY_PATH.exists() and _PUBLIC_KEY_PATH.exists():
        with open(_PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(_PUBLIC_KEY_PATH, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        logger.info("RSA-2048 key pair loaded from disk.")
        return private_key, public_key

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key  = private_key.public_key()

    with open(_PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(_PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    logger.info("RSA-2048 key pair generated and saved to keys/")
    return private_key, public_key

_rsa_private, _rsa_public = _load_or_generate_rsa_keys()


def rsa_sign(payload: dict) -> str:
    """
    Sign a dict with RSA-2048 / SHA-256 (PKCS#1 v1.5).
    Returns base64-encoded signature.
    Provides non-repudiation — only the server holding the private key can sign.
    """
    message = json.dumps(payload, sort_keys=True).encode("utf-8")
    signature = _rsa_private.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(signature).decode("utf-8")


def rsa_verify(payload: dict, signature: str) -> bool:
    """Verify an RSA-2048/SHA-256 signature using the public key."""
    try:
        message = json.dumps(payload, sort_keys=True).encode("utf-8")
        _rsa_public.verify(
            base64.b64decode(signature),
            message,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def get_public_key_pem() -> str:
    """Return RSA public key PEM — clients use this to verify alert signatures."""
    return _PUBLIC_KEY_PATH.read_text()
