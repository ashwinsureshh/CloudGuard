"""
cache.py — Redis-backed caching layer for CloudGuard.

Cloud Computing topics demonstrated:
  1. Distributed caching  — Redis as an in-memory data store
  2. Cache-aside pattern  — check cache first, fall back to DB
  3. TTL-based expiry     — automatic cache invalidation
  4. Graceful degradation — works without Redis (falls back to DB)
"""

import json
import logging
import os

logger = logging.getLogger(__name__)

REDIS_URL      = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
STATS_TTL      = int(os.environ.get("CACHE_STATS_TTL", 5))   # seconds
ALERTS_TTL     = int(os.environ.get("CACHE_ALERTS_TTL", 10))  # seconds

_redis_client = None
_redis_available = False


def init_cache():
    """Connect to Redis. Silently disables caching if Redis is unavailable."""
    global _redis_client, _redis_available
    try:
        import redis
        _redis_client = redis.from_url(REDIS_URL, socket_connect_timeout=2, decode_responses=True)
        _redis_client.ping()
        _redis_available = True
        logger.info("Redis cache connected at %s", REDIS_URL)
    except Exception as e:
        _redis_available = False
        logger.warning("Redis unavailable (%s) — caching disabled, using direct DB.", e)


def is_cache_available() -> bool:
    return _redis_available


def cache_get(key: str):
    """Return parsed JSON from cache, or None on miss/error."""
    if not _redis_available:
        return None
    try:
        val = _redis_client.get(key)
        return json.loads(val) if val else None
    except Exception:
        return None


def cache_set(key: str, value, ttl: int):
    """Store JSON-serialised value in cache with TTL (seconds)."""
    if not _redis_available:
        return
    try:
        _redis_client.setex(key, ttl, json.dumps(value))
    except Exception:
        pass


def cache_delete(key: str):
    """Invalidate a cache key."""
    if not _redis_available:
        return
    try:
        _redis_client.delete(key)
    except Exception:
        pass


def get_cached_stats(db_fn):
    """
    Cache-aside pattern for stats.
    Returns cached stats if fresh, otherwise calls db_fn() and caches result.
    """
    cached = cache_get("cloudguard:stats")
    if cached is not None:
        return cached
    stats = db_fn()
    cache_set("cloudguard:stats", stats, STATS_TTL)
    return stats


def invalidate_stats():
    """Call after every new alert to keep cache consistent."""
    cache_delete("cloudguard:stats")
