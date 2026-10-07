"""
Per-sensor API keys. A key is 256 bits of randomness, so a plain SHA-256 digest is enough to store it safely
(there is nothing to brute-force). Only the digest and a short lookup prefix are stored; the key itself is shown
once, at creation, and cannot be recovered afterwards.
"""
import hashlib
import hmac
import secrets

KEY_PREFIX = "snt_"
LOOKUP_LENGTH = 12  # "snt_" + 8 characters; public enough to index, too short to help an attacker


def generate_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def lookup_prefix(key: str) -> str:
    return key[:LOOKUP_LENGTH]


def key_matches(key: str, stored_hash: str) -> bool:
    return bool(stored_hash) and hmac.compare_digest(hash_key(key), stored_hash)
