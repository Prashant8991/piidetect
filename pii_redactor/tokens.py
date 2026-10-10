"""
Stable Pseudonym Token Generation
Deterministic keyed HMAC-SHA256 tokens that guarantee the same entity receives
the identical pseudonym across multiple pages, files, and runs without leaking raw PII.
"""

import os
import re
import hmac
import hashlib
import secrets

def get_hmac_secret() -> bytes:
    env_secret = os.environ.get("PII_HMAC_SECRET")
    if env_secret:
        return env_secret.encode('utf-8') if isinstance(env_secret, str) else env_secret
    
    secret_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".hmac_secret")
    if os.path.exists(secret_path):
        try:
            with open(secret_path, "rb") as f:
                content = f.read().strip()
                if content:
                    return content
        except Exception:
            pass

    new_secret = secrets.token_bytes(32)
    try:
        with open(secret_path, "wb") as f:
            f.write(new_secret)
    except Exception:
        pass
    return new_secret

HMAC_SECRET = get_hmac_secret()


def canonicalize_person_name(raw: str) -> str:
    """Canonicalizes a person's name to surname/family root for cluster stability."""
    clean = raw.strip()
    clean = re.sub(r'^(?:Dr\.|Prof\.|Mr\.|Ms\.|Mrs\.|Mx\.|Sir|Doctor|Professor)\s*', '', clean, flags=re.IGNORECASE)
    clean = re.sub(r'[^\w\s-]', '', clean).strip().lower()
    parts = clean.split()
    if len(parts) >= 1:
        return parts[-1]
    return clean


def generate_stable_token(entity_type: str, raw_value: str) -> str:
    """Generates an immutable pseudonym token using HMAC-SHA256, e.g. [PERSON_NAME_3f9a1c]."""
    if entity_type == "PERSON_NAME":
        norm_key = canonicalize_person_name(raw_value)
    elif entity_type == "PHONE_NUMBER":
        norm_key = re.sub(r'\D', '', raw_value)
        if len(norm_key) > 7:
            norm_key = norm_key[-10:]
    elif entity_type == "EMAIL":
        norm_key = raw_value.strip().lower()
    else:
        norm_key = re.sub(r'[\s\-_.,]+', '', raw_value.strip().lower())

    h = hmac.new(HMAC_SECRET, norm_key.encode('utf-8'), hashlib.sha256).hexdigest()[:6]
    return f"[{entity_type}_{h}]"


class TokenMap:
    def __init__(self):
        self._ids = {}
        self._count = {}

    def token(self, entity_type, value):
        key = (entity_type, re.sub(r"\W+", "", value.lower()))
        if key not in self._ids:
            self._count[entity_type] = self._count.get(entity_type, 0) + 1
            self._ids[key] = self._count[entity_type]
        return f"[{entity_type}_{self._ids[key]}]"

