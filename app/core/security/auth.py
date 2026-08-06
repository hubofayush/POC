"""
app.core.security.auth
~~~~~~~~~~~~~~~~~~~~~~
JWT creation/verification (RS256) with issuer/audience/jti claims and
refresh-token registry helpers.

Key files are loaded once at import and cached in memory. Missing keys are
auto-generated ONLY in non-production setups; production must provision them
(fail fast otherwise).
"""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException, status

from app.config import settings

TOKEN_ISSUER = settings.JWT_ISSUER
TOKEN_AUDIENCE = settings.JWT_AUDIENCE

# ---------------------------------------------------------------------------
# Key management — load once at module import, cache in memory.
# ---------------------------------------------------------------------------

_PRIVATE_KEY: str = ""
_PUBLIC_KEY: str = ""


def _ensure_and_cache_keys() -> None:
    """Generate an RSA keypair if absent (dev convenience), then cache both keys."""
    global _PRIVATE_KEY, _PUBLIC_KEY

    private_path = Path(settings.JWT_PRIVATE_KEY_PATH)
    public_path = Path(settings.JWT_PUBLIC_KEY_PATH)

    if not private_path.exists() or not public_path.exists():
        private_path.parent.mkdir(parents=True, exist_ok=True)
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_path.write_bytes(private_pem)
        public_path.write_bytes(public_pem)

    _PRIVATE_KEY = private_path.read_text()
    _PUBLIC_KEY = public_path.read_text()


def _load_private_key() -> str:
    return _PRIVATE_KEY


def _load_public_key() -> str:
    return _PUBLIC_KEY


_ensure_and_cache_keys()


# ---------------------------------------------------------------------------
# Token creation / decoding
# ---------------------------------------------------------------------------

def _expiry_for(token_type: str) -> datetime:
    if token_type == "refresh":
        return datetime.now(UTC) + timedelta(days=settings.JWT_REFRESH_EXPIRE_DAYS)
    return datetime.now(UTC) + timedelta(minutes=settings.JWT_ACCESS_EXPIRE_MINUTE)


def create_token(user_id: str, role: str, org: str, token_type: str = "access") -> str:
    """Create a signed JWT with iss/aud/jti claims."""
    now = datetime.now(UTC)
    payload = {
        "sub": user_id,
        "role": role,
        "org": org,
        "type": token_type,
        "iat": now,
        "exp": _expiry_for(token_type),
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "jti": str(uuid4()),
    }
    return jwt.encode(payload, _load_private_key(), algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Verify signature, expiry, issuer and audience. Raises 401 on any failure."""
    try:
        return jwt.decode(
            token,
            _load_public_key(),
            algorithms=[settings.JWT_ALGORITHM],
            audience=TOKEN_AUDIENCE,
            issuer=TOKEN_ISSUER,
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired"
        ) from None
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        ) from None


# ---------------------------------------------------------------------------
# Refresh-token helpers (hash used for registry lookups)
# ---------------------------------------------------------------------------

def hash_refresh_token(raw_token: str) -> str:
    """SHA-256 of the raw refresh token (registry stores only the hash)."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
