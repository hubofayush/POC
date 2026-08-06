from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt  
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException, status

from app.config import settings

# ---------------------------------------------------------------------------
# Key management — load once at module import, cache in memory.
# This eliminates blocking Path.read_text() disk I/O on every request.
# ---------------------------------------------------------------------------

_PRIVATE_KEY: str = ""
_PUBLIC_KEY: str = ""


def _ensure_and_cache_keys() -> None:
    """Generate RSA keypair if absent, then cache both keys in module globals."""
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

    # Load into memory cache — only disk read that ever happens
    _PRIVATE_KEY = private_path.read_text()
    _PUBLIC_KEY = public_path.read_text()


def _load_private_key() -> str:
    """Return cached private key (no disk I/O)."""
    return _PRIVATE_KEY


def _load_public_key() -> str:
    """Return cached public key (no disk I/O)."""
    return _PUBLIC_KEY


# Run once at import time — ensures keys exist and fills the in-memory cache.
_ensure_and_cache_keys()

def create_token(user_id: str, role: str, org: str, token_type: str = "access") -> str:
    expire = (datetime.now(timezone.utc)) + timedelta(
        minutes=settings.JWT_ACCESS_EXPIRE_MINUTE
        if token_type == "access"
        else settings.JWT_REFRESH_EXPIRE_DAYS * 1440
    )
    payload = {
        "sub":user_id,
        "role":role,
        "org":org,
        "type":token_type,
        "iat":datetime.now(timezone.utc)
    }

    return jwt.encode(payload, _load_private_key(),algorithm=settings.JWT_ALGORITHM)

def decode_token(token:str) ->dict:
    try:
        return jwt.decode(token,_load_public_key(),algorithms=[settings.JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token Expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Token")

