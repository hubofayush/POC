"""
app.core.security.passwords
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Password hashing via pwdlib (argon2id, recommended parameters).
"""
from __future__ import annotations

from pwdlib import PasswordHash

_password_hash = PasswordHash.recommended()

# Precomputed hash of a throwaway password — used to equalize login timing for
# unknown usernames (user-enumeration resistance). Same params as real hashes.
_DUMMY_HASH = _password_hash.hash("d5-timing-equalizer")


def hash_password(password: str) -> str:
    """Hash a plaintext password with argon2id."""
    return _password_hash.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a stored argon2id hash."""
    return _password_hash.verify(password, password_hash)


def dummy_verify(password: str) -> bool:
    """Verify against the dummy hash (always False) to burn comparable time."""
    return _password_hash.verify(password, _DUMMY_HASH)
