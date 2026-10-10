from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta, timezone

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
except ImportError:  # pragma: no cover - dependency is declared in requirements
    PasswordHasher = None


class AuthError(ValueError):
    pass


# A fixed Argon2id verifier generated with the same parameters as _hasher().
# Its corresponding password is not an account credential; it equalises the
# expensive verification path for a username that does not exist.
DUMMY_PASSWORD_HASH = "$argon2id$v=19$m=65536,t=3,p=2$cuyInDr7h0fKkQOhKLxaWQ$ag8uhs2N1FCG7z+KBqg5QKOQzDXG8e+9ggsWWSnaggE"


class RateLimiter:
    """Small process-local limiter; successful login resets the address."""
    def __init__(self, limit=8, window_seconds=300):
        self.limit, self.window = limit, window_seconds
        self._entries: dict[str, list[float]] = {}

    def allowed(self, key: str) -> bool:
        now = time.monotonic()
        values = [x for x in self._entries.get(key, []) if now - x < self.window]
        self._entries[key] = values
        return len(values) < self.limit

    def failed(self, key: str):
        now = time.monotonic()
        values = [x for x in self._entries.get(key, []) if now - x < self.window]
        values.append(now)
        self._entries[key] = values[-self.limit:]

    def success(self, key: str):
        self._entries.pop(key, None)


def _hasher():
    if PasswordHasher is None:
        raise RuntimeError("argon2-cffi is required for web authentication")
    return PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)


def hash_password(password: str) -> str:
    if not isinstance(password, str) or len(password) < 12:
        raise AuthError("password must be at least 12 characters")
    if len(password) > 1024:
        raise AuthError("password is too long")
    return _hasher().hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return bool(_hasher().verify(password_hash, password))
    except (VerifyMismatchError, VerificationError, InvalidHashError, ValueError):
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def utc_after(*, minutes=0, hours=0) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes, hours=hours)).replace(microsecond=0).isoformat()


def safe_equal(left: str | None, right: str | None) -> bool:
    return bool(left and right and hmac.compare_digest(left, right))
