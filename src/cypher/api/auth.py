"""Local, single-admin authentication for the dashboard.

No external identity provider — this is an offline tool. The admin
password is set once via `CYPHER_ADMIN_PASSWORD_HASH` (an env var holding
a bcrypt hash, generated with `scripts/set_admin_password.py`) so the
plaintext password is never stored anywhere, including in this repo's
config files.

Sessions are a signed, expiring cookie (itsdangerous) — no server-side
session store needed, which keeps the unprivileged API process simple.
"""
from __future__ import annotations

import os

import bcrypt
from fastapi import Cookie, HTTPException, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

# Using the `bcrypt` package directly rather than passlib's CryptContext:
# passlib 1.7.x probes bcrypt's internals in a way that breaks on
# bcrypt>=4.1 (see https://github.com/pyca/bcrypt/issues/684). Calling
# bcrypt directly avoids that whole compatibility surface.
_SESSION_MAX_AGE = 8 * 3600  # 8 hours
_BCRYPT_MAX_BYTES = 72  # bcrypt silently ignores anything past this


def hash_password(plain: str) -> str:
    encoded = plain.encode("utf-8")[:_BCRYPT_MAX_BYTES]
    return bcrypt.hashpw(encoded, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    encoded = plain.encode("utf-8")[:_BCRYPT_MAX_BYTES]
    try:
        return bcrypt.checkpw(encoded, hashed.encode("utf-8"))
    except ValueError:
        return False


def _serializer(secret: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret, salt="cypher-session")


def create_session_token(username: str, secret: str) -> str:
    return _serializer(secret).dumps({"username": username})


def verify_session_token(token: str, secret: str) -> str | None:
    try:
        data = _serializer(secret).loads(token, max_age=_SESSION_MAX_AGE)
        return data.get("username")
    except (BadSignature, SignatureExpired):
        return None


def require_login(cypher_session: str | None = Cookie(default=None)) -> str:
    """FastAPI dependency — raises 401 if there's no valid session cookie."""
    secret = os.environ.get("CYPHER_SESSION_SECRET")
    if not secret:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "CYPHER_SESSION_SECRET is not set — see docs/user-guide.md",
        )
    if not cypher_session:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not logged in")
    username = verify_session_token(cypher_session, secret)
    if not username:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired or invalid")
    return username
