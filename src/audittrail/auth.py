"""JWT auth (PyJWT). Secret from env; demo users from configs/users.json."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import jwt

logger = logging.getLogger(__name__)

DEV_SECRET = "dev-secret-change-me"


def get_secret() -> str:
    secret = os.environ.get("AUDITTRAIL_JWT_SECRET", DEV_SECRET)
    if secret == DEV_SECRET:
        logger.warning(
            "AUDITTRAIL_JWT_SECRET not set — using the DEV secret. "
            "Set a real secret for anything beyond local testing."
        )
    return secret


def load_users() -> dict[str, dict]:
    path = os.environ.get("AUDITTRAIL_USERS_JSON") or \
        Path(__file__).resolve().parents[2] / "configs" / "users.json"
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return {u["username"]: u for u in raw["users"]}


def authenticate(username: str, password: str) -> dict | None:
    user = load_users().get(username)
    if user and user["password"] == password:
        return user
    return None


def issue_token(user: dict, expires_minutes: int = 480) -> str:
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    payload = {
        "sub": user["username"],
        "role": user["role"],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
    }
    return jwt.encode(payload, get_secret(), algorithm="HS256")


def verify_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, get_secret(), algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
