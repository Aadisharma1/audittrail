import time

import jwt as pyjwt

from audittrail import auth


def test_issue_and_verify_roundtrip():
    user = {"username": "auditor", "role": "auditor"}
    token = auth.issue_token(user, expires_minutes=5)
    claims = auth.verify_token(token)
    assert claims is not None
    assert claims["sub"] == "auditor" and claims["role"] == "auditor"


def test_expired_token_rejected():
    now = int(time.time())
    stale = pyjwt.encode(
        {"sub": "auditor", "role": "auditor", "iat": now - 7200, "exp": now - 60},
        auth.get_secret(), algorithm="HS256",
    )
    assert auth.verify_token(stale) is None


def test_wrong_secret_rejected():
    now = int(time.time())
    forged = pyjwt.encode(
        {"sub": "attacker", "role": "auditor", "iat": now, "exp": now + 600},
        "not-the-real-secret", algorithm="HS256",
    )
    assert auth.verify_token(forged) is None


def test_garbage_string_rejected():
    assert auth.verify_token("not.a.jwt") is None
    assert auth.verify_token("") is None


def test_authenticate_uses_demo_users():
    assert auth.authenticate("auditor", "audit-demo-2025")["role"] == "auditor"
    assert auth.authenticate("auditor", "wrong") is None
    assert auth.authenticate("nobody", "x") is None


def test_dev_secret_warns_but_functions():
    """With AUDITTRAIL_JWT_SECRET unset the dev secret is used — the code must
    still work locally while the warning documents the risk."""
    import audittrail.auth as a

    assert a.get_secret()
    user = {"username": "service", "role": "service"}
    assert a.verify_token(a.issue_token(user)) is not None
