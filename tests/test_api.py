import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from werkzeug.security import check_password_hash

from app import create_app


@pytest.fixture
def app(tmp_path):
    return create_app({
        "TESTING": True,
        "DATABASE": str(tmp_path / "test.sqlite"),
        "JWT_SECRET": secrets.token_hex(32),
    })


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def account(app):
    password = secrets.token_urlsafe(24)
    result = app.test_cli_runner().invoke(
        args=["create-user", "alice"], input=f"{password}\n{password}\n",
    )
    assert result.exit_code == 0, result.output
    return {"username": "alice", "password": password}


@pytest.fixture
def headers(client, account):
    response = client.post("/auth/login", json=account)
    assert response.status_code == 200
    return {"Authorization": "Bearer " + response.json["access_token"]}


def test_login_and_password_storage(app, client, account):
    response = client.post("/auth/login", json=account)
    assert response.status_code == 200
    payload = jwt.decode(
        response.json["access_token"], app.config["JWT_SECRET"],
        algorithms=["HS256"], audience="notes-api", issuer="notes-api",
    )
    assert payload["exp"] - payload["iat"] == 900
    assert "password" not in payload
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        stored = connection.execute("SELECT password_hash FROM users").fetchone()[0]
    assert stored.startswith("scrypt:")
    assert check_password_hash(stored, account["password"])


@pytest.mark.parametrize("method", ["get", "post"])
def test_auth_required(client, method):
    assert getattr(client, method)("/api/data").status_code == 401


def test_wrong_password_and_unknown_user_match(client, account):
    wrong = client.post("/auth/login", json={**account, "password": "wrong"})
    missing = client.post("/auth/login", json={**account, "username": "missing"})
    assert wrong.status_code == missing.status_code == 401
    assert wrong.json == missing.json


def test_sql_injection_cannot_log_in(client, account):
    response = client.post("/auth/login", json={**account, "username": "' OR 1=1 --"})
    assert response.status_code == 401


def test_notes_escape_xss_and_preserve_sql_as_data(client, headers):
    text = "<script>alert(1)</script>'; DROP TABLE users; --"
    created = client.post("/api/data", headers=headers, json={"text": text})
    assert created.status_code == 201
    assert "<script>" not in created.json["text"]
    assert "&lt;script&gt;" in created.json["text"]
    response = client.get("/api/data", headers=headers)
    assert response.status_code == 200
    assert response.json == [created.json]


def test_notes_are_private(app, client, headers):
    password = secrets.token_urlsafe(24)
    result = app.test_cli_runner().invoke(
        args=["create-user", "bob"], input=f"{password}\n{password}\n",
    )
    assert result.exit_code == 0
    # Даже переданный клиентом user_id не меняет владельца записи.
    assert client.post(
        "/api/data", headers=headers, json={"text": "Личная заметка", "user_id": 2},
    ).status_code == 201
    token = client.post("/auth/login", json={"username": "bob", "password": password})
    bob_headers = {"Authorization": "Bearer " + token.json["access_token"]}
    assert client.get("/api/data", headers=bob_headers).json == []
    assert len(client.get("/api/data", headers=headers).json) == 1


@pytest.mark.parametrize("kind", ["expired", "signature", "missing_exp", "algorithm", "user", "audience"])
def test_invalid_jwt(app, client, account, kind):
    now = datetime.now(timezone.utc)
    payload = {"sub": "1", "iat": now, "exp": now + timedelta(minutes=15),
               "iss": "notes-api", "aud": "notes-api"}
    key, algorithm = app.config["JWT_SECRET"], "HS256"
    if kind == "expired":
        payload["exp"] = now - timedelta(seconds=1)
    elif kind == "signature":
        key = secrets.token_hex(32)
    elif kind == "missing_exp":
        del payload["exp"]
    elif kind == "algorithm":
        algorithm = "HS384"
    elif kind == "user":
        payload["sub"] = "999"
    elif kind == "audience":
        payload["aud"] = "other-api"
    token = jwt.encode(payload, key, algorithm=algorithm)
    assert client.get("/api/data", headers={"Authorization": f"Bearer {token}"}).status_code == 401


@pytest.mark.parametrize("value", [None, [], {}, {"text": 12}, {"text": " "}, {"text": "a" * 1001}])
def test_invalid_note(client, headers, value):
    response = client.post("/api/data", headers=headers, json=value)
    assert response.status_code in (400, 415)


def test_invalid_json_and_large_body(client, headers):
    assert client.post(
        "/api/data", headers=headers, data="{", content_type="application/json",
    ).status_code == 400
    assert client.post(
        "/api/data", headers=headers, json={"text": "a" * 20000},
    ).status_code == 413


def test_login_rate_limit(client):
    for _ in range(5):
        assert client.post("/auth/login", json={"username": "nobody", "password": "wrong"}).status_code == 401
    response = client.post("/auth/login", json={"username": "nobody", "password": "wrong"})
    assert response.status_code == 429
    assert response.is_json


def test_headers(client):
    response = client.get("/api/data")
    assert response.is_json
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"


def test_missing_secret_fails(monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        create_app()
