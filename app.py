"""Небольшой API личных заметок: Flask + SQLite + JWT."""

import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import click
import jwt
from flask import Flask, abort, g, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import escape
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

AUTH_SCHEME = "Bearer"


def create_app(test_config=None):
    app = Flask(__name__, static_folder=None)
    app.config.from_mapping(
        JWT_SECRET=os.environ.get("JWT_SECRET", ""),
        DATABASE=str(Path(app.instance_path) / "notes.sqlite"),
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    if len(app.config["JWT_SECRET"].encode()) < 32:
        raise RuntimeError("Задайте JWT_SECRET: случайный секрет не короче 32 байт")
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    limiter = Limiter(
        get_remote_address, app=app, storage_uri="memory://",
        default_limits=["200 per hour"],
    )
    dummy_hash = generate_password_hash(secrets.token_urlsafe(32), method="scrypt")

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db

    @app.teardown_appcontext
    def close_db(_error):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    with app.app_context():
        db().executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                text TEXT NOT NULL
            );
        """)

    @app.cli.command("create-user")
    @click.argument("username")
    @click.password_option()
    def create_user(username, password):
        """Создать пользователя, запросив пароль без отображения на экране."""
        if not 1 <= len(username.strip()) <= 64 or not 12 <= len(password) <= 128:
            raise click.ClickException("Логин: 1–64 символа; пароль: 12–128 символов")
        try:
            db().execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username.strip(), generate_password_hash(password, method="scrypt")),
            )
            db().commit()
        except sqlite3.IntegrityError as error:
            raise click.ClickException("Пользователь уже существует") from error
        click.echo("Пользователь создан")

    def jwt_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            parts = request.headers.get("Authorization", "").split()
            if len(parts) != 2 or parts[0].lower() != AUTH_SCHEME.lower():
                abort(401, description="Требуется Bearer-токен")
            try:
                payload = jwt.decode(
                    parts[1], app.config["JWT_SECRET"], algorithms=["HS256"],
                    issuer="notes-api", audience="notes-api",
                    options={"require": ["sub", "iat", "exp", "iss", "aud"]},
                )
            except jwt.InvalidTokenError:
                abort(401, description="Недействительный или просроченный токен")
            user = db().execute(
                "SELECT id FROM users WHERE CAST(id AS TEXT) = ?", (payload["sub"],)
            ).fetchone()
            if user is None:
                abort(401, description="Пользователь не найден")
            g.user_id = user["id"]
            return view(*args, **kwargs)
        return wrapped

    def json_object():
        data = request.get_json()
        if not isinstance(data, dict):
            abort(400, description="Ожидается JSON-объект")
        return data

    @app.post("/auth/login")
    @limiter.limit("5 per minute")
    def login():
        data = json_object()
        username, password = data.get("username"), data.get("password")
        if (not isinstance(username, str) or not 1 <= len(username) <= 64
                or not isinstance(password, str) or not 1 <= len(password) <= 128):
            abort(400, description="Некорректный логин или пароль")
        user = db().execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        valid = check_password_hash(user["password_hash"] if user else dummy_hash, password)
        if not valid or user is None:
            abort(401, description="Неверный логин или пароль")
        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {"sub": str(user["id"]), "iat": now, "exp": now + timedelta(minutes=15),
             "iss": "notes-api", "aud": "notes-api"},
            app.config["JWT_SECRET"], algorithm="HS256",
        )
        return jsonify({"access_token": token, "token_type": AUTH_SCHEME, "expires_in": 900})

    @app.get("/api/data")
    @jwt_required
    def get_data():
        rows = db().execute(
            "SELECT id, text FROM notes WHERE user_id = ? ORDER BY id DESC LIMIT 100",
            (g.user_id,),
        ).fetchall()
        return jsonify([{"id": row["id"], "text": str(escape(row["text"]))} for row in rows])

    @app.post("/api/data")
    @jwt_required
    def create_data():
        text = json_object().get("text")
        if not isinstance(text, str) or not 1 <= len(text.strip()) <= 1000:
            abort(400, description="Поле text: строка длиной 1–1000 символов")
        text = text.strip()
        cursor = db().execute(
            "INSERT INTO notes (user_id, text) VALUES (?, ?)", (g.user_id, text)
        )
        db().commit()
        return jsonify(id=cursor.lastrowid, text=str(escape(text))), 201

    @app.errorhandler(HTTPException)
    def http_error(error):
        response = error.get_response()
        response.data = app.json.dumps({"error": str(escape(error.description))})
        response.content_type = "application/json"
        return response

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Cache-Control"] = "no-store"
        return response

    return app
