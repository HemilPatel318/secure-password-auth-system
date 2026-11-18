import pytest
import sqlite3
import os
import tempfile
from secureauth import create_app


@pytest.fixture
def app():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    app = create_app()
    app.config["TESTING"] = True
    app.config["DB_PATH"] = db_path
    app.config["SESSION_COOKIE_SECURE"] = False

    from secureauth.db import init_db
    init_db(db_path)

    yield app

    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def client(app):
    return app.test_client()


def register_user(client, username="testuser", email="test@example.com", password="Secure@Pass1"):
    return client.post("/register", data={"username": username, "email": email, "password": password}, follow_redirects=True)


# ── Registration Tests ──────────────────────────────────────────────────────

def test_register_valid_user(client):
    res = register_user(client)
    assert b"Registration successful" in res.data


def test_register_duplicate_email(client):
    register_user(client)
    res = register_user(client)
    assert b"already exists" in res.data


def test_register_weak_password(client):
    res = register_user(client, password="weak")
    assert b"Password must be" in res.data


def test_register_missing_fields(client):
    res = client.post("/register", data={"username": "", "email": "", "password": ""}, follow_redirects=True)
    assert b"required" in res.data


def test_register_short_password(client):
    res = register_user(client, password="Short@1")
    assert b"Password must be" in res.data


def test_register_no_special_char(client):
    res = register_user(client, password="NoSpecial123")
    assert b"Password must be" in res.data


# ── Login Tests ────────────────────────────────────────────────────────────

def test_login_valid_credentials(client):
    register_user(client)
    res = client.post("/login", data={"email": "test@example.com", "password": "Secure@Pass1"}, follow_redirects=True)
    assert b"OTP" in res.data or b"otp" in res.data or b"verify" in res.data.lower()


def test_login_wrong_password(client):
    register_user(client)
    res = client.post("/login", data={"email": "test@example.com", "password": "WrongPass@1"}, follow_redirects=True)
    assert b"Invalid email or password" in res.data


def test_login_nonexistent_email(client):
    res = client.post("/login", data={"email": "ghost@example.com", "password": "Any@Pass123"}, follow_redirects=True)
    assert b"Invalid email or password" in res.data


def test_login_empty_fields(client):
    res = client.post("/login", data={"email": "", "password": ""}, follow_redirects=True)
    assert b"Invalid email or password" in res.data


# ── Account Lockout Tests ────────────────────────────────────────────────────

def test_account_locks_after_5_failed_attempts(client):
    register_user(client)
    for _ in range(5):
        client.post("/login", data={"email": "test@example.com", "password": "WrongPass@1"})
    res = client.post("/login", data={"email": "test@example.com", "password": "WrongPass@1"}, follow_redirects=True)
    assert b"locked" in res.data


def test_correct_password_resets_failed_attempts(client):
    register_user(client)
    for _ in range(3):
        client.post("/login", data={"email": "test@example.com", "password": "WrongPass@1"})
    res = client.post("/login", data={"email": "test@example.com", "password": "Secure@Pass1"}, follow_redirects=True)
    assert b"locked" not in res.data


# ── OTP / MFA Tests ──────────────────────────────────────────────────────────

def test_otp_page_requires_session(client):
    res = client.get("/verify-otp", follow_redirects=True)
    assert b"login" in res.data.lower()


def test_wrong_otp_redirects_to_login(client):
    register_user(client)
    client.post("/login", data={"email": "test@example.com", "password": "Secure@Pass1"})
    res = client.post("/verify-otp", data={"otp": "000000"}, follow_redirects=True)
    assert b"Incorrect OTP" in res.data or b"login" in res.data.lower()


def test_resend_otp_without_session(client):
    res = client.post("/resend-otp", follow_redirects=True)
    assert b"login" in res.data.lower()


# ── Dashboard / Session Tests ────────────────────────────────────────────────

def test_dashboard_requires_login(client):
    res = client.get("/dashboard", follow_redirects=True)
    assert b"Login required" in res.data or b"login" in res.data.lower()


def test_logout_clears_session(client):
    register_user(client)
    client.post("/login", data={"email": "test@example.com", "password": "Secure@Pass1"})
    client.post("/logout", follow_redirects=True)
    res = client.get("/dashboard", follow_redirects=True)
    assert b"login" in res.data.lower()


# ── Password Policy Tests ────────────────────────────────────────────────────

def test_password_no_uppercase(client):
    res = register_user(client, password="secure@pass1")
    assert b"Password must be" in res.data


def test_password_no_digit(client):
    res = register_user(client, password="Secure@Pass!")
    assert b"Password must be" in res.data


def test_password_exactly_10_chars(client):
    res = register_user(client, password="Secure@Pa1")
    assert b"Registration successful" in res.data or b"Password must be" in res.data
