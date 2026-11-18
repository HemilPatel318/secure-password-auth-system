import pytest
import os
import tempfile
from secureauth import create_app
from secureauth.db import init_db


@pytest.fixture
def client():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    app = create_app()
    app.config["TESTING"] = True
    app.config["DB_PATH"] = db_path
    app.config["SESSION_COOKIE_SECURE"] = False
    init_db(db_path)

    # Register a real user first
    with app.test_client() as client:
        client.post("/register", data={
            "username": "admin",
            "email": "admin@example.com",
            "password": "Secure@Pass1"
        })
        yield client

    os.close(db_fd)
    os.unlink(db_path)


SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "' OR 'x'='x",
    "'; DROP TABLE users;--",
    "' UNION SELECT * FROM users--",
    "' UNION SELECT id,username,email,password_hash,failed_attempts,lock_until,created_at FROM users--",
    "1' OR '1'='1' /*",
    "' OR 1=1#",
    "\" OR \"1\"=\"1",
]


def test_sqli_cannot_bypass_login(client):
    for payload in SQLI_PAYLOADS:
        res = client.post("/login", data={
            "email": payload,
            "password": payload
        }, follow_redirects=True)
        # Must NOT land on dashboard or OTP page via injection
        assert b"dashboard" not in res.data.lower(), f"BYPASS via: {payload}"
        assert b"enter the otp" not in res.data.lower() and b"verify-otp" not in res.data.lower(), f"OTP bypass via: {payload}"
        assert b"Invalid email or password" in res.data or b"invalid email or password" in res.data, f"No rejection message via: {payload}"


def test_sqli_cannot_dump_users(client):
    for payload in SQLI_PAYLOADS:
        res = client.post("/login", data={
            "email": payload,
            "password": "anything"
        }, follow_redirects=True)
        # Must NOT expose password hashes or user data
        assert b"password_hash" not in res.data, f"Data leak via: {payload}"
        assert b"$2b$" not in res.data, f"Hash leak via: {payload}"


def test_sqli_cannot_drop_table(client):
    for payload in SQLI_PAYLOADS:
        client.post("/login", data={"email": payload, "password": payload})

    # Real user must still exist after all injection attempts
    res = client.post("/login", data={
        "email": "admin@example.com",
        "password": "Secure@Pass1"
    }, follow_redirects=True)
    assert b"Invalid" not in res.data or b"OTP" in res.data or b"verify" in res.data.lower()


def test_sqli_in_registration(client):
    for payload in SQLI_PAYLOADS:
        res = client.post("/register", data={
            "username": payload,
            "email": f"test_{SQLI_PAYLOADS.index(payload)}@example.com",
            "password": "Secure@Pass1"
        }, follow_redirects=True)
        assert b"password_hash" not in res.data
        assert b"$2b$" not in res.data
