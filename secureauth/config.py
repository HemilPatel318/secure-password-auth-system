import os
import re
from datetime import timedelta

# Project paths shared across the application.
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
DB_PATH = os.path.join(INSTANCE_DIR, "auth.db")
TEMPLATE_DIR = os.path.join(BASE_DIR, "app", "templates")
STATIC_DIR = os.path.join(BASE_DIR, "app", "static")

# Enforces the password policy on both registration and validation feedback.
PASSWORD_RULE = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{10,}$"
)

# Security settings used by the login and MFA workflow.
OTP_EXPIRY_SECONDS = 60
MAX_FAILED_ATTEMPTS = 5
LOCK_MINUTES = 5


def apply_config(app) -> None:
    # Keep app settings in one place so the auth flow can read from Flask config.
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-change-this-secret")
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = os.getenv("FLASK_SECURE_COOKIE", "0") == "1"
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=7)
    app.config["DB_PATH"] = DB_PATH
    app.config["OTP_EXPIRY_SECONDS"] = OTP_EXPIRY_SECONDS
    app.config["MAX_FAILED_ATTEMPTS"] = MAX_FAILED_ATTEMPTS
    app.config["LOCK_MINUTES"] = LOCK_MINUTES
