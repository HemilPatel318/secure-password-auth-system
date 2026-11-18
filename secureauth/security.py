import secrets
from datetime import datetime, timezone

import bcrypt

from .config import PASSWORD_RULE


def validate_password(password: str):
    # Returns both the validation result and the message used in the UI.
    if not PASSWORD_RULE.match(password):
        return (
            False,
            "Password must be at least 10 chars and include uppercase, lowercase, number, and special char.",
        )
    return True, ""


def hash_value(value: str) -> str:
    # bcrypt is used for both account passwords and OTP values stored in the database.
    return bcrypt.hashpw(value.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_hash(raw_value: str, hashed_value: str) -> bool:
    # Compare a raw secret against a stored bcrypt hash.
    return bcrypt.checkpw(raw_value.encode("utf-8"), hashed_value.encode("utf-8"))


def generate_otp() -> str:
    # Keep OTPs numeric and fixed-length for simple demo input handling.
    return f"{secrets.randbelow(1000000):06d}"


def now_utc() -> datetime:
    # All timestamps are timezone-aware to keep expiry checks consistent.
    return datetime.now(timezone.utc)
