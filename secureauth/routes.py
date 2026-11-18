from datetime import datetime, timedelta

from flask import current_app, flash, redirect, render_template, request, session, url_for

from .db import get_db
from .security import generate_otp, hash_value, now_utc, validate_password, verify_hash


def register_routes(app) -> None:
    # Register every public page and auth action in one place.
    app.add_url_rule("/", view_func=home)
    app.add_url_rule("/register", view_func=register, methods=["GET", "POST"])
    app.add_url_rule("/login", view_func=login, methods=["GET", "POST"])
    app.add_url_rule("/verify-otp", view_func=verify_otp, methods=["GET", "POST"])
    app.add_url_rule("/resend-otp", view_func=resend_otp, methods=["POST"])
    app.add_url_rule("/dashboard", view_func=dashboard)
    app.add_url_rule("/logout", view_func=logout, methods=["GET", "POST"])


def home():
    # Send authenticated users straight to the protected area.
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


def register():
    # Step 1: create a local account after validating the password policy.
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("All fields are required.", "error")
            return render_template("register.html")

        valid, message = validate_password(password)
        if not valid:
            flash(message, "error")
            return render_template("register.html")

        if fetch_user_by_email(email):
            flash("An account with this email already exists.", "error")
            return render_template("register.html")

        db = get_db()
        db.execute(
            """
            INSERT INTO users (username, email, password_hash, failed_attempts, lock_until)
            VALUES (?, ?, ?, 0, NULL)
            """,
            (username, email, hash_value(password)),
        )
        db.commit()
        flash("Registration successful. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


def login():
    # Step 2: verify the password before starting the OTP challenge.
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = fetch_user_by_email(email)

        if not user:
            flash("Invalid email or password.", "error")
            return render_template("login.html")

        if is_account_locked(user):
            remaining = get_lock_seconds_remaining(user)
            flash(f"Account locked. Try again in {remaining} seconds.", "error")
            return render_template("login.html")

        if not verify_hash(password, user["password_hash"]):
            update_failed_attempt(user)
            flash("Invalid email or password.", "error")
            return render_template("login.html")

        # A successful password check clears lockout state and starts MFA.
        reset_failed_attempts(user["id"])
        start_otp_challenge(user["id"], email)
        flash("Password verified. Enter the OTP sent to your secure channel.", "success")
        return redirect(url_for("verify_otp"))

    return render_template("login.html")


def verify_otp():
    # Step 3: complete MFA using the pending OTP challenge stored in session.
    pending_user_id = session.get("pending_user_id")
    challenge_id = session.get("otp_challenge_id")

    if not pending_user_id or not challenge_id:
        flash("OTP session expired. Please login again.", "error")
        return redirect(url_for("login"))

    challenge = fetch_pending_challenge(challenge_id, pending_user_id)
    if not challenge:
        clear_pending_auth()
        flash("Invalid OTP session. Please login again.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        if otp_is_expired(challenge):
            # Expired challenges are invalidated immediately to force a fresh login.
            return expire_pending_otp(challenge_id)

        if not verify_hash(otp, challenge["otp_hash"]):
            return reject_pending_otp(challenge_id)

        return complete_login(pending_user_id, challenge_id)

    return render_template(
        "verify_otp.html",
        ttl=current_app.config["OTP_EXPIRY_SECONDS"],
        expires_at_epoch_ms=int(parse_iso_datetime(challenge["expires_at"]).timestamp() * 1000),
    )


def resend_otp():
    # Auto-generates a new OTP when the previous one times out on the verify page.
    pending_user_id = session.get("pending_user_id")
    challenge_id = session.get("otp_challenge_id")
    if not pending_user_id or not challenge_id:
        flash("OTP session expired. Please login again.", "error")
        return redirect(url_for("login"))

    user = fetch_user_identity(pending_user_id)
    if not user:
        clear_pending_auth()
        flash("Invalid session. Please login again.", "error")
        return redirect(url_for("login"))

    # Replace the previous challenge so only the newest OTP can be used.
    start_otp_challenge(pending_user_id, user["email"], clear_session=False)
    flash("Previous OTP expired. A new OTP has been generated.", "success")
    return redirect(url_for("verify_otp"))


def dashboard():
    # Protected page shown only after both password and OTP verification succeed.
    user_id = session.get("user_id")
    if not user_id:
        flash("Login required.", "error")
        return redirect(url_for("login"))

    user = fetch_user_identity(user_id)
    if not user:
        session.clear()
        flash("Session invalid. Please login.", "error")
        return redirect(url_for("login"))

    return render_template("dashboard.html", user=user)


def logout():
    # Logging out clears both full and partial authentication session state.
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


def fetch_user_by_email(email: str):
    # Shared lookup used by registration and login.
    return get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def fetch_user_identity(user_id: int):
    # Shared lookup for routes that only need the basic user profile.
    return get_db().execute(
        "SELECT id, username, email FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def fetch_pending_challenge(challenge_id: int, user_id: int):
    # Reads the OTP challenge tied to the current in-progress MFA session.
    return get_db().execute(
        "SELECT * FROM otp_challenges WHERE id = ? AND user_id = ?",
        (challenge_id, user_id),
    ).fetchone()


def is_account_locked(user) -> bool:
    # Users remain blocked until the stored lockout time has passed.
    lock_until = user["lock_until"]
    return bool(lock_until and now_utc() < parse_iso_datetime(lock_until))


def get_lock_seconds_remaining(user) -> int:
    # Used to show the remaining lockout time on the login form.
    lock_until = parse_iso_datetime(user["lock_until"])
    return max(int((lock_until - now_utc()).total_seconds()), 0)


def update_failed_attempt(user) -> None:
    # Increment failures and apply a temporary lockout after repeated bad passwords.
    db = get_db()
    attempts = user["failed_attempts"] + 1
    if attempts >= current_app.config["MAX_FAILED_ATTEMPTS"]:
        lock_until = (now_utc() + timedelta(minutes=current_app.config["LOCK_MINUTES"])).isoformat()
        db.execute(
            "UPDATE users SET failed_attempts = 0, lock_until = ? WHERE id = ?",
            (lock_until, user["id"]),
        )
        flash("Account locked for 5 minutes due to repeated failures.", "error")
    else:
        db.execute(
            "UPDATE users SET failed_attempts = ? WHERE id = ?",
            (attempts, user["id"]),
        )
    db.commit()


def reset_failed_attempts(user_id: int) -> None:
    # Clear lockout metadata after a correct password.
    db = get_db()
    db.execute(
        "UPDATE users SET failed_attempts = 0, lock_until = NULL WHERE id = ?",
        (user_id,),
    )
    db.commit()


def clear_pending_auth() -> None:
    # Remove the temporary session values used during the MFA step.
    session.pop("pending_user_id", None)
    session.pop("otp_challenge_id", None)


def delete_otp_challenge(challenge_id: int) -> None:
    # Permanently remove a completed or invalid OTP challenge.
    db = get_db()
    db.execute("DELETE FROM otp_challenges WHERE id = ?", (challenge_id,))
    db.commit()


def start_otp_challenge(user_id: int, email: str, clear_session: bool = True) -> None:
    # Create a fresh OTP row and sync the pending MFA session state.
    otp_plain = generate_otp()
    now = now_utc()
    expires_at = now + timedelta(seconds=current_app.config["OTP_EXPIRY_SECONDS"])

    db = get_db()
    # Only one live OTP challenge should exist per user.
    db.execute("DELETE FROM otp_challenges WHERE user_id = ?", (user_id,))
    cur = db.execute(
        """
        INSERT INTO otp_challenges (user_id, otp_hash, expires_at, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (user_id, hash_value(otp_plain), expires_at.isoformat(), now.isoformat()),
    )
    db.commit()

    if clear_session:
        session.clear()
    session["pending_user_id"] = user_id
    session["otp_challenge_id"] = cur.lastrowid
    session.permanent = True

    log_demo_otp(email, otp_plain)


def log_demo_otp(email: str, otp_plain: str) -> None:
    # Demo-only output so the generated OTP can be read from the console.
    print(
        f"[DEMO OTP] user={email} otp={otp_plain} expires_in={current_app.config['OTP_EXPIRY_SECONDS']}s"
    )


def otp_is_expired(challenge) -> bool:
    # Expiry is recalculated server-side, not trusted from the browser countdown.
    return now_utc() > parse_iso_datetime(challenge["expires_at"])


def expire_pending_otp(challenge_id: int):
    # Shared redirect path for expired OTP submissions.
    delete_otp_challenge(challenge_id)
    clear_pending_auth()
    flash("OTP expired after 60 seconds. Please login again.", "error")
    return redirect(url_for("login"))


def reject_pending_otp(challenge_id: int):
    # Shared redirect path for incorrect OTP submissions.
    delete_otp_challenge(challenge_id)
    clear_pending_auth()
    flash("Incorrect OTP. Please login again.", "error")
    return redirect(url_for("login"))


def complete_login(user_id: int, challenge_id: int):
    # Promote the pending MFA session into a full authenticated session.
    delete_otp_challenge(challenge_id)
    clear_pending_auth()
    session["user_id"] = user_id
    session.permanent = True
    flash("MFA successful. You are now logged in.", "success")
    return redirect(url_for("dashboard"))


def parse_iso_datetime(value: str) -> datetime:
    # Centralizes ISO parsing so time comparisons stay consistent across the file.
    return datetime.fromisoformat(value)
