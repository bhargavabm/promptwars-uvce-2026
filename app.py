"""Bankism AI Security Firewall Application.

Flask application exposing REST endpoints to evaluate untrusted natural
language banking messages against defensive firewall policies.
"""

import hashlib
import hmac
import json
import os
import secrets
from functools import wraps
from typing import Optional

from dotenv import load_dotenv
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)

from guard import evaluate_message

# Load environment configuration
load_dotenv()

app = Flask(__name__, static_folder="static", static_url_path="/static")

# Session hardening. Set BANKISM_SECRET_KEY in production; otherwise an
# ephemeral key is generated and users are logged out whenever the app restarts.
app.config.update(
    SECRET_KEY=os.getenv("BANKISM_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("BANKISM_COOKIE_SECURE", "false").lower() == "true",
)

PBKDF2_ITERATIONS = 210_000


def hash_password(password: str, salt: Optional[str] = None) -> str:
    """Hash a password with PBKDF2-HMAC-SHA256.

    Returns ``pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>`` so it can be
    stored in the BANKISM_PASSWORD_HASH environment variable.
    """
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verification of a password against a stored hash."""
    try:
        algorithm, iterations, salt, digest = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations)
        )
        return hmac.compare_digest(candidate.hex(), digest)
    except (ValueError, TypeError):
        return False


def _get_csrf_token() -> str:
    """Return the session CSRF token, creating one if necessary."""
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _is_authenticated() -> bool:
    """Return True when the current session belongs to a logged-in user."""
    return bool(session.get("user"))


def login_required(api: bool = False):
    """Require an authenticated session; return 401 JSON for API routes."""

    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if _is_authenticated():
                return view(*args, **kwargs)
            if api:
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login"))

        return wrapped

    return decorator


@app.before_request
def protect_static_console():
    """Prevent the console shell from being fetched directly as a static file."""
    if request.path == "/static/index.html" and not _is_authenticated():
        return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Render and process the session login form."""
    error = None

    if request.method == "POST":
        form_token = request.form.get("csrf_token", "")
        session_token = session.get("csrf_token", "")
        if not session_token or not hmac.compare_digest(form_token, session_token):
            return (
                render_template(
                    "login.html", error="Session expired. Please try again.", csrf_token=_get_csrf_token()
                ),
                400,
            )

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        expected_user = os.getenv("BANKISM_USERNAME", "")
        expected_hash = os.getenv("BANKISM_PASSWORD_HASH", "")

        if (
            expected_user
            and expected_hash
            and hmac.compare_digest(username.encode("utf-8"), expected_user.encode("utf-8"))
            and verify_password(password, expected_hash)
        ):
            session.clear()
            session["user"] = username
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("index"))

        error = "Invalid username or password."

    status = 401 if error else 200
    return render_template("login.html", error=error, csrf_token=_get_csrf_token()), status


@app.route("/logout", methods=["GET", "POST"])
def logout():
    """Clear the session and return to the login page."""
    session.clear()
    return redirect(url_for("login"))


@app.route("/", methods=["GET"])
@login_required()
def index():
    """Serve the single-page Bankism web interface."""
    return send_from_directory(app.static_folder, "index.html")


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint returning firewall status."""
    return jsonify({"status": "ok"}), 200


@app.route("/evaluate", methods=["POST"])
@login_required(api=True)
def evaluate_request():
    """Screen untrusted user messages and return structured security verdict."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        # Tolerate a valid JSON object sent without Content-Type: application/json
        # (common with PowerShell Invoke-RestMethod / Invoke-WebRequest defaults).
        try:
            fallback = json.loads(request.get_data(as_text=True))
        except (ValueError, TypeError):
            fallback = None
        if isinstance(fallback, dict):
            data = fallback

    if not isinstance(data, dict):
        return jsonify({"error": "Request payload must be a JSON object"}), 400

    if "message" not in data or not isinstance(data["message"], str):
        return jsonify({"error": "Field 'message' is required and must be a string"}), 400

    user_message = data["message"]
    if not user_message.strip():
        return jsonify({"error": "Field 'message' must not be blank"}), 400

    try:
        verdict = evaluate_message(user_message)

        if verdict.verdict == "approved":
            # =========================================================================
            # [CORE BANKING SERVICE INTEGRATION POINT]
            # Approved requests would be forwarded to the core banking service here:
            # e.g., core_banking_client.execute_intent(
            #     intent=verdict.intent,
            #     message=user_message,
            # )
            # Real banking APIs are not called here to ensure strict sandbox isolation.
            # =========================================================================
            pass

        return jsonify(verdict.to_dict()), 200

    except Exception:
        # Never log API keys or return internal stack traces to the client
        return jsonify({"error": "Internal security firewall error during evaluation"}), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
