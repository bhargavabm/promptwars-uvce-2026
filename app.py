"""Bankism AI Security Firewall Application.

Flask application exposing REST endpoints to evaluate untrusted natural
language banking messages against defensive firewall policies, with optional
account sign-in, saved bank details, and privacy controls.
"""

import hmac
import json
import os
import re
import secrets
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory, session

import db
from guard import evaluate_message

# Load environment configuration
load_dotenv()

app = Flask(__name__, static_folder="static", static_url_path="/static")

# Session signing key: taken from the environment, or a fresh random key that is
# generated per process and never logged.
app.secret_key = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("BANKISM_ENV") == "production",
)

# A phone number is 10 to 15 digits with an optional leading plus sign.
PHONE_PATTERN = re.compile(r"^\+?\d{10,15}$")
# An IFSC code is four letters, a zero, then six alphanumeric characters.
IFSC_PATTERN = re.compile(r"^[A-Za-z]{4}0[A-Za-z0-9]{6}$")
GOOGLE_ISSUERS = ("accounts.google.com", "https://accounts.google.com")

# The fixed demonstration code that is always accepted by the phone flow.
DEMO_CODE = "123456"
# Lifetime and lock-out settings for generated demonstration codes.
CODE_TTL_SECONDS = 300
MAX_CODE_ATTEMPTS = 5


def _now_iso():
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _current_user_id():
    """Return the signed-in user id stored in the session, or None."""
    user_id = session.get("user_id")
    return user_id if isinstance(user_id, int) else None


@app.route("/", methods=["GET"])
def landing_page():
    """Serve the static landing page."""
    return send_from_directory(app.static_folder, "landing.html")


@app.route("/check", methods=["GET"])
def check_page():
    """Serve the firewall tester page."""
    return send_from_directory(app.static_folder, "check.html")


@app.route("/profile", methods=["GET"])
def profile_page():
    """Serve the profile and privacy controls page."""
    return send_from_directory(app.static_folder, "profile.html")


@app.route("/privacy", methods=["GET"])
def privacy_page():
    """Serve the plain-language privacy notice."""
    return send_from_directory(app.static_folder, "privacy.html")


def _verify_google_token(credential: str):
    """Verify a Google ID token via the tokeninfo endpoint and return its claims.

    Returns the claims dictionary on success, or None if the token is missing,
    fails verification, or is expired. Never raises.
    """
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    if not client_id:
        return None

    url = "https://oauth2.googleapis.com/tokeninfo?id_token=" + urllib.parse.quote(
        credential, safe=""
    )
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            claims = json.loads(response.read().decode("utf-8"))
    except Exception:
        return None

    if not isinstance(claims, dict):
        return None
    if claims.get("aud") != client_id:
        return None
    if claims.get("iss") not in GOOGLE_ISSUERS:
        return None
    try:
        expires_at = int(claims.get("exp", 0))
    except (TypeError, ValueError):
        return None
    if expires_at < time.time():
        return None
    return claims


@app.route("/config", methods=["GET"])
def public_config():
    """Return public client-side configuration (never any secret)."""
    return jsonify({"google_client_id": os.getenv("GOOGLE_CLIENT_ID") or None}), 200


# ---------------------------------------------------------------------------
# Sign-in and account routes.
#
# NOTE: These routes are not linked from the user interface. The pages no
# longer expose sign-in, sign-out, export, or delete controls. The routes and
# the database code are kept intact for reference and for direct API use.
# ---------------------------------------------------------------------------


@app.route("/auth/session", methods=["GET"])
def auth_session():
    """Report the current sign-in state from the session cookie."""
    if not _current_user_id():
        return jsonify({"signed_in": False}), 200
    method = session.get("method")
    if method == "phone-demo":
        method = "phone"
    return jsonify({"signed_in": True, "name": session.get("name"), "method": method}), 200


@app.route("/auth/google", methods=["POST"])
def auth_google():
    """Sign in with a Google ID token, creating the account on first use."""
    data = request.get_json(silent=True)
    data = data if isinstance(data, dict) else {}
    credential = data.get("credential")
    accept_privacy = bool(data.get("accept_privacy"))

    claims = None
    if isinstance(credential, str) and credential:
        try:
            claims = _verify_google_token(credential)
        except Exception:
            claims = None

    if not claims:
        return jsonify({"error": "Google sign-in could not be verified."}), 401

    subject = claims.get("sub") or claims.get("email") or claims.get("name")
    if not subject:
        return jsonify({"error": "Google sign-in could not be verified."}), 401

    name = claims.get("name") or claims.get("email") or "Google user"
    email = claims.get("email")
    accepted_at = _now_iso() if accept_privacy else None
    try:
        user = db.find_or_create_google_user(subject, name, email, accepted_at)
    except Exception:
        return jsonify({"error": "Could not complete sign-in."}), 500

    session.clear()
    session["user_id"] = user["id"]
    session["name"] = user["name"] or name
    session["method"] = "google"
    return jsonify({"signed_in": True, "name": session["name"], "method": "google"}), 200


@app.route("/auth/phone/send", methods=["POST"])
def auth_phone_send():
    """Create a short-lived demonstration code for the entered phone number."""
    data = request.get_json(silent=True)
    phone = data.get("phone") if isinstance(data, dict) else None
    if not isinstance(phone, str) or not PHONE_PATTERN.match(phone.strip()):
        return jsonify({"error": "Enter a valid phone number."}), 400

    normalized = phone.strip()
    code = "{:06d}".format(secrets.randbelow(1000000))
    try:
        db.store_login_code(normalized, code, ttl_seconds=CODE_TTL_SECONDS)
    except Exception:
        return jsonify({"error": "Could not start the verification flow."}), 500

    payload = {"sent": True}
    if os.getenv("BANKISM_ENV") != "production":
        payload["demo_code"] = code
    return jsonify(payload), 200


@app.route("/auth/phone/verify", methods=["POST"])
def auth_phone_verify():
    """Verify a demonstration code and sign in, creating the account on first use."""
    data = request.get_json(silent=True)
    data = data if isinstance(data, dict) else {}
    phone = data.get("phone")
    code = data.get("code")
    accept_privacy = bool(data.get("accept_privacy"))

    if not isinstance(phone, str) or not PHONE_PATTERN.match(phone.strip()):
        return jsonify({"error": "Enter a valid phone number."}), 400
    if not isinstance(code, str) or not code.strip():
        return jsonify({"error": "Enter the verification code."}), 400

    normalized = phone.strip()
    code = code.strip()

    try:
        record = db.get_login_code(normalized)
    except Exception:
        record = None

    verified = False
    if code == DEMO_CODE:
        verified = True
    elif record is not None:
        if record["expires_at"] >= time.time() and int(record["attempts"]) < MAX_CODE_ATTEMPTS:
            if hmac.compare_digest(record["code_hash"], db.hash_code(code)):
                verified = True

    if not verified:
        if record is not None and code != DEMO_CODE:
            try:
                db.increment_login_attempts(normalized)
            except Exception:
                pass
        return jsonify({"error": "Invalid verification code."}), 401

    try:
        db.delete_login_code(normalized)
    except Exception:
        pass

    accepted_at = _now_iso() if accept_privacy else None
    try:
        user = db.find_or_create_phone_user(normalized, accepted_at)
    except Exception:
        return jsonify({"error": "Could not complete sign-in."}), 500

    session.clear()
    session["user_id"] = user["id"]
    session["name"] = user["name"] or normalized
    session["method"] = "phone"
    return jsonify({"signed_in": True, "name": session["name"], "method": "phone"}), 200


@app.route("/auth/logout", methods=["POST"])
def auth_logout():
    """Clear the current session."""
    session.clear()
    return jsonify({"signed_in": False}), 200


@app.route("/api/account/export", methods=["GET"])
def account_export():
    """Return the signed-in user's profile and bank details as JSON."""
    user_id = _current_user_id()
    if not user_id:
        return jsonify({"error": "Sign in required."}), 401

    try:
        user = db.get_user(user_id)
        bank_details = db.get_bank_details(user_id)
    except Exception:
        return jsonify({"error": "Could not export your data."}), 500

    if user is None:
        session.clear()
        return jsonify({"error": "Sign in required."}), 401

    return (
        jsonify(
            {
                "exported_at": _now_iso(),
                "profile": {
                    "name": user.get("name"),
                    "email": user.get("email"),
                    "phone": user.get("phone"),
                    "auth_method": user.get("auth_method"),
                    "created_at": user.get("created_at"),
                    "accepted_privacy_at": user.get("accepted_privacy_at"),
                },
                "bank_details": bank_details,
            }
        ),
        200,
    )


@app.route("/api/account", methods=["DELETE"])
def account_delete():
    """Delete the signed-in account and all related rows."""
    user_id = _current_user_id()
    if not user_id:
        return jsonify({"error": "Sign in required."}), 401

    try:
        db.delete_user(user_id)
    except Exception:
        return jsonify({"error": "Could not delete your account."}), 500

    session.clear()
    return jsonify({"deleted": True}), 200


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint returning firewall status."""
    return jsonify({"status": "ok"}), 200


@app.route("/evaluate", methods=["POST"])
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
        # Never return internal stack traces to the client
        return jsonify({"error": "Internal security firewall error during evaluation"}), 500


if __name__ == "__main__":
    db.init_db()
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
