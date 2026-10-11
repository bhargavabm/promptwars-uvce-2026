"""Bankism AI Security Firewall Application.

Flask application exposing REST endpoints to evaluate untrusted natural
language banking messages against defensive firewall policies.
"""

import json
import os
import re
import secrets
import time
import urllib.parse
import urllib.request

from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory, session

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
GOOGLE_ISSUERS = ("accounts.google.com", "https://accounts.google.com")


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
    """Serve the demo profile page."""
    return send_from_directory(app.static_folder, "profile.html")


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


@app.route("/auth/session", methods=["GET"])
def auth_session():
    """Report the current sign-in state from the session cookie."""
    method = session.get("method")
    if not method:
        return jsonify({"signed_in": False}), 200
    reported = "phone" if method == "phone-demo" else method
    return (
        jsonify({"signed_in": True, "name": session.get("name"), "method": reported}),
        200,
    )


@app.route("/auth/google", methods=["POST"])
def auth_google():
    """Sign in using a Google ID token, storing only name, email and method."""
    data = request.get_json(silent=True)
    credential = data.get("credential") if isinstance(data, dict) else None

    claims = None
    if isinstance(credential, str) and credential:
        try:
            claims = _verify_google_token(credential)
        except Exception:
            claims = None

    if not claims:
        return jsonify({"error": "Google sign-in could not be verified."}), 401

    name = claims.get("name") or claims.get("email") or "Google user"
    email = claims.get("email")
    session.clear()
    session["name"] = name
    session["email"] = email
    session["method"] = "google"
    return jsonify({"signed_in": True, "name": name, "method": "google"}), 200


@app.route("/auth/phone/send", methods=["POST"])
def auth_phone_send():
    """Validate a phone number for the demonstration code flow."""
    data = request.get_json(silent=True)
    phone = data.get("phone") if isinstance(data, dict) else None
    if not isinstance(phone, str) or not PHONE_PATTERN.match(phone.strip()):
        return jsonify({"error": "Enter a valid phone number."}), 400
    return jsonify({"sent": True}), 200


@app.route("/auth/phone/verify", methods=["POST"])
def auth_phone_verify():
    """Verify the demonstration code and sign in with the phone number."""
    data = request.get_json(silent=True)
    phone = data.get("phone") if isinstance(data, dict) else None
    code = data.get("code") if isinstance(data, dict) else None

    if not isinstance(phone, str) or not PHONE_PATTERN.match(phone.strip()):
        return jsonify({"error": "Enter a valid phone number."}), 400
    if code != "123456":
        return jsonify({"error": "Invalid verification code."}), 401

    normalized_phone = phone.strip()
    session.clear()
    session["name"] = normalized_phone
    session["method"] = "phone-demo"
    return (
        jsonify({"signed_in": True, "name": normalized_phone, "method": "phone"}),
        200,
    )


@app.route("/auth/logout", methods=["POST"])
def auth_logout():
    """Clear the current session."""
    session.clear()
    return jsonify({"signed_in": False}), 200


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
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
