"""Bankism AI Security Firewall Application.

Flask application exposing a REST endpoint that screens untrusted natural
language banking messages against defensive firewall policies.
"""

import json
import os
import time
from collections import deque
from typing import Deque, Dict, Tuple

from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request, send_from_directory

from guard import evaluate_message

# Load environment configuration.
load_dotenv()

app = Flask(__name__, static_folder="static", static_url_path="/static")

# Maximum accepted length of an untrusted message, in characters.
MAX_MESSAGE_LENGTH = 1000

# In-memory rate limit for POST /evaluate: at most this many requests per window.
RATE_LIMIT_MAX_REQUESTS = 30
RATE_LIMIT_WINDOW_SECONDS = 60.0
_rate_limit_hits: Dict[str, Deque[float]] = {}

# Content Security Policy for responses. Pages ship same-origin assets only; the
# Google origins are permitted solely for Google identity and web fonts.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' https://accounts.google.com https://apis.google.com; "
    "style-src 'self' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com"
)


def _client_ip() -> str:
    """Return the requesting client's IP address, or 'unknown' when absent."""
    return request.remote_addr or "unknown"


def _is_rate_limited(client_ip: str) -> bool:
    """Record a request and report whether the client is over the rate limit."""
    now = time.time()
    hits = _rate_limit_hits.setdefault(client_ip, deque())
    while hits and now - hits[0] > RATE_LIMIT_WINDOW_SECONDS:
        hits.popleft()
    if len(hits) >= RATE_LIMIT_MAX_REQUESTS:
        return True
    hits.append(now)
    return False


def reset_rate_limits() -> None:
    """Clear the in-memory rate limit store."""
    _rate_limit_hits.clear()


@app.after_request
def _apply_security_headers(response: Response) -> Response:
    """Attach security headers and static asset caching to every response."""
    response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if request.path.startswith("/static/") and request.path.endswith((".css", ".js")):
        response.headers["Cache-Control"] = "public, max-age=3600"
    return response


@app.route("/", methods=["GET"])
def landing_page() -> Response:
    """Serve the landing page."""
    return send_from_directory(app.static_folder, "landing.html")


@app.route("/check", methods=["GET"])
def check_page() -> Response:
    """Serve the firewall tester page."""
    return send_from_directory(app.static_folder, "check.html")


@app.route("/profile", methods=["GET"])
def profile_page() -> Response:
    """Serve the demonstration profile page."""
    return send_from_directory(app.static_folder, "profile.html")


@app.route("/privacy", methods=["GET"])
def privacy_page() -> Response:
    """Serve the plain-language privacy notice."""
    return send_from_directory(app.static_folder, "privacy.html")


@app.route("/health", methods=["GET"])
def health_check() -> Tuple[Response, int]:
    """Report service health."""
    return jsonify({"status": "ok"}), 200


@app.route("/evaluate", methods=["POST"])
def evaluate_request() -> Tuple[Response, int]:
    """Screen an untrusted banking message and return a structured verdict."""
    if _is_rate_limited(_client_ip()):
        return jsonify({"error": "Rate limit exceeded. Try again in a minute."}), 429

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        # Tolerate a valid JSON object sent without Content-Type: application/json.
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

    if len(user_message) > MAX_MESSAGE_LENGTH:
        return (
            jsonify(
                {"error": f"Field 'message' must be {MAX_MESSAGE_LENGTH} characters or fewer"}
            ),
            400,
        )

    try:
        verdict = evaluate_message(user_message)
    except Exception:
        # Never return internal stack traces to the client.
        return jsonify({"error": "Internal security firewall error during evaluation"}), 500

    # [CORE BANKING SERVICE INTEGRATION POINT] Approved requests would be
    # forwarded to the core banking service here; no real API is called.
    return jsonify(verdict.to_dict()), 200


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
