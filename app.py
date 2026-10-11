"""Bankism AI Security Firewall Application.

Flask application exposing REST endpoints to evaluate untrusted natural
language banking messages against defensive firewall policies.
"""

import hmac
import json
import os

from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory

from guard import evaluate_message

# Load environment configuration
load_dotenv()

app = Flask(__name__, static_folder="static", static_url_path="/static")


def api_key_is_valid() -> bool:
    """Validate the X-API-Key header against BANKISM_API_KEY (fail closed)."""
    expected = os.getenv("BANKISM_API_KEY", "")
    provided = request.headers.get("X-API-Key", "")
    if not expected:
        return False
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


@app.route("/", methods=["GET"])
def index():
    """Serve the single-page Bankism web interface."""
    return send_from_directory(app.static_folder, "index.html")


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint returning firewall status."""
    return jsonify({"status": "ok"}), 200


@app.route("/evaluate", methods=["POST"])
def evaluate_request():
    """Screen untrusted user messages and return structured security verdict."""
    if not api_key_is_valid():
        # Never log or echo the supplied key; fail closed when unconfigured.
        return jsonify({"error": "Unauthorized"}), 401

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
