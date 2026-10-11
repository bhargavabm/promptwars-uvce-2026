"""Bankism AI Security Firewall Application.

Flask application exposing REST endpoints to evaluate untrusted natural
language banking messages against defensive firewall policies.
"""

import os
from dotenv import load_dotenv
from flask import Flask, jsonify, request

from guard import evaluate_message

# Load environment configuration
load_dotenv()

app = Flask(__name__)


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint returning firewall status."""
    return jsonify({"status": "ok"}), 200


@app.route("/evaluate", methods=["POST"])
def evaluate_request():
    """Screen untrusted user messages and return structured security verdict."""
    if not request.is_json:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    data = request.get_json(silent=True)
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
