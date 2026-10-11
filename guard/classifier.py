"""AI LLM classifier module using Google GenAI SDK.

Analyzes untrusted user messages using Gemini with strict JSON parsing and
fail-closed error handling.
"""

import json
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Dict, List, Optional
from google import genai
from google.genai import types

DEFAULT_SYSTEM_PROMPT = (
    "You are a banking request classifier. Return JSON only with intent, amount, "
    "recipient, suspected_threats, and confidence."
)


@dataclass
class ClassifierResult:
    """Structured output returned by the AI classifier."""
    intent: str
    amount: Optional[float]
    recipient: Optional[str]
    suspected_threats: List[str] = field(default_factory=list)
    confidence: float = 0.0
    failed: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert the result to a dictionary."""
        return {
            "intent": self.intent,
            "amount": self.amount,
            "recipient": self.recipient,
            "suspected_threats": self.suspected_threats,
            "confidence": self.confidence,
            "failed": self.failed,
            "error": self.error,
        }


@lru_cache(maxsize=8)
def load_system_prompt(prompt_path: Optional[str] = None) -> str:
    """Load the classifier system prompt from file or return default.

    Cached so a prompt file is only read once per path; the default prompt is
    stable for the lifetime of the process.
    """
    if prompt_path and os.path.isfile(prompt_path):
        try:
            with open(prompt_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            pass

    # Standard location in the project tree
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    std_path = os.path.join(base_dir, "prompts", "classifier.txt")
    if os.path.isfile(std_path):
        try:
            with open(std_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            pass

    return DEFAULT_SYSTEM_PROMPT


def parse_classifier_json(raw_text: str) -> ClassifierResult:
    """Strictly parse and validate the JSON response from Gemini."""
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
        cleaned = cleaned.strip()

    data = json.loads(cleaned)
    if not isinstance(data, dict):
        raise ValueError("Classifier output is not a JSON object")

    intent = data.get("intent")
    if intent not in ("balance_inquiry", "p2p_transfer", "unknown"):
        raise ValueError(f"Invalid intent: {intent}")

    raw_amount = data.get("amount")
    amount: Optional[float] = None
    if raw_amount is not None:
        try:
            amount = float(raw_amount)
        except (ValueError, TypeError):
            raise ValueError(f"Invalid amount value: {raw_amount}")

    raw_recipient = data.get("recipient")
    recipient: Optional[str] = None
    if raw_recipient is not None:
        if not isinstance(raw_recipient, str):
            raise ValueError(f"Invalid recipient value: {raw_recipient}")
        recipient = raw_recipient.strip() or None

    suspected_threats = data.get("suspected_threats")
    if suspected_threats is None:
        suspected_threats = []
    elif not isinstance(suspected_threats, list):
        raise ValueError("suspected_threats must be a list")
    else:
        suspected_threats = [str(t) for t in suspected_threats]

    confidence = data.get("confidence")
    if confidence is None:
        confidence = 0.0
    else:
        try:
            confidence = float(confidence)
            if not (0.0 <= confidence <= 1.0):
                raise ValueError("confidence must be between 0.0 and 1.0")
        except (ValueError, TypeError):
            raise ValueError(f"Invalid confidence value: {confidence}")

    return ClassifierResult(
        intent=intent,
        amount=amount,
        recipient=recipient,
        suspected_threats=suspected_threats,
        confidence=confidence,
        failed=False,
    )


def classify_message(
    message: str,
    api_key: Optional[str] = None,
    prompt_path: Optional[str] = None,
    model_name: Optional[str] = None,
) -> ClassifierResult:
    """Screen the message with Gemini and return structured classification."""
    resolved_api_key = api_key or os.getenv("GEMINI_API_KEY")
    if not resolved_api_key:
        return ClassifierResult(
            intent="unknown",
            amount=None,
            recipient=None,
            suspected_threats=["missing_api_key"],
            confidence=0.0,
            failed=True,
            error="GEMINI_API_KEY is not set",
        )

    resolved_model = model_name or os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    system_prompt = load_system_prompt(prompt_path)

    # The client is built once per request; retries reuse it rather than
    # paying client-construction cost again.
    client = genai.Client(
        api_key=resolved_api_key,
        http_options=types.HttpOptions(timeout=15000),
    )

    last_error_name = "Error"
    for attempt in range(2):
        try:
            response = client.models.generate_content(
                model=resolved_model,
                contents=message,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    temperature=0.0,
                    response_mime_type="application/json",
                ),
            )

            if not response or not response.text:
                return ClassifierResult(
                    intent="unknown",
                    amount=None,
                    recipient=None,
                    suspected_threats=["empty_response"],
                    confidence=0.0,
                    failed=True,
                    error="Empty response from Gemini model",
                )

            return parse_classifier_json(response.text)

        except Exception as e:
            # Never log the API key or leak stack traces
            last_error_name = type(e).__name__

    # At most one retry (two attempts total); any timeout or failure is
    # fail-closed and no further retries are made.
    return ClassifierResult(
        intent="unknown",
        amount=None,
        recipient=None,
        suspected_threats=["classifier_error"],
        confidence=0.0,
        failed=True,
        error=f"Classifier call failed: {last_error_name}",
    )
