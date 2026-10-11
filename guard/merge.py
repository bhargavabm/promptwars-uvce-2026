"""Deterministic decision and merge logic for the Bankism security firewall.

Merges deterministic rule matches and AI classifier results into a final,
strictly-enforced verdict according to fail-closed banking security policies.
"""

import os
from typing import List, Optional

from guard.classifier import ClassifierResult
from guard.rules import RuleMatch
from guard.schema import RiskLevel, ThreatCategory, Verdict

DEFAULT_MAX_TRANSFER_LIMIT = 50000.0


def map_threat_category(category: str) -> ThreatCategory:
    """Normalize any threat string to a valid ThreatCategory schema literal."""
    valid_categories = {
        "none",
        "direct_injection",
        "jailbreak_roleplay",
        "policy_override",
        "hidden_payload_in_memo",
        "token_obfuscation",
        "unauthorized_transfer",
        "data_exfiltration",
        "ambiguous_intent",
    }
    cleaned = category.lower().strip()
    if cleaned in valid_categories:
        return cleaned  # type: ignore

    if "jailbreak" in cleaned or "roleplay" in cleaned or "dan" in cleaned:
        return "jailbreak_roleplay"
    if "override" in cleaned or "ignore" in cleaned:
        return "policy_override"
    if "memo" in cleaned:
        return "hidden_payload_in_memo"
    if "injection" in cleaned:
        return "direct_injection"
    if "exfiltration" in cleaned or "leak" in cleaned or "dump" in cleaned:
        return "data_exfiltration"
    if "transfer" in cleaned or "drain" in cleaned or "empty" in cleaned:
        return "unauthorized_transfer"
    if "obfuscation" in cleaned:
        return "token_obfuscation"
    return "ambiguous_intent"


def merge_decision(
    rule_matches: List[RuleMatch],
    classifier_result: ClassifierResult,
    transformations: Optional[List[str]] = None,
    max_transfer_limit: Optional[float] = None,
) -> Verdict:
    """Evaluate deterministic rules and classifier results to produce final verdict."""
    limit = max_transfer_limit
    if limit is None:
        try:
            limit = float(os.getenv("MAX_TRANSFER_LIMIT", str(DEFAULT_MAX_TRANSFER_LIMIT)))
        except ValueError:
            limit = DEFAULT_MAX_TRANSFER_LIMIT

    transforms = transformations or []

    # 1. Deterministic Rule Hits (Highest Priority - Rules are final)
    if rule_matches:
        rule_ids = list(dict.fromkeys(r.rule_id for r in rule_matches))

        # Check for R06 payment memo instruction first for precise rationale
        r06_match = next((r for r in rule_matches if r.rule_id == "R06"), None)
        r02_match = next((r for r in rule_matches if r.rule_id == "R02"), None)
        r01_match = next((r for r in rule_matches if r.rule_id == "R01"), None)
        r04_match = next((r for r in rule_matches if r.rule_id == "R04"), None)
        r03_match = next((r for r in rule_matches if r.rule_id == "R03"), None)
        r05_match = next((r for r in rule_matches if r.rule_id == "R05"), None)

        if r06_match:
            return Verdict(
                verdict="blocked",
                risk_level="high",
                threat_category="hidden_payload_in_memo",
                intent="unknown",
                rationale="Payment memo contains unauthorized instructions aimed at the system.",
                triggered_rules=rule_ids,
            )
        elif r02_match:
            return Verdict(
                verdict="blocked",
                risk_level="critical",
                threat_category="jailbreak_roleplay",
                intent="unknown",
                rationale="Roleplay jailbreak attempt detected.",
                triggered_rules=rule_ids,
            )
        elif r01_match:
            category: ThreatCategory = "policy_override"
            # If zero-width obfuscation was stripped, token obfuscation was also used
            if "strip_zero_width" in transforms:
                rationale = "Policy override attempt detected with token obfuscation."
            else:
                rationale = "Direct instruction or policy override attempt detected."
            return Verdict(
                verdict="blocked",
                risk_level="critical",
                threat_category=category,
                intent="unknown",
                rationale=rationale,
                triggered_rules=rule_ids,
            )
        elif r04_match:
            return Verdict(
                verdict="blocked",
                risk_level="critical",
                threat_category="data_exfiltration",
                intent="unknown",
                rationale="Data exfiltration attempt targeting system internals or secrets.",
                triggered_rules=rule_ids,
            )
        elif r03_match:
            return Verdict(
                verdict="blocked",
                risk_level="critical",
                threat_category="direct_injection",
                intent="unknown",
                rationale="System prompt manipulation or unauthorized directive detected.",
                triggered_rules=rule_ids,
            )
        elif r05_match:
            return Verdict(
                verdict="blocked",
                risk_level="high",
                threat_category="unauthorized_transfer",
                intent="unknown",
                rationale="High-risk mass transfer or account drain request.",
                triggered_rules=rule_ids,
            )
        else:
            primary = rule_matches[0]
            return Verdict(
                verdict="blocked",
                risk_level="high",
                threat_category=map_threat_category(primary.threat_category),
                intent="unknown",
                rationale=f"Security policy violation detected: {primary.rule_name}.",
                triggered_rules=rule_ids,
            )

    # 2. Classifier Failure (Fail-Closed)
    if classifier_result.failed:
        return Verdict(
            verdict="blocked",
            risk_level="high",
            threat_category="ambiguous_intent",
            intent="unknown",
            rationale="AI classifier failed to safely evaluate request; failing closed.",
            triggered_rules=[],
        )

    # 3. Classifier Suspected Threats
    if classifier_result.suspected_threats:
        threat_cat = map_threat_category(classifier_result.suspected_threats[0])
        return Verdict(
            verdict="blocked",
            risk_level="high",
            threat_category=threat_cat,
            intent="unknown",
            rationale=f"AI classifier detected security threat: {', '.join(classifier_result.suspected_threats)}.",
            triggered_rules=[],
        )

    # 4. Intent Whitelisting: Only balance_inquiry and p2p_transfer allowed
    if classifier_result.intent not in ("balance_inquiry", "p2p_transfer"):
        return Verdict(
            verdict="blocked",
            risk_level="medium",
            threat_category="ambiguous_intent",
            intent="unknown",
            rationale="Ambiguous or unsupported banking intent.",
            triggered_rules=[],
        )

    # 5. P2P Transfer Parameter Validation
    if classifier_result.intent == "p2p_transfer":
        amount = classifier_result.amount
        recipient = classifier_result.recipient

        # Recipient validation: must be specified and not ambiguous placeholder
        ambiguous_recipients = {"the usual account", "usual account", "someone", "anyone"}
        if not recipient or recipient.lower().strip() in ambiguous_recipients:
            return Verdict(
                verdict="blocked",
                risk_level="medium",
                threat_category="ambiguous_intent",
                intent="unknown",
                rationale="Peer-to-peer transfer requires a specific, unambiguous recipient.",
                triggered_rules=[],
            )

        # Amount validation: must be positive numeric and under limit
        if amount is None or amount <= 0:
            return Verdict(
                verdict="blocked",
                risk_level="medium",
                threat_category="ambiguous_intent",
                intent="unknown",
                rationale="Peer-to-peer transfer requires a positive numeric amount.",
                triggered_rules=[],
            )

        if amount > limit:
            return Verdict(
                verdict="blocked",
                risk_level="high",
                threat_category="ambiguous_intent",
                intent="unknown",
                rationale=f"Transfer amount {amount} exceeds the allowed limit of {limit} INR.",
                triggered_rules=[],
            )

        return Verdict(
            verdict="approved",
            risk_level="low",
            threat_category="none",
            intent="p2p_transfer",
            rationale=f"Benign peer-to-peer transfer of {amount} to {recipient} approved.",
            triggered_rules=[],
        )

    # 6. Benign Balance Inquiry
    if classifier_result.intent == "balance_inquiry":
        return Verdict(
            verdict="approved",
            risk_level="low",
            threat_category="none",
            intent="balance_inquiry",
            rationale="Benign balance inquiry approved.",
            triggered_rules=[],
        )

    # Fail closed fallback
    return Verdict(
        verdict="blocked",
        risk_level="high",
        threat_category="ambiguous_intent",
        intent="unknown",
        rationale="Request could not be verified; failing closed.",
        triggered_rules=[],
    )
