"""Bankism AI Firewall Package.

Defensive AI firewall screening untrusted user messages before banking actions run.
"""

from typing import Optional

from guard import classifier
from guard.classifier import ClassifierResult, classify_message
from guard.merge import merge_decision
from guard.normalize import normalize
from guard.rules import RuleMatch, scan_rules
from guard.schema import Verdict


def evaluate_message(
    message: str,
    max_transfer_limit: Optional[float] = None,
    api_key: Optional[str] = None,
) -> Verdict:
    """Run the complete Bankism firewall pipeline on an untrusted message."""
    # Step 1: Normalize message
    normalized_text, transformations = normalize(message)

    # Step 2: Deterministic regex rules
    rule_matches = scan_rules(normalized_text)
    if not rule_matches:
        # Also check raw text in case of edge spans
        raw_matches = scan_rules(message)
        if raw_matches:
            rule_matches = raw_matches

    # If rules already hit, deterministic block is final
    if rule_matches:
        dummy_classifier = ClassifierResult(
            intent="unknown",
            amount=None,
            recipient=None,
            suspected_threats=[],
            confidence=0.0,
            failed=False,
        )
        return merge_decision(
            rule_matches=rule_matches,
            classifier_result=dummy_classifier,
            transformations=transformations,
            max_transfer_limit=max_transfer_limit,
        )

    # Step 3: AI Classifier screening
    classifier_result = classifier.classify_message(
        message=normalized_text,
        api_key=api_key,
    )

    # Step 4: Deterministic merge decision
    return merge_decision(
        rule_matches=rule_matches,
        classifier_result=classifier_result,
        transformations=transformations,
        max_transfer_limit=max_transfer_limit,
    )


__all__ = [
    "normalize",
    "scan_rules",
    "RuleMatch",
    "classify_message",
    "ClassifierResult",
    "merge_decision",
    "Verdict",
    "evaluate_message",
]
