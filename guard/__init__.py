"""Bankism AI Firewall Package.

Defensive AI firewall screening untrusted user messages before banking actions run.
"""

import hashlib
from collections import OrderedDict
from typing import Optional

from guard import classifier
from guard.classifier import ClassifierResult, classify_message
from guard.merge import merge_decision
from guard.normalize import normalize
from guard.rules import RuleMatch, scan_rules
from guard.schema import Verdict

# Maximum number of classifier results retained in the in-memory cache.
CLASSIFIER_CACHE_LIMIT = 256
_classifier_cache: "OrderedDict[str, ClassifierResult]" = OrderedDict()


def reset_classifier_cache() -> None:
    """Clear the in-memory classifier result cache."""
    _classifier_cache.clear()


def _classify_with_cache(
    normalized_text: str, api_key: Optional[str]
) -> ClassifierResult:
    """Return a cached classifier result, or classify and cache it on a miss."""
    # Key the cache by a one-way hash so raw message text is never retained.
    cache_key = hashlib.sha256(normalized_text.encode("utf-8")).hexdigest()
    cached = _classifier_cache.get(cache_key)
    if cached is not None:
        _classifier_cache.move_to_end(cache_key)
        return cached

    result = classifier.classify_message(message=normalized_text, api_key=api_key)
    if not result.failed:
        _classifier_cache[cache_key] = result
        _classifier_cache.move_to_end(cache_key)
        if len(_classifier_cache) > CLASSIFIER_CACHE_LIMIT:
            _classifier_cache.popitem(last=False)
    return result


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

    # Step 3: AI Classifier screening (memoized by a hash of the normalised text)
    classifier_result = _classify_with_cache(normalized_text, api_key)

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
    "reset_classifier_cache",
]
