"""Data models and schemas for Bankism security firewall verdicts."""

from dataclasses import dataclass, asdict
from typing import Literal, List, Dict, Any

VerdictType = Literal["approved", "blocked"]
RiskLevel = Literal["low", "medium", "high", "critical"]
ThreatCategory = Literal[
    "none",
    "direct_injection",
    "jailbreak_roleplay",
    "policy_override",
    "hidden_payload_in_memo",
    "token_obfuscation",
    "unauthorized_transfer",
    "data_exfiltration",
    "ambiguous_intent",
]
IntentType = Literal["balance_inquiry", "p2p_transfer", "unknown"]


@dataclass
class Verdict:
    """Represents the structured security decision for a banking request."""
    verdict: VerdictType
    risk_level: RiskLevel
    threat_category: ThreatCategory
    intent: IntentType
    rationale: str
    triggered_rules: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert the verdict to a plain dictionary matching the API schema."""
        return asdict(self)
