"""Deterministic rule-based pattern matching for the Bankism firewall.

Implements rules R01 through R06 to detect prompt overrides, roleplay
jailbreaks, system-prompt injections, exfiltration attempts, mass drain
transfers, and malicious payment memo instructions.
"""

import re
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class RuleMatch:
    """Represents a single deterministic rule detection match."""
    rule_id: str
    rule_name: str
    matched_text: str
    span: Tuple[int, int]
    threat_category: str


# Regex definitions for deterministic firewall rules
RULE_DEFINITIONS = [
    {
        "id": "R01",
        "name": "direct_override",
        "category": "policy_override",
        "pattern": re.compile(
            r"\b(?:ignore|disregard|override|bypass)\s+(?:all\s+|your\s+|previous\s+|prior\s+)*(?:rules|instructions|policy|policies|guidelines|safeguards|constraints)\b",
            re.IGNORECASE,
        ),
    },
    {
        "id": "R02",
        "name": "roleplay_jailbreak",
        "category": "jailbreak_roleplay",
        "pattern": re.compile(
            r"\b(?:pretend\s+(?:that\s+)?you\s*(?:are|'re)|you\s*(?:are|'re)\s+now|act\s+as|developer\s+mode|dan\s+mode|unrestricted(?:\s+banking\s+bot|\s+bot|\s+mode)?|jailbreak)\b",
            re.IGNORECASE,
        ),
    },
    {
        "id": "R03",
        "name": "system_prompt_manipulation",
        "category": "direct_injection",
        "pattern": re.compile(
            r"(?:\bsystem\s*:|\bsystem\s+prompt\b|\bnew\s+instructions\b|\bapprove\s+all(?:\s+future)?(?:\s+transfers)?\b|\bwithout\s+(?:checking|verification|verifying|authorization|limits)\b)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "R04",
        "name": "data_exfiltration",
        "category": "data_exfiltration",
        "pattern": re.compile(
            r"\b(?:reveal|show|print|dump|leak|display|output|extract)\b.*?\b(?:system\s+prompt|api\s+key|password|passwords|account\s+list|other\s+customers|database|credentials|secret)\b",
            re.IGNORECASE,
        ),
    },
    {
        "id": "R05",
        "name": "transfer_all",
        "category": "unauthorized_transfer",
        "pattern": re.compile(
            r"\b(?:transfer\s+(?:everything|all(?:\s+funds)?|the\s+whole(?:\s+balance|\s+amount)?)|empty\s+(?:the\s+)?account|drain\s+(?:the\s+)?account|send\s+all(?:\s+my)?\s+money)\b",
            re.IGNORECASE,
        ),
    },
]

MEMO_PATTERN = re.compile(r"\b(?:memo|note|for|message)\s*:\s*(.+)$", re.IGNORECASE)
MEMO_IMPERATIVE_PATTERN = re.compile(
    r"(?:\bsystem\s*:|\bapprove(?:\s+all)?\b|\bignore\b|\boverride\b|\bbypass\b|\bexecute\b|\breveal\b|\bshow\b|\btransfer(?:\s+all)?\b|\bdrain\b|\bsend\b|\bdisable\b|\bpretend\b|\bact\s+as\b|\bset\b|\bgrant\b|\bmake\b)",
    re.IGNORECASE,
)


def scan_rules(text: str) -> List[RuleMatch]:
    """Scan the input text against deterministic security rules R01-R06."""
    matches: List[RuleMatch] = []

    # Evaluate rules R01 to R05
    for rule in RULE_DEFINITIONS:
        for match in rule["pattern"].finditer(text):
            matches.append(
                RuleMatch(
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    matched_text=match.group(0),
                    span=match.span(),
                    threat_category=rule["category"],
                )
            )

    # Evaluate rule R06: payment memo containing imperative instructions
    memo_match = MEMO_PATTERN.search(text)
    if memo_match:
        memo_content = memo_match.group(1)
        imp_match = MEMO_IMPERATIVE_PATTERN.search(memo_content)
        if imp_match:
            span_start = memo_match.start(1) + imp_match.start()
            span_end = memo_match.start(1) + imp_match.end()
            matches.append(
                RuleMatch(
                    rule_id="R06",
                    rule_name="memo_instruction",
                    matched_text=memo_match.group(0),
                    span=(span_start, span_end),
                    threat_category="hidden_payload_in_memo",
                )
            )

    return matches
