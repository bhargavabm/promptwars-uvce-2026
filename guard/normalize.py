"""Normalization module for the Bankism AI security firewall.

Performs multi-stage sanitization, including NFKC normalization, zero-width
character removal, base64/hex payload decoding, lowercasing, whitespace
collapsing, and selective leetspeak de-obfuscation.
"""

import base64
import re
import unicodedata
from typing import List, Tuple

ZERO_WIDTH_PATTERN = re.compile(r"[\u200B\u200C\u200D\uFEFF\u2060]")

# Minimum alphabetic characters required in decoded output before we treat a
# token as an intentional obfuscated payload rather than an ordinary word.
MIN_DECODED_ALPHA = 5

LEET_MAP = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
}


def strip_zero_width(text: str) -> Tuple[str, bool]:
    """Strip zero-width and invisible control characters."""
    stripped = ZERO_WIDTH_PATTERN.sub("", text)
    return stripped, (stripped != text)


def looks_like_decoded_payload(decoded: str) -> bool:
    """Return True when decoded bytes resemble an intentional text payload.

    Requires printable output plus enough alphabetic characters to distinguish
    a genuine obfuscated payload from an ordinary word that coincidentally
    happens to be a valid base64/hex token. Without this gate, benign words
    such as "blowfish" or "entrancy" would be silently rewritten.
    """
    if len(decoded) < 4:
        return False
    if not all(32 <= ord(c) <= 126 or c in "\n\r\t" for c in decoded):
        return False
    return len(re.findall(r"[A-Za-z]", decoded)) >= MIN_DECODED_ALPHA


def decode_hex_substrings(text: str) -> Tuple[str, bool]:
    """Detect and decode hex substrings that decode to printable text."""
    changed = False

    def replace_hex(match: re.Match) -> str:
        nonlocal changed
        hex_str = match.group(1) or match.group(0)
        if len(hex_str) % 2 != 0 or len(hex_str) < 8:
            return match.group(0)
        try:
            raw = bytes.fromhex(hex_str)
            decoded = raw.decode("utf-8")
            if looks_like_decoded_payload(decoded):
                changed = True
                return decoded
        except Exception:
            pass
        return match.group(0)

    result = re.sub(r"\b(?:0x)?([0-9a-fA-F]{8,})\b", replace_hex, text)
    return result, changed


def decode_base64_substrings(text: str) -> Tuple[str, bool]:
    """Detect and decode base64 substrings that decode to printable text."""
    changed = False

    def replace_b64(match: re.Match) -> str:
        nonlocal changed
        token = match.group(1)
        if len(token) < 4 or len(token) % 4 != 0:
            return match.group(0)
        try:
            raw = base64.b64decode(token, validate=True)
            decoded = raw.decode("utf-8")
            if looks_like_decoded_payload(decoded):
                changed = True
                prefix = match.group(0)[: match.start(1) - match.start(0)]
                suffix = match.group(0)[match.end(1) - match.start(0) :]
                return f"{prefix}{decoded}{suffix}"
        except Exception:
            pass
        return match.group(0)

    pattern = re.compile(
        r"(?:^|(?<=\s)|(?<=:)|(?<=[(\[{]))([A-Za-z0-9+/]{4,}={0,2})(?=$|[\s.,;:!?)}\]])"
    )
    result = pattern.sub(replace_b64, text)
    return result, changed


def map_leetspeak(text: str) -> Tuple[str, bool]:
    """Map common leetspeak substitutions to standard characters in words."""
    original = text

    def replace_word(match: re.Match) -> str:
        word = match.group(0)
        # Preserve pure numbers (e.g. 500, 200, 50000)
        if re.fullmatch(r"\d+", word):
            return word
        new_chars = [LEET_MAP.get(c.lower(), c) for c in word]
        return "".join(new_chars)

    # Handle @ and $ adjacent to or within word boundaries
    transformed = re.sub(r"(@)(?=[a-zA-Z0-9])", "a", text)
    transformed = re.sub(r"(?<=[a-zA-Z])(\$)", "s", transformed)
    transformed = re.sub(r"(\$)(?=[a-zA-Z])", "s", transformed)

    result = re.sub(r"\b[a-zA-Z0-9_]+\b", replace_word, transformed)
    return result, (result != original)


def normalize(text: str) -> Tuple[str, List[str]]:
    """Normalize input text and return the sanitized string with applied transforms."""
    transformations: List[str] = []
    current = text

    # 1. Unicode NFKC normalization
    nfkc_text = unicodedata.normalize("NFKC", current)
    if nfkc_text != current:
        transformations.append("unicode_nfkc")
        current = nfkc_text

    # 2. Strip zero-width characters
    stripped_text, changed_zw = strip_zero_width(current)
    if changed_zw:
        transformations.append("strip_zero_width")
        current = stripped_text

    # 3. Decode base64 substrings (before lowercasing for case-sensitivity)
    b64_decoded, changed_b64 = decode_base64_substrings(current)
    if changed_b64:
        transformations.append("decode_base64")
        current = b64_decoded

    # 4. Decode hex substrings
    hex_decoded, changed_hex = decode_hex_substrings(current)
    if changed_hex:
        transformations.append("decode_hex")
        current = hex_decoded

    # 5. Lowercase
    lowered = current.lower()
    if lowered != current:
        transformations.append("lowercase")
        current = lowered

    # 6. Collapse whitespace
    collapsed = re.sub(r"\s+", " ", current).strip()
    if collapsed != current:
        transformations.append("collapse_whitespace")
        current = collapsed

    # 7. Map common leetspeak
    leet_mapped, changed_leet = map_leetspeak(current)
    if changed_leet:
        transformations.append("map_leetspeak")
        current = leet_mapped

    # Final whitespace trim in case leet/decoding altered spacing
    final_text = re.sub(r"\s+", " ", current).strip()

    return final_text, transformations
