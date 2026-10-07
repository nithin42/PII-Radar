"""
PII pattern detectors with heuristic and cryptographic validation.

Supports detection of:
- Email addresses (RFC-compliant regex)
- Phone numbers (US/international with strict word boundaries)
- Social Security Numbers (SSN, format + invalid range rejection)
- Credit card numbers (Luhn Mod-10 algorithm validation)
- IP addresses (IPv4 with octet range validation 0-255 & IPv6 hex blocks)
- Dates of Birth (format + column name context heuristics)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class PIIMatch:
    """Represents a single PII detection result."""

    pii_type: str
    value: str
    confidence: float  # 0.0 to 1.0
    column: str
    row_index: int

    def __repr__(self) -> str:
        return (
            f"PIIMatch(type={self.pii_type!r}, column={self.column!r}, "
            f"row={self.row_index}, confidence={self.confidence:.0%})"
        )


# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

_EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    re.IGNORECASE,
)

_PHONE_PATTERN = re.compile(
    r"\b(?:(?:\+?1[\s\-.]?)?(?:\(\d{3}\)|\d{3})[\s\-.]?\d{3}[\s\-.]?\d{4})\b"
)

_SSN_PATTERN = re.compile(
    r"\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0{4})\d{4}\b"
)

_CREDIT_CARD_RAW_PATTERN = re.compile(
    r"\b(?:"
    r"4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{1,4}"
    r"|5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}"
    r"|3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}"
    r"|6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}"
    r"|[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}"
    r")\b"
)

_IPV4_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

_IPV6_PATTERN = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")

_DOB_DATE_PATTERN = re.compile(
    r"\b(?:0?[1-9]|1[0-2])[/\-.](?:0?[1-9]|[12]\d|3[01])[/\-.](?:19|20)\d{2}\b"
)

PATTERNS = {
    "EMAIL": _EMAIL_PATTERN,
    "PHONE": _PHONE_PATTERN,
    "SSN": _SSN_PATTERN,
    "CREDIT_CARD": _CREDIT_CARD_RAW_PATTERN,
    "IP_ADDRESS": _IPV4_PATTERN,
    "IPV6_ADDRESS": _IPV6_PATTERN,
    "DATE_OF_BIRTH": _DOB_DATE_PATTERN,
}

_DOB_COLUMN_KEYWORDS = {
    "dob",
    "birth",
    "birthday",
    "date_of_birth",
    "born",
    "birthdate",
    "bday",
}

_EMAIL_COLUMN_KEYWORDS = {"email", "e_mail", "mail", "email_address"}
_PHONE_COLUMN_KEYWORDS = {
    "phone",
    "telephone",
    "mobile",
    "cell",
    "contact_no",
    "phone_number",
}
_SSN_COLUMN_KEYWORDS = {"ssn", "social_security", "tax_id", "national_id"}
_CARD_COLUMN_KEYWORDS = {"card", "credit_card", "cc_num", "pan", "card_number"}


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def is_luhn_valid(card_number: str) -> bool:
    """
    Validate a credit card number using Luhn Mod-10 algorithm.

    Args:
        card_number: Digits string (hyphens/spaces removed).

    Returns:
        True if the number satisfies Luhn algorithm, False otherwise.
    """
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for idx, digit in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


def is_valid_ipv4(ip_str: str) -> bool:
    """
    Validate IPv4 octet ranges (0-255 per octet) and reject invalid IPs/versions.
    """
    octets = ip_str.split(".")
    if len(octets) != 4:
        return False
    try:
        numbers = [int(o) for o in octets]
        return not any(n < 0 or n > 255 for n in numbers)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Main detection function
# ---------------------------------------------------------------------------


def detect(value: str, column: str, row_index: int) -> List[PIIMatch]:
    """
    Scan a single string value for PII patterns with heuristic validation.

    Args:
        value: The string to scan.
        column: The column name the value came from.
        row_index: The row index in the dataset.

    Returns:
        List of PIIMatch objects, one per detected PII type.
    """
    if not isinstance(value, str) or not value.strip():
        return []

    val_clean = value.strip()
    col_lower = column.lower()
    matches: List[PIIMatch] = []

    # 1. Email Detection
    if _EMAIL_PATTERN.search(val_clean):
        confidence = (
            0.99 if any(k in col_lower for k in _EMAIL_COLUMN_KEYWORDS) else 0.98
        )
        matches.append(
            PIIMatch(
                pii_type="EMAIL",
                value=_redact_value(val_clean, "EMAIL"),
                confidence=confidence,
                column=column,
                row_index=row_index,
            )
        )

    # 2. SSN Detection
    if _SSN_PATTERN.search(val_clean):
        confidence = 0.99 if any(k in col_lower for k in _SSN_COLUMN_KEYWORDS) else 0.97
        matches.append(
            PIIMatch(
                pii_type="SSN",
                value=_redact_value(val_clean, "SSN"),
                confidence=confidence,
                column=column,
                row_index=row_index,
            )
        )

    # 3. Credit Card Detection (Raw regex + Luhn validation)
    cc_match = _CREDIT_CARD_RAW_PATTERN.search(val_clean)
    if cc_match:
        raw_digits = re.sub(r"\D", "", cc_match.group(0))
        if is_luhn_valid(raw_digits):
            confidence = (
                0.99 if any(k in col_lower for k in _CARD_COLUMN_KEYWORDS) else 0.95
            )
            matches.append(
                PIIMatch(
                    pii_type="CREDIT_CARD",
                    value=_redact_value(val_clean, "CREDIT_CARD"),
                    confidence=confidence,
                    column=column,
                    row_index=row_index,
                )
            )

    # 4. Phone Detection
    if _PHONE_PATTERN.search(val_clean):
        confidence = (
            0.95 if any(k in col_lower for k in _PHONE_COLUMN_KEYWORDS) else 0.85
        )
        matches.append(
            PIIMatch(
                pii_type="PHONE",
                value=_redact_value(val_clean, "PHONE"),
                confidence=confidence,
                column=column,
                row_index=row_index,
            )
        )

    # 5. IP Address Detection (IPv4 + IPv6)
    ip_match = _IPV4_PATTERN.search(val_clean)
    if ip_match and is_valid_ipv4(ip_match.group(0)):
        matches.append(
            PIIMatch(
                pii_type="IP_ADDRESS",
                value=_redact_value(val_clean, "IP_ADDRESS"),
                confidence=0.90,
                column=column,
                row_index=row_index,
            )
        )
    elif _IPV6_PATTERN.search(val_clean):
        matches.append(
            PIIMatch(
                pii_type="IP_ADDRESS",
                value=_redact_value(val_clean, "IP_ADDRESS"),
                confidence=0.92,
                column=column,
                row_index=row_index,
            )
        )

    # 6. Date of Birth (Format + Column Keyword Heuristics)
    if _DOB_DATE_PATTERN.search(val_clean):
        is_dob_col = any(k in col_lower for k in _DOB_COLUMN_KEYWORDS)
        if is_dob_col:
            matches.append(
                PIIMatch(
                    pii_type="DATE_OF_BIRTH",
                    value=_redact_value(val_clean, "DATE_OF_BIRTH"),
                    confidence=0.92,
                    column=column,
                    row_index=row_index,
                )
            )

    return matches


def detect_pii_in_text(text: str) -> List[PIIMatch]:
    """
    Scan free-form text or agent response strings for all occurrences of PII.

    Args:
        text: Arbitrary string to scan.

    Returns:
        List of PIIMatch objects for all identified PII entities.
    """
    if not isinstance(text, str) or not text.strip():
        return []

    matches: List[PIIMatch] = []

    # 1. Email Detection
    for m in _EMAIL_PATTERN.finditer(text):
        matches.append(
            PIIMatch(
                pii_type="EMAIL",
                value=m.group(0),
                confidence=0.99,
                column="text",
                row_index=0,
            )
        )

    # 2. SSN Detection
    for m in _SSN_PATTERN.finditer(text):
        matches.append(
            PIIMatch(
                pii_type="SSN",
                value=m.group(0),
                confidence=0.99,
                column="text",
                row_index=0,
            )
        )

    # 3. Credit Card Detection with Luhn validation
    for m in _CREDIT_CARD_RAW_PATTERN.finditer(text):
        raw_digits = re.sub(r"\D", "", m.group(0))
        if is_luhn_valid(raw_digits):
            matches.append(
                PIIMatch(
                    pii_type="CREDIT_CARD",
                    value=m.group(0),
                    confidence=0.99,
                    column="text",
                    row_index=0,
                )
            )

    # 4. Phone Detection
    for m in _PHONE_PATTERN.finditer(text):
        matches.append(
            PIIMatch(
                pii_type="PHONE",
                value=m.group(0),
                confidence=0.95,
                column="text",
                row_index=0,
            )
        )

    # 5. IP Address Detection
    for m in _IPV4_PATTERN.finditer(text):
        if is_valid_ipv4(m.group(0)):
            matches.append(
                PIIMatch(
                    pii_type="IP_ADDRESS",
                    value=m.group(0),
                    confidence=0.92,
                    column="text",
                    row_index=0,
                )
            )

    for m in _IPV6_PATTERN.finditer(text):
        matches.append(
            PIIMatch(
                pii_type="IP_ADDRESS",
                value=m.group(0),
                confidence=0.92,
                column="text",
                row_index=0,
            )
        )

    return matches


def _redact_value(value: str, pii_type: str) -> str:
    """Return a partially redacted version of the value for safe reporting."""
    if len(value) <= 4:
        return "****"
    if pii_type == "EMAIL":
        parts = value.split("@")
        return f"{parts[0][:2]}***@{parts[1]}" if len(parts) == 2 else "****"
    if pii_type in ("CREDIT_CARD", "SSN"):
        return f"{'*' * (len(value) - 4)}{value[-4:]}"
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def scan_and_redact_data(
    content_bytes: bytes,
    file_format: str = "csv",
    pii_types: Optional[List[str]] = None,
) -> Tuple[bytes, int, Dict[str, int]]:
    """
    Scan raw bytes for PII, return redacted bytes, match count, and counts by PII type.

    Args:
        content_bytes: Input raw bytes data.
        file_format: Format string ('csv', 'json', etc.).
        pii_types: Optional list of target PII type names.

    Returns:
        Tuple of (redacted_bytes, total_matches, counts_by_type).
    """
    if not content_bytes:
        return b"", 0, {}

    text_content = content_bytes.decode("utf-8", errors="replace")
    target_patterns = PATTERNS
    if pii_types:
        target_patterns = {k: v for k, v in PATTERNS.items() if k in pii_types}

    total_matches = 0
    counts: Dict[str, int] = {k: 0 for k in target_patterns}

    redacted_text = text_content
    for pii_type, pattern in target_patterns.items():
        found = pattern.findall(redacted_text)
        if found:
            count = len(found)
            counts[pii_type] += count
            total_matches += count
            redacted_text = pattern.sub(f"[REDACTED-{pii_type}]", redacted_text)

    return redacted_text.encode("utf-8"), total_matches, counts
