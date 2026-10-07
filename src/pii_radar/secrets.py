"""
Enterprise Secret and API Key Detection Signatures.

Compliant with:
- OWASP Top 10 for LLMs (LLM06: Sensitive Information Disclosure)
- NIST SP 800-122
- Standard cloud provider secret formats (AWS, OpenAI, Anthropic,
  GitHub, Stripe, Slack, Google)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple


@dataclass(frozen=True)
class SecretMatch:
    """Represents a detected secret or credential."""

    secret_type: str
    value: str
    start_index: int
    end_index: int
    confidence: float
    description: str


# ---------------------------------------------------------------------------
# High-confidence, provider-prefixed compiled regex patterns
# ---------------------------------------------------------------------------

_AWS_ACCESS_KEY_PATTERN = re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b")

_GITHUB_TOKEN_PATTERN = re.compile(
    r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b"
    r"|\bgithub_pat_[A-Za-z0-9_]{82}\b"
)

_OPENAI_API_KEY_PATTERN = re.compile(
    r"\bsk-proj-[A-Za-z0-9_-]{48,160}\b"
    r"|\bsk-[A-Za-z0-9]{20,T3BlbkFJ[A-Za-z0-9]{20,}\b"
    r"|\bsk-(?:live-)?[A-Za-z0-9]{48}\b"
)

_ANTHROPIC_API_KEY_PATTERN = re.compile(
    r"\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{80,120}\b"
)

_STRIPE_KEY_PATTERN = re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}\b")

_SLACK_TOKEN_PATTERN = re.compile(
    r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}\b"
)

_GOOGLE_API_KEY_PATTERN = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")

_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN\s+(?:[A-Za-z0-9_-]+\s+)?(?:PRIVATE\s+)?KEY-----"
    r"[\s\S]*?"
    r"-----END\s+(?:[A-Za-z0-9_-]+\s+)?(?:PRIVATE\s+)?KEY-----",
    re.MULTILINE,
)

_JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)

SECRET_PATTERNS: Dict[str, Tuple[re.Pattern[str], str]] = {
    "AWS_ACCESS_KEY": (_AWS_ACCESS_KEY_PATTERN, "AWS Access Key ID"),
    "GITHUB_TOKEN": (_GITHUB_TOKEN_PATTERN, "GitHub Personal Access Token"),
    "OPENAI_API_KEY": (_OPENAI_API_KEY_PATTERN, "OpenAI API Key"),
    "ANTHROPIC_API_KEY": (_ANTHROPIC_API_KEY_PATTERN, "Anthropic API Key"),
    "STRIPE_KEY": (_STRIPE_KEY_PATTERN, "Stripe API Key"),
    "SLACK_TOKEN": (_SLACK_TOKEN_PATTERN, "Slack OAuth Token"),
    "GOOGLE_API_KEY": (_GOOGLE_API_KEY_PATTERN, "Google Cloud API Key"),
    "PRIVATE_KEY": (_PRIVATE_KEY_PATTERN, "Private Key PEM Block"),
    "JWT_TOKEN": (_JWT_PATTERN, "JSON Web Token (JWT)"),
}

# ---------------------------------------------------------------------------
# Documentation stopwords / placeholder rejection list
# (Prevents false alarms on documentation fixtures and test examples)
# ---------------------------------------------------------------------------

DOCUMENTATION_STOPWORDS: Set[str] = {
    "AKIAIOSFODNN7EXAMPLE",
    "AKIA0123456789EXAMPLE",
    "ASIAIOSFODNN7EXAMPLE",
    "sk-proj-testexamplekey00000000000000000000000000000000000000000000",
}


def is_dummy_or_placeholder(value: str) -> bool:
    """Check if matched token is a documentation placeholder."""
    val_upper = value.upper()
    if val_upper in DOCUMENTATION_STOPWORDS:
        return True
    if "EXAMPLE" in val_upper and len(value) <= 30:
        return True
    return False


def detect_secrets_in_text(
    text: str,
    categories: Optional[List[str]] = None,
) -> List[SecretMatch]:
    """
    Scan text for leaked API keys, tokens, and private keys.

    Args:
        text: String input to scan.
        categories: Optional list of secret types to check. Defaults to all.

    Returns:
        List of SecretMatch records.
    """
    if not text or not text.strip():
        return []

    active_patterns = (
        {k: v for k, v in SECRET_PATTERNS.items() if k in categories}
        if categories
        else SECRET_PATTERNS
    )

    matches: List[SecretMatch] = []
    for secret_type, (pattern, description) in active_patterns.items():
        for match in pattern.finditer(text):
            val = match.group(0)
            if is_dummy_or_placeholder(val):
                continue

            matches.append(
                SecretMatch(
                    secret_type=secret_type,
                    value=val,
                    start_index=match.start(),
                    end_index=match.end(),
                    confidence=0.99,
                    description=description,
                )
            )

    return matches
