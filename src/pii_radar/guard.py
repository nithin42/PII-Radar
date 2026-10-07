"""
Universal AgentGuard Engine for AI Agents, LLM Output Filtering & Evaluation Pipelines.

Provides framework-agnostic guardrails and evaluation outputs for:
- Future AGI (FunctionEvaluator)
- LangChain / CrewAI / LlamaIndex
- LiteLLM / FastAPI proxy middleware
- Standalone Python LLM applications
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from pii_radar.detectors import detect_pii_in_text, is_luhn_valid
from pii_radar.secrets import detect_secrets_in_text


@dataclass(frozen=True)
class Violation:
    """Detailed record of an identified privacy or security violation."""

    category: str  # "PII" or "SECRET"
    type_name: str  # e.g., "AWS_ACCESS_KEY", "CREDIT_CARD", "SSN"
    value: str  # Matched token value
    start: int
    end: int
    confidence: float
    description: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert violation to a serializable dictionary."""
        return {
            "category": self.category,
            "type": self.type_name,
            "value": self.value,
            "start": self.start,
            "end": self.end,
            "confidence": self.confidence,
            "description": self.description,
        }


@dataclass(frozen=True)
class EvaluationResult:
    """Universal evaluation and guardrail result object."""

    passed: bool
    score: float
    reason: str
    violations: List[Violation] = field(default_factory=list)
    redacted_text: str = ""

    @property
    def is_clean(self) -> bool:
        """Alias for passed."""
        return self.passed

    def to_dict(self) -> Dict[str, Any]:
        """
        Output universal dictionary representation compatible with Future AGI,
        DeepEval, LangChain, and standard agent evaluation harnesses.
        """
        return {
            "result": self.passed,
            "passed": self.passed,
            "score": self.score,
            "reason": self.reason,
            "violations": [v.to_dict() for v in self.violations],
            "redacted_text": self.redacted_text,
        }


class AgentGuard:
    """
    Universal Security & Privacy Guardrail for Autonomous AI Agents and LLMs.

    Validates text against cryptographic PII standards and cloud credential signatures.
    """

    def __init__(
        self,
        detect_pii: bool = True,
        detect_secrets: bool = True,
        pii_categories: Optional[List[str]] = None,
        secret_categories: Optional[List[str]] = None,
        redact: bool = False,
    ) -> None:
        """
        Initialize AgentGuard with configurable policies.

        Args:
            detect_pii: Whether to scan for personal data (SSN, Cards, Emails, Phones).
            detect_secrets: Whether to scan for API keys and cloud credentials.
            pii_categories: Optional filter for specific PII types.
            secret_categories: Optional filter for specific secret types.
            redact: Whether to generate sanitized redacted_text in results.
        """
        self.detect_pii = detect_pii
        self.detect_secrets = detect_secrets
        self.pii_categories = pii_categories
        self.secret_categories = secret_categories
        self.redact = redact

    def __call__(self, text: str) -> EvaluationResult:
        """Callable interface matching Python evaluation harnesses."""
        return self.evaluate(text)

    def evaluate(self, text: str) -> EvaluationResult:
        """
        Evaluate text for PII and leaked credentials.

        Args:
            text: Text string to evaluate.

        Returns:
            EvaluationResult conforming to standard evaluation contracts.
        """
        if not text or not str(text).strip():
            return EvaluationResult(
                passed=True,
                score=1.0,
                reason="Clean: empty or whitespace text",
                violations=[],
                redacted_text=text or "",
            )

        text_str = str(text)
        violations: List[Violation] = []

        # 1. PII Scanning with cryptographic validation
        if self.detect_pii:
            pii_matches = detect_pii_in_text(text_str)
            for m in pii_matches:
                if self.pii_categories and m.pii_type not in self.pii_categories:
                    continue

                # Enforce Luhn verification on credit cards to eliminate false positives
                if m.pii_type == "CREDIT_CARD":
                    digits_only = re.sub(r"\D", "", m.value)
                    if not is_luhn_valid(digits_only):
                        continue

                # Locate index positions
                start = text_str.find(m.value)
                end = start + len(m.value) if start != -1 else -1

                violations.append(
                    Violation(
                        category="PII",
                        type_name=m.pii_type,
                        value=m.value,
                        start=start,
                        end=end,
                        confidence=m.confidence,
                        description=(
                            f"Personally Identifiable Information ({m.pii_type})"
                        ),
                    )
                )

        # 2. Secret & Credential Scanning
        if self.detect_secrets:
            secret_matches = detect_secrets_in_text(
                text_str, categories=self.secret_categories
            )
            for s in secret_matches:
                violations.append(
                    Violation(
                        category="SECRET",
                        type_name=s.secret_type,
                        value=s.value,
                        start=s.start_index,
                        end=s.end_index,
                        confidence=s.confidence,
                        description=s.description,
                    )
                )

        passed = len(violations) == 0
        score = 1.0 if passed else 0.0

        if passed:
            reason = "Clean: no sensitive data or credentials detected"
            redacted = text_str
        else:
            summary = [f"{v.type_name} ({v.category})" for v in violations]
            reason = f"Security violation detected: {', '.join(set(summary))}"
            redacted = (
                self._redact_content(text_str, violations) if self.redact else ""
            )

        return EvaluationResult(
            passed=passed,
            score=score,
            reason=reason,
            violations=violations,
            redacted_text=redacted,
        )

    def _redact_content(self, text: str, violations: List[Violation]) -> str:
        """Surgically mask sensitive substrings while preserving formatting."""
        sorted_violations = sorted(
            [v for v in violations if v.start >= 0],
            key=lambda x: x.start,
            reverse=True,
        )

        redacted = text
        for v in sorted_violations:
            mask = f"[REDACTED_{v.type_name}]"
            start_pos = v.start
            end_pos = v.end
            redacted = redacted[:start_pos] + mask + redacted[end_pos:]

        return redacted
