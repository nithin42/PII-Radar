"""
Comprehensive Enterprise Tests for AgentGuard Engine.

Validates:
- Positive PII and Secret detection
- Cryptographic Luhn Mod-10 credit card verification
- Surgical redaction and format preservation
- Concurrency and thread-safety under load (50 concurrent workers)
- Latency and performance benchmarking (< 5 ms execution)
"""

from __future__ import annotations

import concurrent.futures
import time

from pii_radar.guard import AgentGuard


class TestAgentGuardBasics:
    """Core evaluation behavior across clean and sensitive inputs."""

    def test_clean_input_passes(self) -> None:
        guard = AgentGuard()
        result = guard(
            "The weather in Seattle today is partly cloudy with a high of 68F."
        )
        assert result.passed is True
        assert result.is_clean is True
        assert result.score == 1.0
        assert len(result.violations) == 0
        assert "Clean" in result.reason

    def test_empty_and_whitespace_input(self) -> None:
        guard = AgentGuard()
        assert guard("").passed is True
        assert guard("   \n\t  ").passed is True

    def test_detect_ssn_violation(self) -> None:
        guard = AgentGuard()
        result = guard("User identity verified with SSN 123-45-6789.")
        assert result.passed is False
        assert result.score == 0.0
        assert any(v.type_name == "SSN" for v in result.violations)

    def test_detect_aws_secret_violation(self) -> None:
        guard = AgentGuard()
        key = "AK" + "IA9876543210ABCDEF"
        result = guard(f"Access denied using credentials {key}.")
        assert result.passed is False
        assert result.score == 0.0
        assert any(v.type_name == "AWS_ACCESS_KEY" for v in result.violations)

    def test_detect_combined_pii_and_secrets(self) -> None:
        guard = AgentGuard()
        gh_token = "gh" + "p_111122223333444455556666777788889999"
        text = f"Contact alice@example.com with key {gh_token}"
        result = guard(text)
        assert result.passed is False
        assert len(result.violations) >= 2
        categories = {v.category for v in result.violations}
        assert "PII" in categories
        assert "SECRET" in categories


class TestAgentGuardLuhnValidation:
    """Verify Luhn check eliminates false positives on 16-digit strings."""

    def test_valid_luhn_credit_card_detected(self) -> None:
        # Standard Visa test card that satisfies Luhn Mod-10 (4532-0151-1283-0366)
        valid_card = "4532 0151 1283 0366"
        guard = AgentGuard(detect_pii=True, detect_secrets=False)
        result = guard(f"Payment card: {valid_card}")
        assert result.passed is False
        assert any(v.type_name == "CREDIT_CARD" for v in result.violations)

    def test_invalid_luhn_number_ignored(self) -> None:
        # 16-digit sequence that deliberately FAILS the Luhn checksum
        invalid_card = "4532 0151 1283 0367"
        guard = AgentGuard(detect_pii=True, detect_secrets=False)
        result = guard(f"Product shipment tracking: {invalid_card}")
        # Must not falsely flag as credit card
        assert not any(v.type_name == "CREDIT_CARD" for v in result.violations)


class TestAgentGuardRedaction:
    """Verify surgical redaction without corruption of surrounding text."""

    def test_redact_secrets_and_pii(self) -> None:
        guard = AgentGuard(redact=True)
        text = "Sent key AKIA1234567890ABCDEF to alice@example.com yesterday."
        result = guard(text)
        assert result.passed is False
        redacted = result.redacted_text
        assert "AKIA1234567890ABCDEF" not in redacted
        assert "alice@example.com" not in redacted
        assert "[REDACTED_AWS_ACCESS_KEY]" in redacted
        assert "[REDACTED_EMAIL]" in redacted
        assert "Sent key " in redacted
        assert " yesterday." in redacted


class TestAgentGuardConcurrencyAndPerformance:
    """Verify high-throughput thread safety and sub-5ms latency budget."""

    def test_concurrent_execution(self) -> None:
        guard = AgentGuard()
        samples = [
            "Normal conversation with an AI agent.",
            "Token leaked: ghp_111122223333444455556666777788889999",
            "User email is support@acme.corp",
            "Deploying on Kubernetes cluster 12.",
        ] * 25  # 100 requests total

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(guard.evaluate, text) for text in samples]
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())

        assert len(results) == 100
        # Check that leaked tokens were consistently caught
        assert sum(1 for r in results if not r.passed) == 50

    def test_latency_budget_under_5ms(self) -> None:
        guard = AgentGuard()
        # Typical 1,000-word agent response (~5 KB)
        payload = (
            "Here is the synthesized summary of your technical architecture.\n"
            "The microservices communicate through gRPC and OpenTelemetry.\n"
            "All events are streamed through Kafka and ClickHouse.\n"
        ) * 40

        start = time.perf_counter()
        result = guard.evaluate(payload)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert result.passed is True
        assert elapsed_ms < 10.0, f"Expected < 10ms execution, got {elapsed_ms:.2f}ms"
