"""
Rigorous Unit Tests for Enterprise Secret and API Key Detection.

Compliant with OWASP LLM06 and Cloud Provider Token Signatures.
"""

from __future__ import annotations

from pii_radar.secrets import detect_secrets_in_text


class TestSecretDetectionAccuracy:
    """Positive detection tests against authentic cloud credential patterns."""

    def test_detect_aws_access_key(self) -> None:
        key = "AK" + "IA1234567890ABCDEF"
        text = f"Deploying with AWS credentials: {key} in us-east-1."
        matches = detect_secrets_in_text(text)
        assert len(matches) == 1
        assert matches[0].secret_type == "AWS_ACCESS_KEY"
        assert matches[0].value == key
        assert matches[0].confidence >= 0.95

    def test_detect_aws_session_key(self) -> None:
        key = "AS" + "IA9876543210FEDCBA"
        text = f"Temporary STS token: {key}."
        matches = detect_secrets_in_text(text)
        assert len(matches) == 1
        assert matches[0].secret_type == "AWS_ACCESS_KEY"
        assert matches[0].value == key

    def test_detect_github_personal_access_token(self) -> None:
        token = "gh" + "p_111122223333444455556666777788889999"
        text = f"Git push via token {token}"
        matches = detect_secrets_in_text(text)
        assert len(matches) == 1
        assert matches[0].secret_type == "GITHUB_TOKEN"
        assert matches[0].value == token

    def test_detect_openai_modern_project_key(self) -> None:
        key = "sk-proj-" + "1234567890abcdefghijklmnopqrstuvwxyz" * 2
        text = f"OpenAI key: {key}"
        matches = detect_secrets_in_text(text)
        assert len(matches) == 1
        assert matches[0].secret_type == "OPENAI_API_KEY"
        assert matches[0].value.startswith("sk-proj-")

    def test_detect_anthropic_api_key(self) -> None:
        key = "sk-ant-api03-" + "a" * 85
        text = f"Anthropic Claude connection using {key}."
        matches = detect_secrets_in_text(text)
        assert len(matches) == 1
        assert matches[0].secret_type == "ANTHROPIC_API_KEY"
        assert matches[0].value == key

    def test_detect_stripe_live_key(self) -> None:
        key = "sk_" + "live_51AbcdEFghIjKlMnOpQrStUvWxYz0123456789"
        text = f"Charge customer with {key}"
        matches = detect_secrets_in_text(text)
        assert len(matches) == 1
        assert matches[0].secret_type == "STRIPE_KEY"
        assert matches[0].value == key

    def test_detect_slack_bot_token(self) -> None:
        token = "xox" + "b-123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
        text = f"Slack bot token is {token}"
        matches = detect_secrets_in_text(text)
        assert len(matches) == 1
        assert matches[0].secret_type == "SLACK_TOKEN"
        assert matches[0].value.startswith("xoxb-")

    def test_detect_google_api_key(self) -> None:
        key = "AI" + "zaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q"
        text = f"Google Maps API: {key}"
        matches = detect_secrets_in_text(text)
        assert len(matches) == 1
        assert matches[0].secret_type == "GOOGLE_API_KEY"

    def test_detect_private_key_pem(self) -> None:
        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Y1u...fake...key...material\n"
            "-----END RSA PRIVATE KEY-----"
        )
        text = f"Certificate config:\n{pem}\nHost: prod.example.com"
        matches = detect_secrets_in_text(text)
        assert len(matches) == 1
        assert matches[0].secret_type == "PRIVATE_KEY"
        assert "BEGIN RSA PRIVATE KEY" in matches[0].value

    def test_detect_jwt_token(self) -> None:
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        text = f"Bearer {jwt} in authorization header."
        matches = detect_secrets_in_text(text)
        assert len(matches) == 1
        assert matches[0].secret_type == "JWT_TOKEN"


class TestSecretFalsePositiveImmunity:
    """Negative testing: verify immunity to documentation placeholders."""

    def test_ignore_aws_doc_example(self) -> None:
        text = "Configure your AWS key: AKIAIOSFODNN7EXAMPLE"
        matches = detect_secrets_in_text(text)
        assert len(matches) == 0

    def test_ignore_sha1_and_sha256_hashes(self) -> None:
        text = (
            "Commit hash: 4af5338700d6f835a5efbec57fbd1bf6f92958b6\n"
            "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        matches = detect_secrets_in_text(text)
        assert len(matches) == 0

    def test_ignore_uuids(self) -> None:
        text = "Session ID: 550e8400-e29b-41d4-a716-446655440000"
        matches = detect_secrets_in_text(text)
        assert len(matches) == 0

    def test_ignore_normal_prose_mentioning_keys(self) -> None:
        text = (
            "You should never commit your API key or secret token to GitHub. "
            "Please use environment variables instead."
        )
        matches = detect_secrets_in_text(text)
        assert len(matches) == 0

    def test_empty_and_whitespace(self) -> None:
        assert detect_secrets_in_text("") == []
        assert detect_secrets_in_text("   \n\t  ") == []
