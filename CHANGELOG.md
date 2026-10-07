# Changelog

All notable changes to **pii-radar** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/).

## [0.6.0] — 2026-10-07

### Added
- **Universal AgentGuard Engine**: Added framework-agnostic `AgentGuard` (`src/pii_radar/guard.py`) for AI agents, LLM output filtering, and automated evaluation pipelines
- **Enterprise Secret & API Key Detection**: Added `detect_secrets_in_text` (`src/pii_radar/secrets.py`) covering AWS (IAM/STS), OpenAI (legacy & project keys), Anthropic, GitHub PATs, Stripe, Slack, Google Cloud, JWTs, and PEM private key headers
- **Cryptographic PII Enhancements**: Added `detect_pii_in_text` (`src/pii_radar/detectors.py`) for arbitrary text streams and enhanced credit card regex to support formatted sequences with Luhn Mod-10 verification
- **Universal Evaluation Contract**: Added `EvaluationResult.to_dict()` exporting standardized schemas (`result: bool`, `passed: bool`, `score: float`, `reason: str`, `violations: list`) compatible with external evaluation frameworks
- **Test Suites**: Added `test_secrets.py`, `test_guard.py` (concurrency & latency), and `test_eval_contract.py` (79 total unit tests)

## [0.5.0] — 2026-08-05

### Added
- **Azure Blob Storage Stream Redactor**: Added `AzureBlobStreamRedactor` (`src/pii_radar/integrations/azure.py`) for real-time PII scanning and masking of CSV/JSON blobs in Azure Storage containers
- **Azure Event Hubs Redaction Handler**: Added `AzureEventHubHandler` (`src/pii_radar/integrations/azure.py`) for low-latency PII redaction on streaming telemetry event batches
- **Optional Dependency Extras**: Added `pip install pii-radar[azure]` and `pip install pii-radar[all]`
- **Test Suite**: Added `test_azure_integration.py` unit test suite

## [0.4.1] — 2026-07-31

### Added
- **IPv6 Regex Detection**: Added 128-bit IPv6 address pattern matching (`_IPV6_PATTERN`)
- **Optional Parquet Extra**: Made `pyarrow` optional (`pip install pii-radar[parquet]`) for lighter base installs
- **Test Coverage Validation**: Validated `test_negative_cases.py` and IPv6 detection in unit test suite

## [0.4.0] — 2026-07-31

### Added
- **Luhn Mod-10 Algorithm Checksum**: Validates credit card numbers to eliminate 16-digit account/order false positives
- **IPv4 Octet Range Validation**: Verifies 0-255 octet bounds and rejects version strings
- **DOB Column Heuristics**: Contextual matching on column headers (`dob`, `birth`, `birthday`, `bday`)
- **`--sample N` / `-s N` Flag**: Limits row scanning for rapid audit sampling on massive files
- **`tests/test_negative_cases.py`**: Comprehensive false-positive unit test suite
- **`examples/benchmark.py`**: Performance benchmarking script
- **Windows Runner**: Added `windows-latest` to GitHub Actions CI matrix

## [0.3.1] — 2026-07-30

### Added
- PyPI release via OIDC Pending Publisher

## [0.3.0] — 2026-07-30

### Added
- PyPI Trusted Publisher integration via OpenID Connect (OIDC)
- Dynamic Console instantiation for headless CliRunner output compatibility
- Pytest pythonpath options in pyproject.toml

## [0.2.0] — 2026-07-20

### Added
- Parquet file support (`.parquet`, `.pq`) via PyArrow
- `--fail-on-detect` flag for CI/CD pipeline integration
- Confidence scoring displayed per detection in terminal table
- Folder scanning with recursive file discovery (`scan directory/`)
- JSON output mode (`--output json`) for programmatic consumption

### Fixed
- False positive reduction in phone number detection for zip codes
- Encoding errors on Windows for UTF-16 encoded CSV files

### Changed
- Rich terminal output redesigned with panel summary + detailed table
- Improved SSN regex to reject invalid ranges (000-xx, 666-xx)

---

## [0.1.0] — 2025-06-25

### Added
- Initial release of `pii-radar`
- CLI command: `pii-radar scan <file>`
- PII detectors: EMAIL, PHONE, SSN, CREDIT_CARD, IP_ADDRESS, DATE_OF_BIRTH
- CSV and JSON file reader support
- `--output table/json` flag
- `--min-confidence` threshold filtering
- `--report` flag to save matches to CSV
- `--redact` flag to create a sanitized CSV copy
- GitHub Actions CI across Python 3.9–3.12
- Pre-commit hooks: black, flake8, bandit

<!-- Updated Jun 2026 -->

<!-- v0.2.0 finalized -->
