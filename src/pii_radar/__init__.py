"""
pii-radar: A CLI tool to scan CSV, JSON, and Parquet files for PII.

Detects: EMAIL, PHONE, SSN, CREDIT_CARD, IP_ADDRESS, DATE_OF_BIRTH
Formats: CSV, JSON, Parquet (.parquet, .pq)
Integrations: Azure Blob Storage, Azure Event Hubs
"""

from __future__ import annotations

__version__ = "0.6.0"
__author__ = "Nithin"
__email__ = "kumbam.nithingoud@gmail.com"
__license__ = "MIT"
__url__ = "https://github.com/nithin42/pii-radar"

from pii_radar.guard import AgentGuard, EvaluationResult, Violation
from pii_radar.integrations.azure import AzureBlobStreamRedactor, AzureEventHubHandler

__all__ = [
    "AgentGuard",
    "AzureBlobStreamRedactor",
    "AzureEventHubHandler",
    "EvaluationResult",
    "Violation",
    "__version__",
]
