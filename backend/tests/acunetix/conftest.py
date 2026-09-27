"""Pytest fixtures and mock data for Acunetix tests."""

import pytest
from typing import List, Dict, Any


@pytest.fixture
def sample_acunetix_vulns() -> List[Dict[str, Any]]:
    return [
        {
            "vuln_id": "v1",
            "vt_id": "vt_sqli",
            "vt_name": "SQL Injection",
            "severity": 3,
            "confidence": 95,
            "affects_url": "https://api.example.com/v1/users",
        },
        {
            "vuln_id": "v2",
            "vt_id": "vt_xss",
            "vt_name": "Cross-site Scripting",
            "severity": 2,
            "confidence": 90,
            "affects_url": "https://api.example.com/v1/comments",
        },
    ]
