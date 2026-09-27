"""Unit tests for AcunetixClient."""

import pytest
from app.engines.acunetix.config import AcunetixConfig
from app.engines.acunetix.auth import AcunetixAuthProvider


def test_auth_provider_headers():
    auth = AcunetixAuthProvider("test-key-0123456789")
    headers = auth.get_headers()
    assert headers.get("X-Auth") == "test-key-0123456789"
    assert headers.get("Content-Type") == "application/json"


def test_auth_provider_validation():
    auth_valid = AcunetixAuthProvider("long-enough-secret-key-1234")
    assert auth_valid.validate() is True

    auth_short = AcunetixAuthProvider("short")
    assert auth_short.validate() is False
