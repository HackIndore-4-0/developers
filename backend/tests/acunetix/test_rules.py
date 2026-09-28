"""Unit tests for rules engine."""

from app.engines.acunetix.rules.suppression import filter_suppressed
from app.engines.acunetix.rules.severity_override import apply_severity_override


def test_suppression():
    findings = [{"name": "CORS Misconfiguration"}, {"name": "SQL Injection"}]
    filtered = filter_suppressed(findings, ["CORS Misconfiguration"])
    assert len(filtered) == 1
    assert filtered[0]["name"] == "SQL Injection"


def test_severity_override():
    f = {"name": "Test", "severity": "medium"}
    overridden = apply_severity_override(f, is_public=True)
    assert overridden["severity"] == "high"
