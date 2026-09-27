"""Unit tests for vulnerability normalizer."""

from app.engines.acunetix.normalizer.cwe_mapper import get_cwe_id
from app.engines.acunetix.normalizer.severity import map_acunetix_severity, compute_cvss_score


def test_cwe_mapping():
    assert get_cwe_id("SQL Injection in parameter id") == 89
    assert get_cwe_id("Reflected Cross-site Scripting") == 79
    assert get_cwe_id("Server-Side Request Forgery") == 918
    assert get_cwe_id("Unrecognized bug name") == 1035


def test_severity_mapping():
    assert map_acunetix_severity(3) == "critical"
    assert map_acunetix_severity(2) == "high"
    assert map_acunetix_severity(1) == "medium"
    assert map_acunetix_severity(0) == "low"
    assert compute_cvss_score("critical") == 9.5
