"""Unit tests for report formatters."""

from app.engines.acunetix.reports.sarbanes_oxley import format_sox_report
from app.engines.acunetix.reports.pci_dss import format_pci_report


def test_sox_report_generation(sample_acunetix_vulns):
    rep = format_sox_report("https://target.com", sample_acunetix_vulns)
    assert rep["compliance_standard"] == "Sarbanes-Oxley Act Section 404"
    assert rep["critical_deficiencies"] == 1


def test_pci_report_generation(sample_acunetix_vulns):
    rep = format_pci_report("https://target.com", sample_acunetix_vulns)
    assert rep["compliant"] is False
