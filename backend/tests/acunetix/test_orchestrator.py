"""Unit tests for scan state machine."""

from app.engines.acunetix.types import AcunetixScanStatus
from app.engines.acunetix.orchestrator.state_machine import is_valid_transition


def test_state_transitions():
    assert is_valid_transition(AcunetixScanStatus.QUEUED, AcunetixScanStatus.STARTING) is True
    assert is_valid_transition(AcunetixScanStatus.SCANNING, AcunetixScanStatus.COMPLETED) is False
    assert is_valid_transition(AcunetixScanStatus.SCANNING, AcunetixScanStatus.PROCESSING) is True
    assert is_valid_transition(AcunetixScanStatus.COMPLETED, AcunetixScanStatus.SCANNING) is False
