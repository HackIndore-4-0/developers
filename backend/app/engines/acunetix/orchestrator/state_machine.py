"""Acunetix Scan Finite State Machine."""

from typing import Set
from app.engines.acunetix.types import AcunetixScanStatus


VALID_TRANSITIONS = {
    AcunetixScanStatus.QUEUED: {AcunetixScanStatus.STARTING, AcunetixScanStatus.ABORTED},
    AcunetixScanStatus.STARTING: {AcunetixScanStatus.SCANNING, AcunetixScanStatus.FAILED},
    AcunetixScanStatus.SCANNING: {AcunetixScanStatus.PROCESSING, AcunetixScanStatus.PAUSED, AcunetixScanStatus.FAILED, AcunetixScanStatus.ABORTED},
    AcunetixScanStatus.PROCESSING: {AcunetixScanStatus.COMPLETED, AcunetixScanStatus.FAILED},
    AcunetixScanStatus.PAUSED: {AcunetixScanStatus.SCANNING, AcunetixScanStatus.ABORTED},
    AcunetixScanStatus.COMPLETED: set(),
    AcunetixScanStatus.FAILED: set(),
    AcunetixScanStatus.ABORTED: set(),
}


def is_valid_transition(current: AcunetixScanStatus, target: AcunetixScanStatus) -> bool:
    return target in VALID_TRANSITIONS.get(current, set())
