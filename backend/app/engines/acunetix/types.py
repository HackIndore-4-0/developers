"""Acunetix domain types and enumeration definitions."""

from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class AcunetixScanStatus(str, Enum):
    QUEUED = "queued"
    STARTING = "starting"
    SCANNING = "scanning"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"
    PAUSED = "paused"


class AcunetixSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AcunetixCriticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"
