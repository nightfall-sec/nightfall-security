from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


VALID_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


@dataclass
class SecurityEvent:
    """
    Standardized security event representation.

    This model is intentionally lightweight so it can be used by
    log analysis, detection, correlation, risk scoring, incident
    response, reporting, and AI layers.
    """

    event_type: str
    severity: str
    source_ip: str | None = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not isinstance(self.event_type, str):
            raise TypeError("event_type must be a string")

        if not isinstance(self.severity, str):
            raise TypeError("severity must be a string")

        self.event_type = self.event_type.strip().upper()
        self.severity = self.severity.strip().upper()

        if not self.event_type:
            raise ValueError("event_type cannot be empty")

        if not self.severity:
            raise ValueError("severity cannot be empty")

        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"invalid severity: {self.severity}. "
                f"Expected one of: {sorted(VALID_SEVERITIES)}"
            )

        if self.source_ip is not None:
            if not isinstance(self.source_ip, str):
                raise TypeError("source_ip must be a string or None")

            self.source_ip = self.source_ip.strip()

            if not self.source_ip:
                self.source_ip = None

        if not isinstance(self.timestamp, str):
            raise TypeError("timestamp must be a string")

        if not self.timestamp.strip():
            raise ValueError("timestamp cannot be empty")

        if not isinstance(self.metadata, dict):
            raise TypeError("metadata must be a dictionary")

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the security event to a dictionary.
        """

        return {
            "event_type": self.event_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "timestamp": self.timestamp,
            "metadata": dict(self.metadata),
        }
