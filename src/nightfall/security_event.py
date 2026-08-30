from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class SecurityEvent:
    """
    Standardized security event representation.
    """

    event_type: str
    severity: str
    source_ip: str | None = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.event_type = self.event_type.upper()
        self.severity = self.severity.upper()

        if not self.event_type:
            raise ValueError("event_type cannot be empty")

        if not self.severity:
            raise ValueError("severity cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the security event to a dictionary.
        """

        return {
            "event_type": self.event_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }
