"""
NIGHTFALL Detection Contracts (schema_version 1.0).

This module defines the typed, immutable value objects agreed upon in
the "NIGHTFALL Core Architecture v0.2" proposal:

    SourceRef, TimeWindow, EvidenceItem, Detection, Alert, SecurityEvent

These contracts are intentionally decoupled from the existing runtime
pipeline (log_analyzer / threat_detection / alert_engine / event_pipeline
/ security_pipeline / reporting / cli). Nothing in this module is
imported by, or changes the behavior of, any existing public API.

Audit trail
-----------
``SecurityEvent`` in this module models an immutable audit-trail entry
for the detection lifecycle:

    DETECTION_RECORDED -> ALERT_CREATED -> RESPONSE_DECIDED

It is a distinct type from ``nightfall.security_event.SecurityEvent``
(the legacy pipeline event model), which is left untouched. The two
are intentionally not unified in this phase; migration/adapters are
out of scope here.

Detector Registry compatibility
--------------------------------
``Detection`` carries ``detector_name`` and ``detector_version`` fields
(independent from ``schema_version``) so that a future Detector
Registry can identify, version, and look up the detector that produced
a given finding. No registry is implemented in this phase.

Immutability
------------
Every contract in this module is a frozen dataclass. Mutable inputs
(dicts, lists) are copied and, for the ``metadata`` fields, deeply
frozen: nested dicts become read-only ``MappingProxyType`` views and
nested lists become tuples, recursively, so no part of a constructed
contract's metadata can be mutated after the fact -- this matters most
for ``SecurityEvent``, which is meant to serve as an immutable audit
trail, but is applied consistently across all contracts for
predictability.

Serialization
--------------
Every contract exposes ``to_dict`` / ``from_dict`` and ``to_json`` /
``from_json``. ``to_dict`` output is guaranteed JSON-safe: enums are
serialized to their ``.value`` string, nested contracts are recursively
serialized, and metadata is validated at construction time to only
contain JSON-safe primitives (str, int, float, bool, None, and
nested lists/dicts thereof), with NaN/Infinity explicitly rejected.
"""

import json
import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections.abc import Mapping
from enum import Enum
from types import MappingProxyType
from typing import Any


# ---------------------------------------------------------------------------
# Schema version
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """Severity levels shared across detections, alerts, and events."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventKind(str, Enum):
    """The immutable audit-trail stages a SecurityEvent can represent."""

    DETECTION_RECORDED = "DETECTION_RECORDED"
    ALERT_CREATED = "ALERT_CREATED"
    RESPONSE_DECIDED = "RESPONSE_DECIDED"


class ResponseAction(str, Enum):
    """
    Defensive response actions.

    Mirrors the values already produced by
    ``nightfall.incident_response.RESPONSE_ACTIONS``. The values are
    duplicated here (rather than imported) to keep this contract
    module fully decoupled from the existing pipeline, per the
    compatibility constraints of this phase.
    """

    LOG = "LOG"
    FLAG = "FLAG"
    ESCALATE = "ESCALATE"
    ESCALATE_PRIORITY = "ESCALATE_PRIORITY"


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def validate_uuid(value: Any, field_name: str) -> str:
    """
    Validate that ``value`` is a UUID string and return its canonical
    (lower-case, hyphenated) string form.
    """

    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")

    stripped = value.strip()

    if not stripped:
        raise ValueError(f"{field_name} cannot be empty")

    try:
        parsed = uuid.UUID(stripped)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError(f"{field_name} must be a valid UUID") from exc

    return str(parsed)


def validate_rfc3339_utc(value: Any, field_name: str) -> str:
    """
    Validate that ``value`` is an RFC3339 timestamp expressed in UTC
    and return it in a canonical ``...Z`` form.

    A UTC offset is required (either a trailing ``Z`` or ``+00:00``);
    naive timestamps and non-UTC offsets are rejected.
    """

    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")

    stripped = value.strip()

    if not stripped:
        raise ValueError(f"{field_name} cannot be empty")

    normalized = stripped[:-1] + "+00:00" if stripped.endswith("Z") else stripped

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(
            f"{field_name} must be a valid RFC3339 timestamp"
        ) from exc

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")

    if parsed.utcoffset().total_seconds() != 0:
        raise ValueError(
            f"{field_name} must be expressed in UTC (offset +00:00)"
        )

    canonical = parsed.astimezone(timezone.utc).isoformat()

    if canonical.endswith("+00:00"):
        canonical = canonical[: -len("+00:00")] + "Z"

    return canonical


def validate_confidence(value: Any, field_name: str = "confidence") -> float:
    """
    Validate a confidence score.

    Must be a real number (bool is explicitly rejected, since ``bool``
    is a subclass of ``int``), in the inclusive range ``[0.0, 1.0]``,
    and must not be NaN or Infinity.
    """

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{field_name} must be a number")

    numeric = float(value)

    if math.isnan(numeric):
        raise ValueError(f"{field_name} cannot be NaN")

    if math.isinf(numeric):
        raise ValueError(f"{field_name} cannot be infinite")

    if not (0.0 <= numeric <= 1.0):
        raise ValueError(f"{field_name} must be between 0.0 and 1.0")

    return numeric


def _validate_non_empty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")

    stripped = value.strip()

    if not stripped:
        raise ValueError(f"{field_name} cannot be empty")

    return stripped


def _validate_optional_str(value: Any, field_name: str) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string or None")

    stripped = value.strip()

    return stripped or None


def _coerce_enum(value: Any, enum_cls: type[Enum], field_name: str) -> Enum:
    if isinstance(value, enum_cls):
        return value

    if isinstance(value, str):
        try:
            return enum_cls(value.strip().upper())
        except ValueError as exc:
            valid = ", ".join(member.value for member in enum_cls)
            raise ValueError(f"{field_name} must be one of: {valid}") from exc

    raise TypeError(f"{field_name} must be a {enum_cls.__name__} or string")


def _ensure_json_safe(value: Any, path: str) -> None:
    if value is None or isinstance(value, str) or isinstance(value, bool):
        return

    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError(f"{path} contains a non-JSON-safe float")
        return

    if isinstance(value, int):
        return

    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{path} keys must be strings")
            _ensure_json_safe(item, f"{path}.{key}")
        return

    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _ensure_json_safe(item, f"{path}[{index}]")
        return

    raise TypeError(f"{path} must be JSON-safe (got {type(value).__name__})")


def _deep_freeze(value: Any) -> Any:
    """
    Recursively convert a JSON-safe value into an immutable structure.

    ``dict`` -> ``MappingProxyType`` (with every nested value frozen).
    ``list``/``tuple`` -> ``tuple`` (with every nested value frozen).
    Everything else (``str``, ``int``, ``float``, ``bool``, ``None``) is
    already immutable and is returned unchanged.
    """

    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _deep_freeze(item) for key, item in value.items()}
        )

    if isinstance(value, (list, tuple)):
        return tuple(_deep_freeze(item) for item in value)

    return value


def _deep_thaw(value: Any) -> Any:
    """
    Recursively convert a frozen structure (as produced by
    :func:`_deep_freeze`) back into plain, JSON-compatible ``dict``/
    ``list`` structures suitable for ``json.dumps``.
    """

    if isinstance(value, Mapping):
        return {key: _deep_thaw(item) for key, item in value.items()}

    if isinstance(value, tuple):
        return [_deep_thaw(item) for item in value]

    return value


def _freeze_metadata(metadata: Any, field_name: str) -> Mapping[str, Any]:
    if metadata is None:
        metadata = {}

    if not isinstance(metadata, Mapping):
        raise TypeError(f"{field_name} must be a dictionary")

    snapshot = dict(metadata)
    _ensure_json_safe(snapshot, field_name)

    return _deep_freeze(snapshot)


def _validate_schema_version(value: Any) -> str:
    schema_version = _validate_non_empty_str(value, "schema_version")

    if schema_version != SCHEMA_VERSION:
        raise ValueError(
            f"unsupported schema_version: {schema_version!r}. "
            f"Expected: {SCHEMA_VERSION!r}"
        )

    return schema_version


def _default_uuid() -> str:
    return str(uuid.uuid4())


def _default_timestamp() -> str:
    return validate_rfc3339_utc(
        datetime.now(timezone.utc).isoformat(), "timestamp"
    )


# ---------------------------------------------------------------------------
# SourceRef
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceRef:
    """
    A reference to the origin of a detection or a piece of evidence.

    At least one of ``ip``, ``host``, or ``identifier`` must be
    supplied so a SourceRef always points at something concrete.
    """

    ip: str | None = None
    host: str | None = None
    identifier: str | None = None
    description: str | None = None

    def __post_init__(self) -> None:
        ip = _validate_optional_str(self.ip, "ip")
        host = _validate_optional_str(self.host, "host")
        identifier = _validate_optional_str(self.identifier, "identifier")
        description = _validate_optional_str(self.description, "description")

        if not any([ip, host, identifier]):
            raise ValueError(
                "SourceRef requires at least one of: ip, host, identifier"
            )

        object.__setattr__(self, "ip", ip)
        object.__setattr__(self, "host", host)
        object.__setattr__(self, "identifier", identifier)
        object.__setattr__(self, "description", description)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "host": self.host,
            "identifier": self.identifier,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SourceRef":
        if not isinstance(data, dict):
            raise TypeError("SourceRef data must be a dictionary")

        return cls(
            ip=data.get("ip"),
            host=data.get("host"),
            identifier=data.get("identifier"),
            description=data.get("description"),
        )


# ---------------------------------------------------------------------------
# TimeWindow
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TimeWindow:
    """An inclusive UTC time window, e.g. the span an evidence set covers."""

    start: str
    end: str

    def __post_init__(self) -> None:
        start = validate_rfc3339_utc(self.start, "start")
        end = validate_rfc3339_utc(self.end, "end")

        start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))

        if end_dt < start_dt:
            raise ValueError("end must not be before start")

        object.__setattr__(self, "start", start)
        object.__setattr__(self, "end", end)

    def to_dict(self) -> dict[str, Any]:
        return {"start": self.start, "end": self.end}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TimeWindow":
        if not isinstance(data, dict):
            raise TypeError("TimeWindow data must be a dictionary")

        return cls(start=data.get("start"), end=data.get("end"))


# ---------------------------------------------------------------------------
# EvidenceItem
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceItem:
    """A single piece of evidence backing a Detection."""

    kind: str
    reference: str
    source: SourceRef | None = None
    observed_at: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        kind = _validate_non_empty_str(self.kind, "kind").upper()
        reference = _validate_non_empty_str(self.reference, "reference")

        if self.source is not None and not isinstance(self.source, SourceRef):
            raise TypeError("source must be a SourceRef instance or None")

        observed_at = (
            validate_rfc3339_utc(self.observed_at, "observed_at")
            if self.observed_at is not None
            else None
        )

        metadata = _freeze_metadata(self.metadata, "evidence.metadata")

        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "reference", reference)
        object.__setattr__(self, "observed_at", observed_at)
        object.__setattr__(self, "metadata", metadata)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "reference": self.reference,
            "source": self.source.to_dict() if self.source is not None else None,
            "observed_at": self.observed_at,
            "metadata": _deep_thaw(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidenceItem":
        if not isinstance(data, dict):
            raise TypeError("EvidenceItem data must be a dictionary")

        source_data = data.get("source")

        return cls(
            kind=data.get("kind"),
            reference=data.get("reference"),
            source=SourceRef.from_dict(source_data) if source_data else None,
            observed_at=data.get("observed_at"),
            metadata=data.get("metadata") or {},
        )


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Detection:
    """
    A single, typed detector finding.

    ``detector_name`` and ``detector_version`` identify the detector
    that produced this Detection and are independent of
    ``schema_version`` (the contract's own version). This keeps the
    shape ready for a future Detector Registry that looks detectors
    up by name/version without requiring a contract schema bump.
    """

    detector_name: str
    detector_version: str
    threat_type: str
    severity: Severity
    confidence: float
    source: SourceRef
    detection_id: str = field(default_factory=_default_uuid)
    created_at: str = field(default_factory=_default_timestamp)
    time_window: TimeWindow | None = None
    evidence: tuple[EvidenceItem, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        detection_id = validate_uuid(self.detection_id, "detection_id")
        detector_name = _validate_non_empty_str(
            self.detector_name, "detector_name"
        )
        detector_version = _validate_non_empty_str(
            self.detector_version, "detector_version"
        )
        threat_type = _validate_non_empty_str(
            self.threat_type, "threat_type"
        ).upper()
        severity = _coerce_enum(self.severity, Severity, "severity")
        confidence = validate_confidence(self.confidence)
        created_at = validate_rfc3339_utc(self.created_at, "created_at")

        if not isinstance(self.source, SourceRef):
            raise TypeError("source must be a SourceRef instance")

        if self.time_window is not None and not isinstance(
            self.time_window, TimeWindow
        ):
            raise TypeError("time_window must be a TimeWindow instance or None")

        if not isinstance(self.evidence, (tuple, list)):
            raise TypeError("evidence must be a tuple or list of EvidenceItem")

        evidence = tuple(self.evidence)

        for item in evidence:
            if not isinstance(item, EvidenceItem):
                raise TypeError(
                    "evidence must contain only EvidenceItem instances"
                )

        metadata = _freeze_metadata(self.metadata, "detection.metadata")
        schema_version = _validate_schema_version(self.schema_version)

        object.__setattr__(self, "detection_id", detection_id)
        object.__setattr__(self, "detector_name", detector_name)
        object.__setattr__(self, "detector_version", detector_version)
        object.__setattr__(self, "threat_type", threat_type)
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "metadata", metadata)
        object.__setattr__(self, "schema_version", schema_version)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "detection_id": self.detection_id,
            "detector_name": self.detector_name,
            "detector_version": self.detector_version,
            "threat_type": self.threat_type,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "created_at": self.created_at,
            "source": self.source.to_dict(),
            "time_window": (
                self.time_window.to_dict() if self.time_window is not None else None
            ),
            "evidence": [item.to_dict() for item in self.evidence],
            "metadata": _deep_thaw(self.metadata),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), allow_nan=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Detection":
        if not isinstance(data, dict):
            raise TypeError("Detection data must be a dictionary")

        time_window_data = data.get("time_window")
        evidence_data = data.get("evidence") or []

        kwargs: dict[str, Any] = {
            "detector_name": data.get("detector_name"),
            "detector_version": data.get("detector_version"),
            "threat_type": data.get("threat_type"),
            "severity": data.get("severity"),
            "confidence": data.get("confidence"),
            "source": SourceRef.from_dict(data.get("source") or {}),
            "time_window": (
                TimeWindow.from_dict(time_window_data)
                if time_window_data
                else None
            ),
            "evidence": tuple(
                EvidenceItem.from_dict(item) for item in evidence_data
            ),
            "metadata": data.get("metadata") or {},
        }

        if "detection_id" in data:
            kwargs["detection_id"] = data["detection_id"]

        if "created_at" in data:
            kwargs["created_at"] = data["created_at"]

        if "schema_version" in data:
            kwargs["schema_version"] = data["schema_version"]

        return cls(**kwargs)

    @classmethod
    def from_json(cls, payload: str) -> "Detection":
        return cls.from_dict(json.loads(payload))


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Alert:
    """
    A security alert derived from exactly one Detection.

    ``detection_id`` links the alert back to the Detection that
    produced it, forming the first edge of the
    Detection -> Alert -> SecurityEvent relationship.
    """

    detection_id: str
    severity: Severity
    description: str
    alert_id: str = field(default_factory=_default_uuid)
    created_at: str = field(default_factory=_default_timestamp)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        alert_id = validate_uuid(self.alert_id, "alert_id")
        detection_id = validate_uuid(self.detection_id, "detection_id")
        severity = _coerce_enum(self.severity, Severity, "severity")
        description = _validate_non_empty_str(self.description, "description")
        created_at = validate_rfc3339_utc(self.created_at, "created_at")
        metadata = _freeze_metadata(self.metadata, "alert.metadata")
        schema_version = _validate_schema_version(self.schema_version)

        object.__setattr__(self, "alert_id", alert_id)
        object.__setattr__(self, "detection_id", detection_id)
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "description", description)
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "metadata", metadata)
        object.__setattr__(self, "schema_version", schema_version)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "alert_id": self.alert_id,
            "detection_id": self.detection_id,
            "severity": self.severity.value,
            "description": self.description,
            "created_at": self.created_at,
            "metadata": _deep_thaw(self.metadata),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), allow_nan=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Alert":
        if not isinstance(data, dict):
            raise TypeError("Alert data must be a dictionary")

        kwargs: dict[str, Any] = {
            "detection_id": data.get("detection_id"),
            "severity": data.get("severity"),
            "description": data.get("description"),
            "metadata": data.get("metadata") or {},
        }

        if "alert_id" in data:
            kwargs["alert_id"] = data["alert_id"]

        if "created_at" in data:
            kwargs["created_at"] = data["created_at"]

        if "schema_version" in data:
            kwargs["schema_version"] = data["schema_version"]

        return cls(**kwargs)

    @classmethod
    def from_json(cls, payload: str) -> "Alert":
        return cls.from_dict(json.loads(payload))


# ---------------------------------------------------------------------------
# SecurityEvent (immutable audit trail)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SecurityEvent:
    """
    An immutable audit-trail entry for the detection lifecycle:

        DETECTION_RECORDED -> ALERT_CREATED -> RESPONSE_DECIDED

    Validation is applied per ``event_kind``:

    - ``DETECTION_RECORDED`` requires ``detection_id``, must not
      reference ``alert_id`` (no alert exists yet at this stage), and
      must not carry a ``response_action``.
    - ``ALERT_CREATED`` requires both ``detection_id`` and
      ``alert_id``, recording that an alert was derived from a
      detection, and must not carry a ``response_action``.
    - ``RESPONSE_DECIDED`` requires ``alert_id`` and a typed
      ``response_action`` (a :class:`ResponseAction`).

    This type is distinct from ``nightfall.security_event.SecurityEvent``
    (the existing pipeline event model), which is unmodified.
    """

    event_kind: EventKind
    event_id: str = field(default_factory=_default_uuid)
    occurred_at: str = field(default_factory=_default_timestamp)
    detection_id: str | None = None
    alert_id: str | None = None
    response_action: ResponseAction | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        event_id = validate_uuid(self.event_id, "event_id")
        event_kind = _coerce_enum(self.event_kind, EventKind, "event_kind")
        occurred_at = validate_rfc3339_utc(self.occurred_at, "occurred_at")

        detection_id = (
            validate_uuid(self.detection_id, "detection_id")
            if self.detection_id is not None
            else None
        )
        alert_id = (
            validate_uuid(self.alert_id, "alert_id")
            if self.alert_id is not None
            else None
        )
        response_action = (
            _coerce_enum(self.response_action, ResponseAction, "response_action")
            if self.response_action is not None
            else None
        )

        metadata = _freeze_metadata(self.metadata, "event.metadata")
        schema_version = _validate_schema_version(self.schema_version)

        self._validate_for_kind(event_kind, detection_id, alert_id, response_action)

        object.__setattr__(self, "event_id", event_id)
        object.__setattr__(self, "event_kind", event_kind)
        object.__setattr__(self, "occurred_at", occurred_at)
        object.__setattr__(self, "detection_id", detection_id)
        object.__setattr__(self, "alert_id", alert_id)
        object.__setattr__(self, "response_action", response_action)
        object.__setattr__(self, "metadata", metadata)
        object.__setattr__(self, "schema_version", schema_version)

    @staticmethod
    def _validate_for_kind(
        event_kind: EventKind,
        detection_id: str | None,
        alert_id: str | None,
        response_action: ResponseAction | None,
    ) -> None:
        if event_kind is EventKind.DETECTION_RECORDED:
            if detection_id is None:
                raise ValueError(
                    "DETECTION_RECORDED events require detection_id"
                )
            if alert_id is not None:
                raise ValueError(
                    "DETECTION_RECORDED events must not reference alert_id"
                )
            if response_action is not None:
                raise ValueError(
                    "DETECTION_RECORDED events must not set response_action"
                )
            return

        if event_kind is EventKind.ALERT_CREATED:
            if detection_id is None:
                raise ValueError("ALERT_CREATED events require detection_id")
            if alert_id is None:
                raise ValueError("ALERT_CREATED events require alert_id")
            if response_action is not None:
                raise ValueError(
                    "ALERT_CREATED events must not set response_action"
                )
            return

        if event_kind is EventKind.RESPONSE_DECIDED:
            if alert_id is None:
                raise ValueError("RESPONSE_DECIDED events require alert_id")
            if response_action is None:
                raise ValueError(
                    "RESPONSE_DECIDED events require response_action"
                )
            return

        raise ValueError(f"unsupported event_kind: {event_kind}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "event_kind": self.event_kind.value,
            "occurred_at": self.occurred_at,
            "detection_id": self.detection_id,
            "alert_id": self.alert_id,
            "response_action": (
                self.response_action.value
                if self.response_action is not None
                else None
            ),
            "metadata": _deep_thaw(self.metadata),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), allow_nan=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityEvent":
        if not isinstance(data, dict):
            raise TypeError("SecurityEvent data must be a dictionary")

        kwargs: dict[str, Any] = {
            "event_kind": data.get("event_kind"),
            "detection_id": data.get("detection_id"),
            "alert_id": data.get("alert_id"),
            "response_action": data.get("response_action"),
            "metadata": data.get("metadata") or {},
        }

        if "event_id" in data:
            kwargs["event_id"] = data["event_id"]

        if "occurred_at" in data:
            kwargs["occurred_at"] = data["occurred_at"]

        if "schema_version" in data:
            kwargs["schema_version"] = data["schema_version"]

        return cls(**kwargs)

    @classmethod
    def from_json(cls, payload: str) -> "SecurityEvent":
        return cls.from_dict(json.loads(payload))


__all__ = [
    "SCHEMA_VERSION",
    "Severity",
    "EventKind",
    "ResponseAction",
    "SourceRef",
    "TimeWindow",
    "EvidenceItem",
    "Detection",
    "Alert",
    "SecurityEvent",
    "validate_uuid",
    "validate_rfc3339_utc",
    "validate_confidence",
]
