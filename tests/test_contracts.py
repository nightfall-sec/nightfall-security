import json
import math
from dataclasses import FrozenInstanceError

import pytest

from src.nightfall.contracts import (
    SCHEMA_VERSION,
    Alert,
    Detection,
    EventKind,
    EvidenceItem,
    ResponseAction,
    SecurityEvent,
    Severity,
    SourceRef,
    TimeWindow,
    validate_confidence,
    validate_rfc3339_utc,
    validate_uuid,
)

VALID_UUID = "3b2e5d0a-6c9c-4f8e-9a1e-8f6a7b2c1d40"
OTHER_UUID = "9a7c1b44-2e3d-4a5b-8c6f-1a2b3c4d5e6f"
VALID_TS = "2026-01-01T00:00:00Z"
LATER_TS = "2026-01-01T01:00:00Z"


# ---------------------------------------------------------------------------
# validate_uuid
# ---------------------------------------------------------------------------


def test_validate_uuid_accepts_valid_uuid():
    assert validate_uuid(VALID_UUID, "id") == VALID_UUID


def test_validate_uuid_normalizes_case_and_whitespace():
    assert validate_uuid(f"  {VALID_UUID.upper()}  ", "id") == VALID_UUID


def test_validate_uuid_rejects_non_string():
    with pytest.raises(TypeError):
        validate_uuid(123, "id")


def test_validate_uuid_rejects_empty_string():
    with pytest.raises(ValueError):
        validate_uuid("   ", "id")


def test_validate_uuid_rejects_malformed_uuid():
    with pytest.raises(ValueError):
        validate_uuid("not-a-uuid", "id")


# ---------------------------------------------------------------------------
# validate_rfc3339_utc
# ---------------------------------------------------------------------------


def test_validate_rfc3339_accepts_z_suffix():
    assert validate_rfc3339_utc(VALID_TS, "t") == VALID_TS


def test_validate_rfc3339_accepts_explicit_utc_offset():
    assert validate_rfc3339_utc("2026-01-01T00:00:00+00:00", "t") == VALID_TS


def test_validate_rfc3339_rejects_non_string():
    with pytest.raises(TypeError):
        validate_rfc3339_utc(12345, "t")


def test_validate_rfc3339_rejects_empty_string():
    with pytest.raises(ValueError):
        validate_rfc3339_utc("", "t")


def test_validate_rfc3339_rejects_naive_timestamp():
    with pytest.raises(ValueError):
        validate_rfc3339_utc("2026-01-01T00:00:00", "t")


def test_validate_rfc3339_rejects_non_utc_offset():
    with pytest.raises(ValueError):
        validate_rfc3339_utc("2026-01-01T00:00:00+02:00", "t")


def test_validate_rfc3339_rejects_malformed_timestamp():
    with pytest.raises(ValueError):
        validate_rfc3339_utc("not-a-timestamp", "t")


# ---------------------------------------------------------------------------
# validate_confidence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [0.0, 1.0, 0.5, 1, 0])
def test_validate_confidence_accepts_in_range_values(value):
    result = validate_confidence(value)
    assert result == float(value)


def test_validate_confidence_rejects_below_zero():
    with pytest.raises(ValueError):
        validate_confidence(-0.01)


def test_validate_confidence_rejects_above_one():
    with pytest.raises(ValueError):
        validate_confidence(1.01)


def test_validate_confidence_rejects_nan():
    with pytest.raises(ValueError):
        validate_confidence(math.nan)


def test_validate_confidence_rejects_infinity():
    with pytest.raises(ValueError):
        validate_confidence(math.inf)
    with pytest.raises(ValueError):
        validate_confidence(-math.inf)


def test_validate_confidence_rejects_bool():
    with pytest.raises(TypeError):
        validate_confidence(True)


def test_validate_confidence_rejects_non_number():
    with pytest.raises(TypeError):
        validate_confidence("0.5")


# ---------------------------------------------------------------------------
# SourceRef
# ---------------------------------------------------------------------------


def test_source_ref_requires_at_least_one_field():
    with pytest.raises(ValueError):
        SourceRef()


def test_source_ref_accepts_ip_only():
    ref = SourceRef(ip="10.0.0.1")
    assert ref.ip == "10.0.0.1"
    assert ref.host is None


def test_source_ref_roundtrip():
    ref = SourceRef(ip="10.0.0.1", host="host-a", identifier="id-1")
    restored = SourceRef.from_dict(ref.to_dict())
    assert restored == ref


def test_source_ref_is_frozen():
    ref = SourceRef(ip="10.0.0.1")
    with pytest.raises(FrozenInstanceError):
        ref.ip = "10.0.0.2"


# ---------------------------------------------------------------------------
# TimeWindow
# ---------------------------------------------------------------------------


def test_time_window_valid_range():
    window = TimeWindow(start=VALID_TS, end=LATER_TS)
    assert window.start == VALID_TS
    assert window.end == LATER_TS


def test_time_window_rejects_end_before_start():
    with pytest.raises(ValueError):
        TimeWindow(start=LATER_TS, end=VALID_TS)


def test_time_window_allows_equal_start_and_end():
    window = TimeWindow(start=VALID_TS, end=VALID_TS)
    assert window.start == window.end


def test_time_window_roundtrip():
    window = TimeWindow(start=VALID_TS, end=LATER_TS)
    restored = TimeWindow.from_dict(window.to_dict())
    assert restored == window


# ---------------------------------------------------------------------------
# EvidenceItem
# ---------------------------------------------------------------------------


def test_evidence_item_normalizes_kind_to_uppercase():
    item = EvidenceItem(kind="log_line", reference="ref-1")
    assert item.kind == "LOG_LINE"


def test_evidence_item_rejects_empty_reference():
    with pytest.raises(ValueError):
        EvidenceItem(kind="log_line", reference="")


def test_evidence_item_rejects_non_source_ref():
    with pytest.raises(TypeError):
        EvidenceItem(kind="log_line", reference="ref-1", source="10.0.0.1")


def test_evidence_item_rejects_non_json_safe_metadata():
    with pytest.raises(TypeError):
        EvidenceItem(kind="log_line", reference="ref-1", metadata={"bad": object()})


def test_evidence_item_rejects_nan_metadata():
    with pytest.raises(ValueError):
        EvidenceItem(kind="log_line", reference="ref-1", metadata={"score": math.nan})


def test_evidence_item_roundtrip_with_source():
    item = EvidenceItem(
        kind="log_line",
        reference="ref-1",
        source=SourceRef(ip="10.0.0.1"),
        observed_at=VALID_TS,
        metadata={"line_no": 42},
    )
    restored = EvidenceItem.from_dict(item.to_dict())
    assert restored == item


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def _make_detection(**overrides):
    kwargs = {
        "detector_name": "brute_force_detector",
        "detector_version": "1.0.0",
        "threat_type": "brute_force",
        "severity": Severity.HIGH,
        "confidence": 0.9,
        "source": SourceRef(ip="10.0.0.1"),
    }
    kwargs.update(overrides)
    return Detection(**kwargs)


def test_detection_defaults_are_generated():
    detection = _make_detection()
    normalized = validate_uuid(detection.detection_id, "detection_id")
    assert normalized == detection.detection_id
    assert detection.created_at
    assert detection.schema_version == SCHEMA_VERSION


def test_detection_normalizes_threat_type():
    detection = _make_detection(threat_type="brute_force")
    assert detection.threat_type == "BRUTE_FORCE"


def test_detection_accepts_string_severity():
    detection = _make_detection(severity="high")
    assert detection.severity is Severity.HIGH


def test_detection_rejects_invalid_severity():
    with pytest.raises(ValueError):
        _make_detection(severity="not-a-severity")


def test_detection_rejects_out_of_range_confidence():
    with pytest.raises(ValueError):
        _make_detection(confidence=1.5)


def test_detection_rejects_non_source_ref():
    with pytest.raises(TypeError):
        _make_detection(source="10.0.0.1")


def test_detection_rejects_wrong_time_window_type():
    with pytest.raises(TypeError):
        _make_detection(time_window="not-a-window")


def test_detection_rejects_non_evidence_items():
    with pytest.raises(TypeError):
        _make_detection(evidence=["not-an-evidence-item"])


def test_detection_rejects_wrong_schema_version():
    with pytest.raises(ValueError):
        _make_detection(schema_version="9.9")


def test_detection_is_frozen():
    detection = _make_detection()
    with pytest.raises(FrozenInstanceError):
        detection.confidence = 0.1


def test_detection_metadata_is_read_only():
    detection = _make_detection(metadata={"a": 1})
    with pytest.raises(TypeError):
        detection.metadata["a"] = 2


def test_detection_with_evidence_and_time_window_roundtrip():
    detection = _make_detection(
        time_window=TimeWindow(start=VALID_TS, end=LATER_TS),
        evidence=(
            EvidenceItem(kind="log_line", reference="ref-1"),
            EvidenceItem(kind="log_line", reference="ref-2"),
        ),
        metadata={"attempts": 5},
    )

    restored = Detection.from_dict(detection.to_dict())

    assert restored == detection
    assert restored.evidence[0].reference == "ref-1"
    assert restored.time_window.start == VALID_TS


def test_detection_json_roundtrip():
    detection = _make_detection()
    payload = detection.to_json()
    restored = Detection.from_json(payload)
    assert restored == detection
    assert json.loads(payload)["schema_version"] == SCHEMA_VERSION


def test_detection_to_dict_is_json_safe():
    detection = _make_detection()
    # Should not raise: proves to_dict() output round-trips through
    # the standard json module without special handling.
    json.dumps(detection.to_dict())


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------


def _make_alert(**overrides):
    kwargs = {
        "detection_id": VALID_UUID,
        "severity": Severity.CRITICAL,
        "description": "Brute-force attempt detected from 10.0.0.1",
    }
    kwargs.update(overrides)
    return Alert(**kwargs)


def test_alert_links_to_detection_id():
    alert = _make_alert()
    assert alert.detection_id == VALID_UUID


def test_alert_rejects_invalid_detection_id():
    with pytest.raises(ValueError):
        _make_alert(detection_id="not-a-uuid")


def test_alert_rejects_empty_description():
    with pytest.raises(ValueError):
        _make_alert(description="   ")


def test_alert_is_frozen():
    alert = _make_alert()
    with pytest.raises(FrozenInstanceError):
        alert.description = "changed"


def test_alert_roundtrip():
    alert = _make_alert(metadata={"threshold": 5})
    restored = Alert.from_dict(alert.to_dict())
    assert restored == alert


def test_alert_json_roundtrip():
    alert = _make_alert()
    restored = Alert.from_json(alert.to_json())
    assert restored == alert


# ---------------------------------------------------------------------------
# SecurityEvent
# ---------------------------------------------------------------------------


def test_security_event_detection_recorded_requires_detection_id():
    with pytest.raises(ValueError):
        SecurityEvent(event_kind=EventKind.DETECTION_RECORDED)


def test_security_event_detection_recorded_rejects_alert_id():
    with pytest.raises(ValueError):
        SecurityEvent(
            event_kind=EventKind.DETECTION_RECORDED,
            detection_id=VALID_UUID,
            alert_id=OTHER_UUID,
        )


def test_security_event_detection_recorded_valid():
    event = SecurityEvent(
        event_kind=EventKind.DETECTION_RECORDED,
        detection_id=VALID_UUID,
    )
    assert event.event_kind is EventKind.DETECTION_RECORDED
    assert event.alert_id is None


def test_security_event_alert_created_requires_both_ids():
    with pytest.raises(ValueError):
        SecurityEvent(event_kind=EventKind.ALERT_CREATED, detection_id=VALID_UUID)

    with pytest.raises(ValueError):
        SecurityEvent(event_kind=EventKind.ALERT_CREATED, alert_id=OTHER_UUID)


def test_security_event_alert_created_valid():
    event = SecurityEvent(
        event_kind=EventKind.ALERT_CREATED,
        detection_id=VALID_UUID,
        alert_id=OTHER_UUID,
    )
    assert event.detection_id == VALID_UUID
    assert event.alert_id == OTHER_UUID


def test_security_event_response_decided_requires_alert_id():
    with pytest.raises(ValueError):
        SecurityEvent(
            event_kind=EventKind.RESPONSE_DECIDED,
            response_action=ResponseAction.LOG,
        )


def test_security_event_response_decided_requires_response_action():
    with pytest.raises(ValueError):
        SecurityEvent(event_kind=EventKind.RESPONSE_DECIDED, alert_id=OTHER_UUID)


def test_security_event_response_decided_rejects_invalid_response_action():
    with pytest.raises(ValueError):
        SecurityEvent(
            event_kind=EventKind.RESPONSE_DECIDED,
            alert_id=OTHER_UUID,
            response_action="NOT_A_REAL_ACTION",
        )


def test_security_event_response_decided_valid():
    event = SecurityEvent(
        event_kind=EventKind.RESPONSE_DECIDED,
        alert_id=OTHER_UUID,
        response_action=ResponseAction.ESCALATE,
    )
    assert event.response_action is ResponseAction.ESCALATE
    assert "response" not in event.metadata


def test_security_event_detection_recorded_rejects_response_action():
    with pytest.raises(ValueError):
        SecurityEvent(
            event_kind=EventKind.DETECTION_RECORDED,
            detection_id=VALID_UUID,
            response_action=ResponseAction.LOG,
        )


def test_security_event_alert_created_rejects_response_action():
    with pytest.raises(ValueError):
        SecurityEvent(
            event_kind=EventKind.ALERT_CREATED,
            detection_id=VALID_UUID,
            alert_id=OTHER_UUID,
            response_action=ResponseAction.LOG,
        )


def test_security_event_response_action_serializes_in_to_dict():
    event = SecurityEvent(
        event_kind=EventKind.RESPONSE_DECIDED,
        alert_id=OTHER_UUID,
        response_action=ResponseAction.ESCALATE,
    )
    data = event.to_dict()
    assert data["response_action"] == "ESCALATE"
    assert "response" not in data["metadata"]


def test_security_event_response_action_none_for_non_response_kinds():
    event = SecurityEvent(
        event_kind=EventKind.DETECTION_RECORDED, detection_id=VALID_UUID
    )
    assert event.response_action is None
    assert event.to_dict()["response_action"] is None


def test_security_event_response_action_roundtrip_from_dict():
    event = SecurityEvent(
        event_kind=EventKind.RESPONSE_DECIDED,
        alert_id=OTHER_UUID,
        response_action=ResponseAction.ESCALATE_PRIORITY,
    )
    restored = SecurityEvent.from_dict(event.to_dict())
    assert restored == event
    assert restored.response_action is ResponseAction.ESCALATE_PRIORITY


def test_security_event_is_frozen():
    event = SecurityEvent(
        event_kind=EventKind.DETECTION_RECORDED, detection_id=VALID_UUID
    )
    with pytest.raises(FrozenInstanceError):
        event.detection_id = OTHER_UUID


def test_security_event_unique_ids_by_default():
    event_a = SecurityEvent(
        event_kind=EventKind.DETECTION_RECORDED, detection_id=VALID_UUID
    )
    event_b = SecurityEvent(
        event_kind=EventKind.DETECTION_RECORDED, detection_id=VALID_UUID
    )
    assert event_a.event_id != event_b.event_id


def test_security_event_roundtrip():
    event = SecurityEvent(
        event_kind=EventKind.ALERT_CREATED,
        detection_id=VALID_UUID,
        alert_id=OTHER_UUID,
        metadata={"note": "correlated"},
    )
    restored = SecurityEvent.from_dict(event.to_dict())
    assert restored == event


def test_security_event_json_roundtrip():
    event = SecurityEvent(
        event_kind=EventKind.RESPONSE_DECIDED,
        alert_id=OTHER_UUID,
        response_action=ResponseAction.FLAG,
    )
    restored = SecurityEvent.from_json(event.to_json())
    assert restored == event
    assert restored.response_action is ResponseAction.FLAG


def test_security_event_rejects_unsupported_schema_version():
    with pytest.raises(ValueError):
        SecurityEvent(
            event_kind=EventKind.DETECTION_RECORDED,
            detection_id=VALID_UUID,
            schema_version="0.9",
        )


# ---------------------------------------------------------------------------
# Detection -> Alert -> SecurityEvent relationship
# ---------------------------------------------------------------------------


def test_detection_alert_event_relationship_chain():
    detection = _make_detection()
    alert = Alert(
        detection_id=detection.detection_id,
        severity=Severity.HIGH,
        description="Linked alert",
    )

    recorded = SecurityEvent(
        event_kind=EventKind.DETECTION_RECORDED,
        detection_id=detection.detection_id,
    )
    created = SecurityEvent(
        event_kind=EventKind.ALERT_CREATED,
        detection_id=detection.detection_id,
        alert_id=alert.alert_id,
    )
    decided = SecurityEvent(
        event_kind=EventKind.RESPONSE_DECIDED,
        alert_id=alert.alert_id,
        response_action=ResponseAction.ESCALATE_PRIORITY,
    )

    assert alert.detection_id == detection.detection_id
    assert recorded.detection_id == detection.detection_id
    assert created.detection_id == detection.detection_id
    assert created.alert_id == alert.alert_id
    assert decided.alert_id == alert.alert_id


# ---------------------------------------------------------------------------
# Deep metadata immutability
# ---------------------------------------------------------------------------


def test_detection_metadata_nested_dict_is_read_only():
    detection = _make_detection(
        metadata={"context": {"ip_reputation": "bad", "count": 3}}
    )

    with pytest.raises(TypeError):
        detection.metadata["context"]["count"] = 99


def test_detection_metadata_nested_list_is_immutable():
    detection = _make_detection(metadata={"tags": ["brute-force", "ssh"]})

    assert isinstance(detection.metadata["tags"], tuple)
    with pytest.raises(TypeError):
        detection.metadata["tags"][0] = "changed"


def test_security_event_metadata_deeply_nested_structure_is_frozen():
    event = SecurityEvent(
        event_kind=EventKind.DETECTION_RECORDED,
        detection_id=VALID_UUID,
        metadata={
            "sources": [
                {"ip": "10.0.0.1", "flags": ["nat", "vpn"]},
                {"ip": "10.0.0.2", "flags": []},
            ]
        },
    )

    sources = event.metadata["sources"]
    assert isinstance(sources, tuple)
    assert isinstance(sources[0], type(event.metadata))  # MappingProxyType
    assert isinstance(sources[0]["flags"], tuple)

    with pytest.raises(TypeError):
        sources[0]["ip"] = "changed"
    with pytest.raises(TypeError):
        sources[0]["flags"][0] = "changed"


def test_nested_metadata_round_trips_through_to_dict():
    original_metadata = {
        "context": {"ip_reputation": "bad", "count": 3},
        "tags": ["brute-force", "ssh"],
        "sources": [{"ip": "10.0.0.1", "flags": ["nat", "vpn"]}],
    }
    detection = _make_detection(metadata=original_metadata)

    dumped = detection.to_dict()

    # to_dict() output must be plain, mutable, JSON-compatible structures.
    assert dumped["metadata"] == original_metadata
    assert isinstance(dumped["metadata"]["tags"], list)
    assert isinstance(dumped["metadata"]["sources"], list)
    assert isinstance(dumped["metadata"]["sources"][0], dict)
    assert isinstance(dumped["metadata"]["sources"][0]["flags"], list)

    # Mutating the dumped dict must not affect the frozen original.
    dumped["metadata"]["tags"].append("mutated")
    assert "mutated" not in detection.metadata["tags"]


def test_nested_metadata_round_trips_through_from_dict_and_json():
    original_metadata = {
        "context": {"ip_reputation": "bad", "count": 3},
        "tags": ["brute-force", "ssh"],
    }
    detection = _make_detection(metadata=original_metadata)

    restored_from_dict = Detection.from_dict(detection.to_dict())
    assert restored_from_dict == detection
    assert restored_from_dict.metadata["context"]["count"] == 3
    assert restored_from_dict.metadata["tags"] == ("brute-force", "ssh")

    restored_from_json = Detection.from_json(detection.to_json())
    assert restored_from_json == detection
    assert json.loads(detection.to_json())["metadata"] == original_metadata


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


def test_severity_enum_values():
    assert {member.value for member in Severity} == {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }


def test_event_kind_enum_values():
    assert {member.value for member in EventKind} == {
        "DETECTION_RECORDED",
        "ALERT_CREATED",
        "RESPONSE_DECIDED",
    }


def test_response_action_enum_values():
    assert {member.value for member in ResponseAction} == {
        "LOG",
        "FLAG",
        "ESCALATE",
        "ESCALATE_PRIORITY",
    }
