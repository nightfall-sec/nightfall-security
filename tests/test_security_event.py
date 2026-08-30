from src.nightfall.security_event import SecurityEvent


def test_security_event_creation():
    event = SecurityEvent(
        event_type="brute_force",
        severity="high",
        source_ip="192.168.1.10",
    )

    assert event.event_type == "BRUTE_FORCE"
    assert event.severity == "HIGH"
    assert event.source_ip == "192.168.1.10"


def test_security_event_default_timestamp():
    event = SecurityEvent(
        event_type="login_failure",
        severity="medium",
    )

    assert event.timestamp
    assert "T" in event.timestamp


def test_security_event_metadata():
    event = SecurityEvent(
        event_type="malware",
        severity="critical",
        metadata={
            "file": "sample.exe",
            "detection": "suspicious_hash",
        },
    )

    assert event.metadata["file"] == "sample.exe"
    assert event.metadata["detection"] == "suspicious_hash"


def test_security_event_to_dict():
    event = SecurityEvent(
        event_type="brute_force",
        severity="high",
        source_ip="10.0.0.5",
        metadata={"failed_attempts": 10},
    )

    result = event.to_dict()

    assert result["event_type"] == "BRUTE_FORCE"
    assert result["severity"] == "HIGH"
    assert result["source_ip"] == "10.0.0.5"
    assert result["metadata"]["failed_attempts"] == 10
    assert "timestamp" in result


def test_security_event_rejects_empty_event_type():
    try:
        SecurityEvent(
            event_type="",
            severity="HIGH",
        )
        assert False
    except ValueError:
        assert True


def test_security_event_rejects_empty_severity():
    try:
        SecurityEvent(
            event_type="BRUTE_FORCE",
            severity="",
        )
        assert False
    except ValueError:
        assert True
