import pytest

from src.nightfall.incident_response import (
    determine_response,
    process_alert,
)


def test_low_severity_response():
    assert determine_response("LOW") == "LOG"


def test_medium_severity_response():
    assert determine_response("MEDIUM") == "FLAG"


def test_high_severity_response():
    assert determine_response("HIGH") == "ESCALATE"


def test_critical_severity_response():
    assert determine_response("CRITICAL") == "ESCALATE_PRIORITY"


def test_severity_is_case_insensitive():
    assert determine_response("high") == "ESCALATE"


def test_invalid_severity_raises_error():
    with pytest.raises(ValueError):
        determine_response("UNKNOWN")


def test_process_alert_adds_response():
    alert = {
        "threat_type": "BRUTE_FORCE",
        "source_ip": "192.168.1.10",
        "severity": "HIGH",
        "failed_attempts": 5,
    }

    result = process_alert(alert)

    assert result["threat_type"] == "BRUTE_FORCE"
    assert result["source_ip"] == "192.168.1.10"
    assert result["severity"] == "HIGH"
    assert result["failed_attempts"] == 5
    assert result["response"] == "ESCALATE"


def test_process_alert_preserves_original_alert():
    alert = {
        "threat_type": "BRUTE_FORCE",
        "severity": "CRITICAL",
    }

    result = process_alert(alert)

    assert result is not alert
    assert alert["severity"] == "CRITICAL"
    assert result["response"] == "ESCALATE_PRIORITY"
