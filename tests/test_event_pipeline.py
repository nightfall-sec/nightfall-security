from src.nightfall.config import NightfallConfig
from src.nightfall.event_pipeline import process_logs


def test_event_pipeline_detects_brute_force():
    logs = [
        "Failed password for user admin from 192.168.1.10",
        "Failed password for user root from 192.168.1.10",
        "Failed password for user test from 192.168.1.10",
        "Accepted password for user nightfall from 192.168.1.20",
    ]

    result = process_logs(logs, threshold=3)

    assert result["analysis"]["failed_attempts"] == 3

    assert len(result["detections"]) == 1
    assert result["detections"][0]["type"] == "BRUTE_FORCE"

    assert len(result["alerts"]) == 1
    assert result["alerts"][0]["source_ip"] == "192.168.1.10"
    assert result["alerts"][0]["severity"] == "HIGH"

    assert len(result["events"]) == 1

    event = result["events"][0]

    assert event.event_type == "BRUTE_FORCE"
    assert event.severity == "HIGH"
    assert event.source_ip == "192.168.1.10"


def test_event_pipeline_contains_response():
    logs = [
        "Failed password for user admin from 10.0.0.5",
        "Failed password for user root from 10.0.0.5",
        "Failed password for user test from 10.0.0.5",
    ]

    result = process_logs(logs, threshold=3)

    event = result["events"][0]

    assert event.metadata["failed_attempts"] == 3
    assert event.metadata["response"] == "ESCALATE"


def test_event_pipeline_no_threat_below_threshold():
    logs = [
        "Failed password for user admin from 10.0.0.5",
        "Failed password for user root from 10.0.0.5",
    ]

    result = process_logs(logs, threshold=3)

    assert result["detections"] == []
    assert result["alerts"] == []
    assert result["events"] == []


def test_event_pipeline_ignores_successful_logins():
    logs = [
        "Accepted password for user nightfall from 192.168.1.20",
        "Accepted password for user admin from 192.168.1.30",
    ]

    result = process_logs(logs, threshold=1)

    assert result["analysis"]["failed_attempts"] == 0
    assert result["detections"] == []
    assert result["alerts"] == []
    assert result["events"] == []


def test_event_pipeline_uses_configuration_threshold():
    logs = [
        "Failed password for user admin from 192.168.1.10",
        "Failed password for user root from 192.168.1.10",
        "Failed password for user test from 192.168.1.10",
        "Failed password for user guest from 192.168.1.10",
    ]

    config = NightfallConfig(
        brute_force_threshold=4,
    )

    result = process_logs(
        logs,
        config=config,
    )

    assert result["analysis"]["failed_attempts"] == 4
    assert len(result["detections"]) == 1
    assert result["detections"][0]["ip"] == "192.168.1.10"
    assert result["detections"][0]["failed_attempts"] == 4
