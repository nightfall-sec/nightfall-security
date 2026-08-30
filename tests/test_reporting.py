import json

from src.nightfall.reporting import build_report, report_to_json
from src.nightfall.security_event import SecurityEvent


def make_result():
    event = SecurityEvent(
        event_type="BRUTE_FORCE",
        severity="HIGH",
        source_ip="192.168.1.10",
        metadata={
            "failed_attempts": 5,
            "response": "ESCALATE",
        },
    )

    return {
        "analysis": {
            "total_lines": 10,
            "failed_attempts": 5,
            "failed_sources": {
                "192.168.1.10": 5,
            },
        },
        "detections": [
            {
                "ip": "192.168.1.10",
                "failed_attempts": 5,
                "severity": "HIGH",
                "type": "BRUTE_FORCE",
            }
        ],
        "alerts": [
            {
                "threat_type": "BRUTE_FORCE",
                "source_ip": "192.168.1.10",
                "severity": "HIGH",
                "failed_attempts": 5,
                "description": "Possible brute-force activity detected.",
            }
        ],
        "events": [event],
    }


def test_build_report_summary():
    result = make_result()

    report = build_report(result)

    assert report["summary"]["total_log_lines"] == 10
    assert report["summary"]["failed_attempts"] == 5
    assert report["summary"]["detected_threats"] == 1
    assert report["summary"]["generated_alerts"] == 1
    assert report["summary"]["security_events"] == 1


def test_build_report_preserves_detection_data():
    result = make_result()

    report = build_report(result)

    assert report["detections"][0]["type"] == "BRUTE_FORCE"
    assert report["detections"][0]["ip"] == "192.168.1.10"
    assert report["detections"][0]["severity"] == "HIGH"


def test_build_report_serializes_security_events():
    result = make_result()

    report = build_report(result)

    event = report["events"][0]

    assert event["event_type"] == "BRUTE_FORCE"
    assert event["severity"] == "HIGH"
    assert event["source_ip"] == "192.168.1.10"
    assert event["metadata"]["failed_attempts"] == 5
    assert event["metadata"]["response"] == "ESCALATE"


def test_report_to_json_returns_valid_json():
    result = make_result()

    json_output = report_to_json(result)

    parsed = json.loads(json_output)

    assert parsed["summary"]["detected_threats"] == 1
    assert parsed["alerts"][0]["severity"] == "HIGH"


def test_report_to_json_supports_custom_indent():
    result = make_result()

    json_output = report_to_json(
        result,
        indent=4,
    )

    assert json_output.startswith("{")
    assert "    \"summary\"" in json_output
