from src.nightfall.security_pipeline import analyze_security_logs


def test_security_pipeline_detects_brute_force_and_builds_alert():
    logs = [
        "Failed password for user admin from 192.168.1.10",
        "Failed password for user root from 192.168.1.10",
        "Failed password for user test from 192.168.1.10",
        "Accepted password for user nightfall from 192.168.1.20",
    ]

    result = analyze_security_logs(logs, threshold=3)

    assert result["analysis"]["total_lines"] == 4
    assert result["analysis"]["failed_attempts"] == 3
    assert result["analysis"]["failed_sources"] == {"192.168.1.10": 3}

    assert len(result["detections"]) == 1
    assert result["detections"][0]["type"] == "BRUTE_FORCE"
    assert result["detections"][0]["severity"] == "HIGH"

    assert len(result["alerts"]) == 1
    assert result["alerts"][0]["threat_type"] == "BRUTE_FORCE"
    assert result["alerts"][0]["source_ip"] == "192.168.1.10"
    assert result["alerts"][0]["severity"] == "HIGH"
    assert result["alerts"][0]["failed_attempts"] == 3


def test_security_pipeline_returns_no_alert_below_threshold():
    logs = [
        "Failed password for user admin from 10.0.0.5",
        "Failed password for user root from 10.0.0.5",
    ]

    result = analyze_security_logs(logs, threshold=3)

    assert result["analysis"]["failed_attempts"] == 2
    assert result["detections"] == []
    assert result["alerts"] == []
