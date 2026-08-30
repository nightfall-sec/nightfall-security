from src.nightfall.alert_engine import build_alerts


def test_build_alert():
    detection_results = [
        {
            "ip": "192.168.1.10",
            "failed_attempts": 7,
            "severity": "HIGH",
            "type": "BRUTE_FORCE",
        }
    ]

    alerts = build_alerts(detection_results)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert["threat_type"] == "BRUTE_FORCE"
    assert alert["source_ip"] == "192.168.1.10"
    assert alert["severity"] == "HIGH"
    assert alert["failed_attempts"] == 7


def test_alert_description():
    detection_results = [
        {
            "ip": "10.0.0.5",
            "failed_attempts": 6,
            "severity": "HIGH",
            "type": "BRUTE_FORCE",
        }
    ]

    alerts = build_alerts(detection_results)

    description = alerts[0]["description"]

    assert "10.0.0.5" in description
    assert "6" in description
    assert "brute-force" in description.lower()


def test_multiple_alerts():
    detection_results = [
        {
            "ip": "192.168.1.10",
            "failed_attempts": 8,
            "severity": "HIGH",
            "type": "BRUTE_FORCE",
        },
        {
            "ip": "172.16.0.8",
            "failed_attempts": 5,
            "severity": "HIGH",
            "type": "BRUTE_FORCE",
        },
    ]

    alerts = build_alerts(detection_results)

    assert len(alerts) == 2
    assert alerts[0]["source_ip"] == "192.168.1.10"
    assert alerts[1]["source_ip"] == "172.16.0.8"
