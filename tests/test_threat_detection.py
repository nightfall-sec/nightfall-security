from src.nightfall.threat_detection import detect_brute_force


def test_brute_force_detection():
    failed_sources = {
        "192.168.1.10": 7,
        "10.0.0.5": 2,
        "172.16.0.8": 5,
    }

    alerts = detect_brute_force(failed_sources)

    assert len(alerts) == 2

    detected_ips = {alert["ip"] for alert in alerts}

    assert "192.168.1.10" in detected_ips
    assert "172.16.0.8" in detected_ips
    assert "10.0.0.5" not in detected_ips


def test_brute_force_alert_details():
    failed_sources = {
        "192.168.1.10": 6,
    }

    alerts = detect_brute_force(failed_sources)

    assert len(alerts) == 1
    assert alerts[0]["ip"] == "192.168.1.10"
    assert alerts[0]["failed_attempts"] == 6
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["type"] == "BRUTE_FORCE"


def test_custom_threshold():
    failed_sources = {
        "192.168.1.10": 3,
        "10.0.0.5": 4,
    }

    alerts = detect_brute_force(
        failed_sources,
        threshold=4,
    )

    assert len(alerts) == 1
    assert alerts[0]["ip"] == "10.0.0.5"
