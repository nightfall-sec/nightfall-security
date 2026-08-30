from src.nightfall.log_analyzer import analyze_logs


def test_failed_login_detection():
    logs = [
        "Failed password for user admin from 192.168.1.10",
        "Accepted password for user nightfall from 192.168.1.20",
        "Failed password for user root from 192.168.1.10",
    ]

    result = analyze_logs(logs)

    assert result["total_lines"] == 3
    assert result["failed_attempts"] == 2
