def build_alerts(detection_results):
    """
    Convert threat detection results into standardized security alerts.
    """

    alerts = []

    for detection in detection_results:
        alert = {
            "threat_type": detection["type"],
            "source_ip": detection["ip"],
            "severity": detection["severity"],
            "failed_attempts": detection["failed_attempts"],
            "description": (
                f"Possible brute-force activity detected from "
                f"{detection['ip']} with "
                f"{detection['failed_attempts']} failed login attempts."
            ),
        }

        alerts.append(alert)

    return alerts
