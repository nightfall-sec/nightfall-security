def build_alerts(detection_results):
    """
    Convert threat detection results into standardized security alerts.
    """

    if not isinstance(detection_results, list):
        raise TypeError("detection_results must be a list")

    alerts = []

    for detection in detection_results:
        if not isinstance(detection, dict):
            raise TypeError("each detection must be a dictionary")

        required_fields = {
            "type",
            "ip",
            "severity",
            "failed_attempts",
        }

        missing_fields = required_fields - detection.keys()

        if missing_fields:
            raise KeyError(
                f"missing detection fields: {sorted(missing_fields)}"
            )

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
