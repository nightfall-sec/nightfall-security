def detect_brute_force(failed_sources, threshold=5):
    """
    Detect possible brute-force activity.

    Returns IP addresses that reached or exceeded
    the configured failed-attempt threshold.
    """

    alerts = []

    for ip_address, failed_count in failed_sources.items():
        if failed_count >= threshold:
            alerts.append(
                {
                    "ip": ip_address,
                    "failed_attempts": failed_count,
                    "severity": "HIGH",
                    "type": "BRUTE_FORCE",
                }
            )

    return alerts
