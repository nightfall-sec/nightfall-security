def detect_brute_force(failed_sources, threshold=5):
    """
    Detect possible brute-force activity.

    Returns IP addresses that reached or exceeded
    the configured failed-attempt threshold.
    """

    if not isinstance(failed_sources, dict):
        raise TypeError("failed_sources must be a dictionary")

    if not isinstance(threshold, int):
        raise TypeError("threshold must be an integer")

    if threshold < 1:
        raise ValueError("threshold must be greater than 0")

    detections = []

    for ip_address, failed_count in failed_sources.items():
        if not isinstance(ip_address, str) or not ip_address.strip():
            raise ValueError("IP addresses must be non-empty strings")

        if not isinstance(failed_count, int):
            raise TypeError("failed attempt counts must be integers")

        if failed_count < 0:
            raise ValueError("failed attempt counts cannot be negative")

        if failed_count >= threshold:
            detections.append(
                {
                    "ip": ip_address,
                    "failed_attempts": failed_count,
                    "severity": "HIGH",
                    "type": "BRUTE_FORCE",
                }
            )

    return detections
