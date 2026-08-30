RESPONSE_ACTIONS = {
    "LOW": "LOG",
    "MEDIUM": "FLAG",
    "HIGH": "ESCALATE",
    "CRITICAL": "ESCALATE_PRIORITY",
}


def determine_response(severity):
    """
    Determine the appropriate defensive response
    for a security alert severity.
    """

    normalized_severity = severity.upper()

    if normalized_severity not in RESPONSE_ACTIONS:
        raise ValueError(f"Unsupported severity: {severity}")

    return RESPONSE_ACTIONS[normalized_severity]


def process_alert(alert):
    """
    Add a defensive response decision to a security alert.
    """

    severity = alert["severity"]

    response = determine_response(severity)

    return {
        **alert,
        "response": response,
    }
