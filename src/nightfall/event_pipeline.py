from .alert_engine import build_alerts
from .incident_response import process_alert
from .log_analyzer import analyze_logs
from .security_event import SecurityEvent
from .threat_detection import detect_brute_force


def process_logs(log_lines, threshold=5):
    """
    Process raw authentication logs through the NIGHTFALL
    defensive detection pipeline.

    Pipeline:
        logs
        -> log analysis
        -> threat detection
        -> alert generation
        -> incident response
        -> standardized security events
    """

    # Step 1: Analyze raw logs
    analysis = analyze_logs(log_lines)

    # Step 2: Detect threats
    detections = detect_brute_force(
        analysis["failed_sources"],
        threshold=threshold,
    )

    # Step 3: Build security alerts
    alerts = build_alerts(detections)

    # Step 4: Convert alerts into standardized security events
    events = []

    for alert in alerts:
        processed_alert = process_alert(alert)

        event = SecurityEvent(
            event_type=processed_alert["threat_type"],
            severity=processed_alert["severity"],
            source_ip=processed_alert["source_ip"],
            metadata={
                "failed_attempts": processed_alert["failed_attempts"],
                "description": processed_alert["description"],
                "response": processed_alert["response"],
            },
        )

        events.append(event)

    return {
        "analysis": analysis,
        "detections": detections,
        "alerts": alerts,
        "events": events,
    }
