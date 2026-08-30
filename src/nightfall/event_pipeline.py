from .alert_engine import build_alerts
from .config import NightfallConfig
from .incident_response import process_alert
from .log_analyzer import analyze_logs
from .security_event import SecurityEvent
from .threat_detection import detect_brute_force


def process_logs(log_lines, config=None, threshold=None):
    """
    Process raw authentication logs through the complete
    NIGHTFALL defensive security pipeline.

    Pipeline:
        logs
        -> analysis
        -> threat detection
        -> alerts
        -> incident response
        -> security events

    A NightfallConfig object can be supplied to centralize
    security settings.
    """

    if config is None:
        config = NightfallConfig()

    if not isinstance(config, NightfallConfig):
        raise TypeError("config must be a NightfallConfig instance")

    if threshold is None:
        threshold = config.brute_force_threshold

    analysis = analyze_logs(log_lines)

    detections = detect_brute_force(
        analysis["failed_sources"],
        threshold=threshold,
    )

    alerts = build_alerts(detections)

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
