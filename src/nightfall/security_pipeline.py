from uuid import uuid4

from .alert_engine import build_alerts
from .log_analyzer import analyze_logs
from .threat_detection import detect_brute_force


def analyze_security_logs(log_lines, threshold=5):
    """
    Run the complete log security analysis pipeline.

    Flow:
        logs -> log analyzer -> threat detection -> alert engine

    Every analysis receives a unique analysis_id so that
    future detection, AI, incident-response, reporting,
    and audit layers can correlate the complete operation.
    """

    analysis_id = uuid4().hex

    analysis = analyze_logs(log_lines)

    detections = detect_brute_force(
        analysis["failed_sources"],
        threshold=threshold,
    )

    alerts = build_alerts(detections)

    return {
        "analysis_id": analysis_id,
        "analysis": analysis,
        "detections": detections,
        "alerts": alerts,
    }