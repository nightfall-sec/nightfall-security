from .alert_engine import build_alerts
from .log_analyzer import analyze_logs
from .threat_detection import detect_brute_force


def analyze_security_logs(log_lines, threshold=5):
    """
    Run the complete log security analysis pipeline.

    Flow:
        logs -> log analyzer -> threat detection -> alert engine
    """

    analysis = analyze_logs(log_lines)

    detections = detect_brute_force(
        analysis["failed_sources"],
        threshold=threshold,
    )

    alerts = build_alerts(detections)

    return {
        "analysis": analysis,
        "detections": detections,
        "alerts": alerts,
    }
