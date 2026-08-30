import json
from typing import Any


def build_report(result: dict[str, Any]) -> dict[str, Any]:
    """
    Build a standardized NIGHTFALL security report.
    """

    events = result.get("events", [])

    serialized_events = [
        event.to_dict() if hasattr(event, "to_dict") else event
        for event in events
    ]

    return {
        "summary": {
            "total_log_lines": result["analysis"]["total_lines"],
            "failed_attempts": result["analysis"]["failed_attempts"],
            "detected_threats": len(result["detections"]),
            "generated_alerts": len(result["alerts"]),
            "security_events": len(result["events"]),
        },
        "analysis": result["analysis"],
        "detections": result["detections"],
        "alerts": result["alerts"],
        "events": serialized_events,
    }


def report_to_json(
    result: dict[str, Any],
    indent: int = 2,
) -> str:
    """
    Convert a NIGHTFALL security report to JSON.
    """

    report = build_report(result)

    return json.dumps(
        report,
        indent=indent,
        ensure_ascii=False,
    )
