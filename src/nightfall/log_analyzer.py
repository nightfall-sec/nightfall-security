from collections import Counter


def analyze_logs(log_lines):
    """
    Analyze authentication logs and count failed login attempts.
    """

    failed_attempts = []

    for line in log_lines:
        if "Failed password" in line:
            failed_attempts.append(line)

    return {
        "total_lines": len(log_lines),
        "failed_attempts": len(failed_attempts),
    }


if __name__ == "__main__":
    sample_logs = [
        "Failed password for user admin from 192.168.1.10",
        "Accepted password for user nightfall from 192.168.1.20",
        "Failed password for user root from 192.168.1.10",
    ]

    result = analyze_logs(sample_logs)

    print("NIGHTFALL Log Analyzer")
    print("----------------------")
    print(f"Total log lines: {result['total_lines']}")
    print(f"Failed attempts: {result['failed_attempts']}")
