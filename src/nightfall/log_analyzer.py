import re
from collections import Counter


def analyze_logs(log_lines):
    """
    Analyze authentication logs and detect failed login sources.
    """

    failed_attempts = []
    failed_sources = Counter()

    for line in log_lines:
        if "Failed password" in line:
            failed_attempts.append(line)

            match = re.search(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})", line)

            if match:
                ip_address = match.group(1)
                failed_sources[ip_address] += 1

    return {
        "total_lines": len(log_lines),
        "failed_attempts": len(failed_attempts),
        "failed_sources": dict(failed_sources),
    }


if __name__ == "__main__":
    sample_logs = [
        "Failed password for user admin from 192.168.1.10",
        "Accepted password for user nightfall from 192.168.1.20",
        "Failed password for user root from 192.168.1.10",
        "Failed password for user test from 10.0.0.5",
    ]

    result = analyze_logs(sample_logs)

    print("NIGHTFALL Log Analyzer v2")
    print("-------------------------")
    print(f"Total log lines: {result['total_lines']}")
    print(f"Failed attempts: {result['failed_attempts']}")
    print("Failed sources:")

    for ip, count in result["failed_sources"].items():
        print(f"  {ip}: {count}")
