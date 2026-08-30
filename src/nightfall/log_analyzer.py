import re
from collections import Counter


IP_PATTERN = re.compile(
    r"from\s+(\d{1,3}(?:\.\d{1,3}){3})"
)


def _is_valid_ipv4(ip_address):
    """Return True when the value is a valid IPv4 address."""

    parts = ip_address.split(".")

    if len(parts) != 4:
        return False

    return all(
        part.isdigit() and 0 <= int(part) <= 255
        for part in parts
    )


def analyze_logs(log_lines):
    """
    Analyze authentication logs and detect failed login sources.

    The analyzer returns structured information that can later
    be consumed by the detection, correlation, risk, and AI layers.
    """

    if not isinstance(log_lines, (list, tuple)):
        raise TypeError("log_lines must be a list or tuple")

    failed_attempts = []
    failed_sources = Counter()
    invalid_lines = 0

    for line in log_lines:
        if not isinstance(line, str):
            raise TypeError("each log line must be a string")

        if "Failed password" not in line:
            continue

        failed_attempts.append(line)

        match = IP_PATTERN.search(line)

        if not match:
            invalid_lines += 1
            continue

        ip_address = match.group(1)

        if _is_valid_ipv4(ip_address):
            failed_sources[ip_address] += 1
        else:
            invalid_lines += 1

    return {
        "total_lines": len(log_lines),
        "failed_attempts": len(failed_attempts),
        "failed_sources": dict(failed_sources),
        "invalid_lines": invalid_lines,
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
    print(f"Invalid log lines: {result['invalid_lines']}")
    print("Failed sources:")

    for ip, count in result["failed_sources"].items():
        print(f"  {ip}: {count}")
