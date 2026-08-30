import argparse
import json
import sys

from .config import NightfallConfig
from .event_pipeline import process_logs
from .reporting import build_report


def build_parser():
    parser = argparse.ArgumentParser(
        prog="nightfall",
        description="NIGHTFALL Defensive Security Toolkit",
    )

    subparsers = parser.add_subparsers(
        dest="command",
    )

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze authentication log lines.",
    )

    analyze_parser.add_argument(
        "logfile",
        help="Path to the log file.",
    )

    analyze_parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Brute-force detection threshold.",
    )

    analyze_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the security report as JSON.",
    )

    return parser


def run_analyze(args):
    try:
        with open(args.logfile, "r", encoding="utf-8") as file:
            log_lines = file.readlines()
    except OSError as exc:
        print(
            f"Error: unable to read log file: {exc}",
            file=sys.stderr,
        )
        return 1

    try:
        config = NightfallConfig(
            brute_force_threshold=args.threshold,
        )
    except ValueError as exc:
        print(
            f"Error: invalid configuration: {exc}",
            file=sys.stderr,
        )
        return 1

    result = process_logs(
        log_lines,
        config=config,
    )

    if args.json:
        print(
            json.dumps(
                build_report(result),
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    analysis = result["analysis"]

    print("NIGHTFALL Security Analysis")
    print("=" * 30)
    print(f"Total log lines: {analysis['total_lines']}")
    print(f"Failed attempts: {analysis['failed_attempts']}")
    print(f"Detected threats: {len(result['detections'])}")
    print(f"Generated alerts: {len(result['alerts'])}")
    print(f"Security events: {len(result['events'])}")

    return 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        return run_analyze(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
