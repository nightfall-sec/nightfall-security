import argparse
import sys

from .config import NightfallConfig
from .event_pipeline import process_logs


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

    return parser


def run_analyze(args):
    try:
        with open(args.logfile, "r", encoding="utf-8") as file:
            log_lines = file.readlines()
    except OSError as exc:
        print(f"Error: unable to read log file: {exc}", file=sys.stderr)
        return 1

    config = NightfallConfig(
        brute_force_threshold=args.threshold,
    )

    result = process_logs(
        log_lines,
        config=config,
    )

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
