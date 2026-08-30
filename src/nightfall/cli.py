import argparse
import json
import sys

from .config import NightfallConfig
from .event_pipeline import process_logs
from .file_integrity import (
    compare_baseline,
    create_baseline,
    load_baseline,
    save_baseline,
    scan_directory,
)
from .reporting import build_report


def build_parser():
    parser = argparse.ArgumentParser(
        prog="nightfall",
        description="NIGHTFALL Defensive Security Toolkit",
    )

    subparsers = parser.add_subparsers(
        dest="command",
    )

    # ---------------------------------------------------------
    # ANALYZE
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # INTEGRITY
    # ---------------------------------------------------------

    integrity_parser = subparsers.add_parser(
        "integrity",
        help="Scan a directory and calculate SHA-256 hashes.",
    )

    integrity_parser.add_argument(
        "directory",
        help="Directory to scan.",
    )

    integrity_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the integrity results as JSON.",
    )

    # ---------------------------------------------------------
    # BASELINE
    # ---------------------------------------------------------

    baseline_parser = subparsers.add_parser(
        "baseline",
        help="Create a SHA-256 file-integrity baseline.",
    )

    baseline_parser.add_argument(
        "directory",
        help="Directory to create a baseline for.",
    )

    baseline_parser.add_argument(
        "--output",
        required=True,
        help="Path where the baseline JSON file will be saved.",
    )

    baseline_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the baseline result as JSON.",
    )

    # ---------------------------------------------------------
    # CHECK
    # ---------------------------------------------------------

    check_parser = subparsers.add_parser(
        "check",
        help="Compare a directory against a saved integrity baseline.",
    )

    check_parser.add_argument(
        "directory",
        help="Directory to check.",
    )

    check_parser.add_argument(
        "--baseline",
        required=True,
        help="Path to the baseline JSON file.",
    )

    check_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the integrity check as JSON.",
    )

    return parser


# =============================================================
# ANALYZE COMMAND
# =============================================================

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


# =============================================================
# INTEGRITY COMMAND
# =============================================================

def run_integrity(args):
    try:
        hashes = scan_directory(args.directory)

    except (OSError, NotADirectoryError) as exc:
        print(
            f"Error: unable to scan directory: {exc}",
            file=sys.stderr,
        )
        return 1

    if args.json:
        print(
            json.dumps(
                {
                    "directory": args.directory,
                    "files": hashes,
                    "file_count": len(hashes),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    print("NIGHTFALL File Integrity Scan")
    print("=" * 30)
    print(f"Directory: {args.directory}")
    print(f"Files scanned: {len(hashes)}")

    for path, file_hash in hashes.items():
        print(f"{path}: {file_hash}")

    return 0


# =============================================================
# BASELINE COMMAND
# =============================================================

def run_baseline(args):
    try:
        baseline = create_baseline(args.directory)
        save_baseline(
            baseline,
            args.output,
        )

    except (OSError, NotADirectoryError) as exc:
        print(
            f"Error: unable to create baseline: {exc}",
            file=sys.stderr,
        )
        return 1

    if args.json:
        print(
            json.dumps(
                {
                    "directory": args.directory,
                    "baseline": args.output,
                    "file_count": len(baseline),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    print("NIGHTFALL Baseline Created")
    print("=" * 30)
    print(f"Directory: {args.directory}")
    print(f"Baseline: {args.output}")
    print(f"Files recorded: {len(baseline)}")

    return 0


# =============================================================
# CHECK COMMAND
# =============================================================

def run_check(args):
    try:
        baseline = load_baseline(args.baseline)

    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"Error: unable to load baseline: {exc}",
            file=sys.stderr,
        )
        return 1

    try:
        result = compare_baseline(
            baseline,
            args.directory,
        )

    except (OSError, NotADirectoryError) as exc:
        print(
            f"Error: unable to check directory: {exc}",
            file=sys.stderr,
        )
        return 1

    unchanged = result["unchanged"]
    modified = result["modified"]
    new = result["new"]
    deleted = result["deleted"]

    has_changes = bool(
        modified
        or new
        or deleted
    )

    if args.json:
        output = {
            "directory": args.directory,
            "baseline": args.baseline,
            "summary": {
                "unchanged": len(unchanged),
                "modified": len(modified),
                "new": len(new),
                "deleted": len(deleted),
            },
            "unchanged": unchanged,
            "modified": modified,
            "new": new,
            "deleted": deleted,
        }

        print(
            json.dumps(
                output,
                indent=2,
                ensure_ascii=False,
            )
        )

        return 1 if has_changes else 0

    print("NIGHTFALL Integrity Check")
    print("=" * 30)
    print(f"Directory: {args.directory}")
    print(f"Baseline: {args.baseline}")
    print(f"Unchanged: {len(unchanged)}")
    print(f"Modified: {len(modified)}")
    print(f"New: {len(new)}")
    print(f"Deleted: {len(deleted)}")

    if modified:
        print()
        print("Modified files:")

        for path in modified:
            print(f"  - {path}")

    if new:
        print()
        print("New files:")

        for path in new:
            print(f"  - {path}")

    if deleted:
        print()
        print("Deleted files:")

        for path in deleted:
            print(f"  - {path}")

    print()

    if has_changes:
        print("INTEGRITY VIOLATION")
        return 1

    print("INTEGRITY OK")
    return 0


# =============================================================
# MAIN
# =============================================================

def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        return run_analyze(args)

    if args.command == "integrity":
        return run_integrity(args)

    if args.command == "baseline":
        return run_baseline(args)

    if args.command == "check":
        return run_check(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
