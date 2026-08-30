import json
from pathlib import Path

from src.nightfall.cli import build_parser, main


def test_cli_parser_analyze():
    parser = build_parser()

    args = parser.parse_args(
        [
            "analyze",
            "auth.log",
            "--threshold",
            "3",
        ]
    )

    assert args.command == "analyze"
    assert args.logfile == "auth.log"
    assert args.threshold == 3
    assert args.json is False


def test_cli_parser_default_threshold():
    parser = build_parser()

    args = parser.parse_args(
        [
            "analyze",
            "auth.log",
        ]
    )

    assert args.command == "analyze"
    assert args.logfile == "auth.log"
    assert args.threshold == 5
    assert args.json is False


def test_cli_parser_json_option():
    parser = build_parser()

    args = parser.parse_args(
        [
            "analyze",
            "auth.log",
            "--json",
        ]
    )

    assert args.command == "analyze"
    assert args.logfile == "auth.log"
    assert args.json is True


def test_cli_analyze_success(tmp_path, capsys):
    logfile = Path(tmp_path) / "auth.log"

    logfile.write_text(
        "\n".join(
            [
                "Failed password for user admin from 192.168.1.10",
                "Failed password for user root from 192.168.1.10",
                "Failed password for user test from 192.168.1.10",
                "Accepted password for user nightfall from 192.168.1.20",
            ]
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "analyze",
            str(logfile),
            "--threshold",
            "3",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "NIGHTFALL Security Analysis" in captured.out
    assert "Total log lines: 4" in captured.out
    assert "Failed attempts: 3" in captured.out
    assert "Detected threats: 1" in captured.out
    assert "Generated alerts: 1" in captured.out
    assert "Security events: 1" in captured.out


def test_cli_analyze_missing_file(capsys):
    exit_code = main(
        [
            "analyze",
            "missing.log",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Error: unable to read log file" in captured.err


def test_cli_without_command(capsys):
    exit_code = main([])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "usage:" in captured.out.lower()
    assert "NIGHTFALL Defensive Security Toolkit" in captured.out


def test_cli_analyze_json_output(tmp_path, capsys):
    logfile = tmp_path / "auth.log"

    logfile.write_text(
        "\n".join(
            [
                "Failed password for user admin from 192.168.1.10",
                "Failed password for user root from 192.168.1.10",
                "Failed password for user test from 192.168.1.10",
            ]
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "analyze",
            str(logfile),
            "--threshold",
            "3",
            "--json",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0

    report = json.loads(captured.out)

    assert report["summary"]["total_log_lines"] == 3
    assert report["summary"]["failed_attempts"] == 3
    assert report["summary"]["detected_threats"] == 1
    assert report["summary"]["generated_alerts"] == 1
    assert report["summary"]["security_events"] == 1

    assert report["detections"][0]["type"] == "BRUTE_FORCE"
    assert report["detections"][0]["ip"] == "192.168.1.10"

    assert report["alerts"][0]["severity"] == "HIGH"
    assert report["alerts"][0]["source_ip"] == "192.168.1.10"

    assert report["events"][0]["event_type"] == "BRUTE_FORCE"
    assert report["events"][0]["severity"] == "HIGH"
    assert report["events"][0]["source_ip"] == "192.168.1.10"
