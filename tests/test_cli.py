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
