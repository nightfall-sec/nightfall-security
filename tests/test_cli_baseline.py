import json

from src.nightfall.cli import build_parser, main


def test_cli_parser_baseline():
    parser = build_parser()

    args = parser.parse_args(
        [
            "baseline",
            "/tmp/monitored",
            "--output",
            "/tmp/baseline.json",
        ]
    )

    assert args.command == "baseline"
    assert args.directory == "/tmp/monitored"
    assert args.output == "/tmp/baseline.json"
    assert args.json is False


def test_cli_parser_baseline_json():
    parser = build_parser()

    args = parser.parse_args(
        [
            "baseline",
            "/tmp/monitored",
            "--output",
            "/tmp/baseline.json",
            "--json",
        ]
    )

    assert args.command == "baseline"
    assert args.directory == "/tmp/monitored"
    assert args.output == "/tmp/baseline.json"
    assert args.json is True


def test_cli_parser_check():
    parser = build_parser()

    args = parser.parse_args(
        [
            "check",
            "/tmp/monitored",
            "--baseline",
            "/tmp/baseline.json",
        ]
    )

    assert args.command == "check"
    assert args.directory == "/tmp/monitored"
    assert args.baseline == "/tmp/baseline.json"
    assert args.json is False


def test_cli_parser_check_json():
    parser = build_parser()

    args = parser.parse_args(
        [
            "check",
            "/tmp/monitored",
            "--baseline",
            "/tmp/baseline.json",
            "--json",
        ]
    )

    assert args.command == "check"
    assert args.directory == "/tmp/monitored"
    assert args.baseline == "/tmp/baseline.json"
    assert args.json is True


def test_cli_baseline_creates_file(tmp_path, capsys):
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()

    test_file = monitored_dir / "important.txt"
    test_file.write_text(
        "NIGHTFALL",
        encoding="utf-8",
    )

    baseline_file = tmp_path / "baseline.json"

    exit_code = main(
        [
            "baseline",
            str(monitored_dir),
            "--output",
            str(baseline_file),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert baseline_file.exists()
    assert "NIGHTFALL Baseline Created" in captured.out
    assert "Files recorded: 1" in captured.out

    with open(baseline_file, "r", encoding="utf-8") as file:
        baseline = json.load(file)

    assert "important.txt" in baseline
    assert len(baseline["important.txt"]) == 64


def test_cli_baseline_json_output(tmp_path, capsys):
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()

    test_file = monitored_dir / "important.txt"
    test_file.write_text(
        "NIGHTFALL",
        encoding="utf-8",
    )

    baseline_file = tmp_path / "baseline.json"

    exit_code = main(
        [
            "baseline",
            str(monitored_dir),
            "--output",
            str(baseline_file),
            "--json",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0

    result = json.loads(captured.out)

    assert result["directory"] == str(monitored_dir)
    assert result["baseline"] == str(baseline_file)
    assert result["file_count"] == 1


def test_cli_check_clean_directory(tmp_path, capsys):
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()

    test_file = monitored_dir / "important.txt"
    test_file.write_text(
        "NIGHTFALL",
        encoding="utf-8",
    )

    baseline_file = tmp_path / "baseline.json"

    main(
        [
            "baseline",
            str(monitored_dir),
            "--output",
            str(baseline_file),
        ]
    )

    capsys.readouterr()

    exit_code = main(
        [
            "check",
            str(monitored_dir),
            "--baseline",
            str(baseline_file),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "NIGHTFALL Integrity Check" in captured.out
    assert "Unchanged: 1" in captured.out
    assert "Modified: 0" in captured.out
    assert "New: 0" in captured.out
    assert "Deleted: 0" in captured.out
    assert "INTEGRITY OK" in captured.out


def test_cli_check_detects_modified_file(tmp_path, capsys):
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()

    test_file = monitored_dir / "important.txt"
    test_file.write_text(
        "ORIGINAL",
        encoding="utf-8",
    )

    baseline_file = tmp_path / "baseline.json"

    main(
        [
            "baseline",
            str(monitored_dir),
            "--output",
            str(baseline_file),
        ]
    )

    capsys.readouterr()

    test_file.write_text(
        "MODIFIED",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "check",
            str(monitored_dir),
            "--baseline",
            str(baseline_file),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Modified: 1" in captured.out
    assert "important.txt" in captured.out
    assert "INTEGRITY VIOLATION" in captured.out


def test_cli_check_detects_new_file(tmp_path, capsys):
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()

    original_file = monitored_dir / "original.txt"
    original_file.write_text(
        "ORIGINAL",
        encoding="utf-8",
    )

    baseline_file = tmp_path / "baseline.json"

    main(
        [
            "baseline",
            str(monitored_dir),
            "--output",
            str(baseline_file),
        ]
    )

    capsys.readouterr()

    new_file = monitored_dir / "new.txt"
    new_file.write_text(
        "NEW FILE",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "check",
            str(monitored_dir),
            "--baseline",
            str(baseline_file),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "New: 1" in captured.out
    assert "new.txt" in captured.out
    assert "INTEGRITY VIOLATION" in captured.out


def test_cli_check_detects_deleted_file(tmp_path, capsys):
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()

    test_file = monitored_dir / "important.txt"
    test_file.write_text(
        "ORIGINAL",
        encoding="utf-8",
    )

    baseline_file = tmp_path / "baseline.json"

    main(
        [
            "baseline",
            str(monitored_dir),
            "--output",
            str(baseline_file),
        ]
    )

    capsys.readouterr()

    test_file.unlink()

    exit_code = main(
        [
            "check",
            str(monitored_dir),
            "--baseline",
            str(baseline_file),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Deleted: 1" in captured.out
    assert "important.txt" in captured.out
    assert "INTEGRITY VIOLATION" in captured.out


def test_cli_check_json_output(tmp_path, capsys):
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()

    test_file = monitored_dir / "important.txt"
    test_file.write_text(
        "ORIGINAL",
        encoding="utf-8",
    )

    baseline_file = tmp_path / "baseline.json"

    main(
        [
            "baseline",
            str(monitored_dir),
            "--output",
            str(baseline_file),
        ]
    )

    capsys.readouterr()

    test_file.write_text(
        "MODIFIED",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "check",
            str(monitored_dir),
            "--baseline",
            str(baseline_file),
            "--json",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 1

    result = json.loads(captured.out)

    assert result["directory"] == str(monitored_dir)
    assert result["baseline"] == str(baseline_file)

    assert result["summary"]["unchanged"] == 0
    assert result["summary"]["modified"] == 1
    assert result["summary"]["new"] == 0
    assert result["summary"]["deleted"] == 0

    assert result["modified"] == ["important.txt"]


def test_cli_check_missing_baseline(tmp_path, capsys):
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()

    exit_code = main(
        [
            "check",
            str(monitored_dir),
            "--baseline",
            str(tmp_path / "missing.json"),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Error: unable to load baseline" in captured.err
