import json

import pytest

from src.nightfall.file_integrity import (
    compare_baseline,
    create_baseline,
    load_baseline,
    save_baseline,
)


def test_save_and_load_baseline(tmp_path):
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()

    file_a = monitored_dir / "file_a.txt"
    file_a.write_text("original content", encoding="utf-8")

    baseline = create_baseline(monitored_dir)

    baseline_file = tmp_path / "baseline.json"

    save_baseline(baseline, baseline_file)

    loaded = load_baseline(baseline_file)

    assert loaded == baseline


def test_saved_baseline_is_valid_json(tmp_path):
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()

    file_a = monitored_dir / "file_a.txt"
    file_a.write_text("security data", encoding="utf-8")

    baseline = create_baseline(monitored_dir)

    baseline_file = tmp_path / "baseline.json"

    save_baseline(baseline, baseline_file)

    with open(baseline_file, encoding="utf-8") as file:
        data = json.load(file)

    assert isinstance(data, dict)
    assert data == baseline


def test_baseline_detects_modified_file(tmp_path):
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()

    file_a = monitored_dir / "file_a.txt"
    file_a.write_text("original", encoding="utf-8")

    baseline = create_baseline(monitored_dir)

    file_a.write_text("modified", encoding="utf-8")

    result = compare_baseline(baseline, monitored_dir)

    assert result["modified"] == ["file_a.txt"]
    assert result["new"] == []
    assert result["deleted"] == []


def test_baseline_detects_new_file(tmp_path):
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()

    file_a = monitored_dir / "file_a.txt"
    file_a.write_text("original", encoding="utf-8")

    baseline = create_baseline(monitored_dir)

    file_b = monitored_dir / "file_b.txt"
    file_b.write_text("new file", encoding="utf-8")

    result = compare_baseline(baseline, monitored_dir)

    assert result["new"] == ["file_b.txt"]
    assert result["modified"] == []
    assert result["deleted"] == []


def test_baseline_detects_deleted_file(tmp_path):
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()

    file_a = monitored_dir / "file_a.txt"
    file_a.write_text("original", encoding="utf-8")

    baseline = create_baseline(monitored_dir)

    file_a.unlink()

    result = compare_baseline(baseline, monitored_dir)

    assert result["deleted"] == ["file_a.txt"]
    assert result["modified"] == []
    assert result["new"] == []


def test_baseline_reports_unchanged_file(tmp_path):
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()

    file_a = monitored_dir / "file_a.txt"
    file_a.write_text("unchanged", encoding="utf-8")

    baseline = create_baseline(monitored_dir)

    result = compare_baseline(baseline, monitored_dir)

    assert result["unchanged"] == ["file_a.txt"]
    assert result["modified"] == []
    assert result["deleted"] == []
    assert result["new"] == []


def test_load_baseline_missing_file(tmp_path):
    baseline_file = tmp_path / "missing.json"

    with pytest.raises(FileNotFoundError):
        load_baseline(baseline_file)
