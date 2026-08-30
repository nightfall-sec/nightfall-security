from src.nightfall.file_integrity import (
    compare_baseline,
    create_baseline,
    load_baseline,
    save_baseline,
    scan_directory,
)


def test_unchanged_file(tmp_path):
    test_file = tmp_path / "important.txt"
    test_file.write_text("NIGHTFALL")

    baseline = create_baseline(tmp_path)

    result = compare_baseline(baseline, tmp_path)

    assert result["unchanged"] == ["important.txt"]
    assert result["modified"] == []
    assert result["deleted"] == []
    assert result["new"] == []


def test_modified_file(tmp_path):
    test_file = tmp_path / "important.txt"
    test_file.write_text("NIGHTFALL")

    baseline = create_baseline(tmp_path)

    test_file.write_text("MODIFIED")

    result = compare_baseline(baseline, tmp_path)

    assert result["modified"] == ["important.txt"]
    assert result["unchanged"] == []


def test_deleted_file(tmp_path):
    test_file = tmp_path / "important.txt"
    test_file.write_text("NIGHTFALL")

    baseline = create_baseline(tmp_path)

    test_file.unlink()

    result = compare_baseline(baseline, tmp_path)

    assert result["deleted"] == ["important.txt"]


def test_new_file(tmp_path):
    test_file = tmp_path / "important.txt"
    test_file.write_text("NIGHTFALL")

    baseline = create_baseline(tmp_path)

    new_file = tmp_path / "new_file.txt"
    new_file.write_text("NEW FILE")

    result = compare_baseline(baseline, tmp_path)

    assert result["new"] == ["new_file.txt"]


def test_save_and_load_baseline(tmp_path):
    test_file = tmp_path / "important.txt"
    test_file.write_text("NIGHTFALL")

    baseline = create_baseline(tmp_path)

    baseline_file = tmp_path / "baseline.json"

    save_baseline(baseline, baseline_file)

    loaded_baseline = load_baseline(baseline_file)

    assert loaded_baseline == baseline


def test_scan_directory(tmp_path):
    test_file = tmp_path / "important.txt"
    test_file.write_text("NIGHTFALL")

    result = scan_directory(tmp_path)

    assert "important.txt" in result
    assert len(result) == 1
