from src.nightfall.file_integrity import (
    create_baseline,
    compare_baseline,
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
