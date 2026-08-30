from src.nightfall.file_integrity import calculate_sha256, check_integrity


def test_sha256_calculation(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("NIGHTFALL")

    actual_hash = calculate_sha256(test_file)

    assert isinstance(actual_hash, str)
    assert len(actual_hash) == 64


def test_file_integrity(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("NIGHTFALL")

    actual_hash = calculate_sha256(test_file)

    assert check_integrity(test_file, actual_hash) is True
    assert check_integrity(test_file, "0" * 64) is False
