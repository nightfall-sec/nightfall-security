import hashlib


def calculate_sha256(file_path):
    """Calculate the SHA-256 hash of a file."""
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def check_integrity(file_path, expected_hash):
    """Check whether a file matches the expected SHA-256 hash."""
    actual_hash = calculate_sha256(file_path)

    return actual_hash == expected_hash
