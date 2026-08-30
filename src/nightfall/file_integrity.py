import hashlib
from pathlib import Path


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


def scan_directory(directory):
    """Return SHA-256 hashes for all files under a directory."""
    root = Path(directory)

    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")

    hashes = {}

    for path in sorted(root.rglob("*")):
        if path.is_file():
            relative_path = path.relative_to(root).as_posix()
            hashes[relative_path] = calculate_sha256(path)

    return hashes


def create_baseline(directory):
    """Create a file-integrity baseline for a directory."""
    return scan_directory(directory)


def compare_baseline(baseline, directory):
    """Compare a baseline with the current directory state."""

    current = scan_directory(directory)

    baseline_paths = set(baseline)
    current_paths = set(current)

    unchanged = sorted(
        path
        for path in baseline_paths & current_paths
        if baseline[path] == current[path]
    )

    modified = sorted(
        path
        for path in baseline_paths & current_paths
        if baseline[path] != current[path]
    )

    deleted = sorted(
        baseline_paths - current_paths
    )

    new = sorted(
        current_paths - baseline_paths
    )

    return {
        "unchanged": unchanged,
        "modified": modified,
        "deleted": deleted,
        "new": new,
    }
