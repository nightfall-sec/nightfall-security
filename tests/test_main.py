import subprocess
import sys


def test_package_entry_point_shows_help():
    result = subprocess.run(
        [sys.executable, "-m", "src.nightfall"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "NIGHTFALL Defensive Security Toolkit" in result.stdout
    assert "usage:" in result.stdout.lower()
