import pytest

from src.nightfall.config import NightfallConfig


def test_default_configuration():
    config = NightfallConfig()

    assert config.brute_force_threshold == 5
    assert config.monitored_paths == []


def test_custom_configuration():
    config = NightfallConfig(
        brute_force_threshold=10,
        monitored_paths=[
            "/var/log",
            "/etc",
        ],
    )

    assert config.brute_force_threshold == 10
    assert config.monitored_paths == [
        "/var/log",
        "/etc",
    ]


def test_configuration_to_dict():
    config = NightfallConfig(
        brute_force_threshold=7,
        monitored_paths=["/var/log"],
    )

    result = config.to_dict()

    assert result == {
        "brute_force_threshold": 7,
        "monitored_paths": ["/var/log"],
    }


def test_invalid_threshold():
    with pytest.raises(ValueError):
        NightfallConfig(brute_force_threshold=0)


def test_negative_threshold():
    with pytest.raises(ValueError):
        NightfallConfig(brute_force_threshold=-1)


def test_monitored_paths_are_independent():
    config_one = NightfallConfig()
    config_two = NightfallConfig()

    config_one.monitored_paths.append("/tmp")

    assert config_one.monitored_paths == ["/tmp"]
    assert config_two.monitored_paths == []
