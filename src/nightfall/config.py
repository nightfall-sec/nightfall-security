from dataclasses import dataclass, field


@dataclass
class NightfallConfig:
    """
    Central configuration for the NIGHTFALL security toolkit.
    """

    brute_force_threshold: int = 5
    monitored_paths: list[str] = field(default_factory=list)

    def __post_init__(self):
        if self.brute_force_threshold < 1:
            raise ValueError(
                "brute_force_threshold must be greater than 0"
            )

    def to_dict(self) -> dict:
        """
        Convert configuration to a dictionary.
        """

        return {
            "brute_force_threshold": self.brute_force_threshold,
            "monitored_paths": list(self.monitored_paths),
        }
