"""Resource limits applied before allocating decompressed output."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Limits:
    """Limits used to bound work on untrusted compressed input."""

    max_output_size: int = 256 * 1024 * 1024
    max_chunks: int = 1_000_000

    def __post_init__(self) -> None:
        if self.max_output_size < 0:
            raise ValueError("max_output_size must not be negative")
        if self.max_chunks < 1:
            raise ValueError("max_chunks must be positive")


DEFAULT_LIMITS = Limits()
