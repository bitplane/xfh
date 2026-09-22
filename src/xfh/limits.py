"""Resource limits applied before allocating decompressed output."""

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace

from xfh.errors import ResourceLimitError


@dataclass(frozen=True, slots=True)
class Limits:
    """Limits used to bound work on untrusted compressed input."""

    max_output_size: int = 256 * 1024 * 1024
    max_chunks: int = 1_000_000
    max_depth: int = 16

    def __post_init__(self) -> None:
        if self.max_output_size < 0:
            raise ValueError("max_output_size must not be negative")
        if self.max_depth < 1:
            raise ValueError("max_depth must be positive")
        if self.max_chunks < 1:
            raise ValueError("max_chunks must be positive")


DEFAULT_LIMITS = Limits()


@dataclass
class _DecodeBudget:
    limits: Limits
    chunks_left: int
    depth: int = 0


_BUDGET: ContextVar[_DecodeBudget | None] = ContextVar("xfh_decode_budget", default=None)


@contextmanager
def decoding_scope(limits: Limits):
    """Share chunk and nesting budgets across recursive decoders in this call."""

    budget = _BUDGET.get()
    token = None
    if budget is None:
        budget = _DecodeBudget(limits, limits.max_chunks)
        token = _BUDGET.set(budget)
    try:
        if budget.depth >= budget.limits.max_depth:
            raise ResourceLimitError("stream exceeds configured nesting depth")
        budget.depth += 1
        try:
            yield
        finally:
            budget.depth -= 1
    finally:
        if token is not None:
            _BUDGET.reset(token)


def charge_chunks(count: int) -> None:
    budget = _BUDGET.get()
    if budget is not None:
        if count > budget.chunks_left:
            raise ResourceLimitError("nested streams exceed configured total chunk count")
        budget.chunks_left -= count


def nested_limits(output_size: int) -> Limits:
    budget = _BUDGET.get()
    limits = DEFAULT_LIMITS if budget is None else budget.limits
    return replace(limits, max_output_size=min(output_size, limits.max_output_size))
