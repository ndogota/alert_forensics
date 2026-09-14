"""Wilson score intervals, in code, on every proportion the evaluation reports."""

import math

from pydantic import model_validator

from alert_forensics.contracts._base import ContractModel, StrictNonNegativeInt

Z_95 = 1.959963984540054
"""The 97.5th percentile of the standard normal: a two-sided 95 percent interval."""


def wilson(successes: int, trials: int, z: float = Z_95) -> tuple[float, float]:
    """The Wilson score interval for ``successes`` in ``trials``.

    With ``p = successes / trials`` and ``n = trials``::

        centre = (p + z^2 / (2 n)) / (1 + z^2 / n)
        half   = z * sqrt(p (1 - p) / n + z^2 / (4 n^2)) / (1 + z^2 / n)
        low, high = centre - half, centre + half

    clamped to ``[0, 1]``. It is not the normal approximation ``p +/- z sqrt(p(1-p)/n)``,
    which collapses to a point at 0 of n or n of n and is meaningless at the run counts
    a cell has: 0 of 3 is ``[0, 0.56]`` here and ``[0, 0]`` there.
    """
    if trials <= 0:
        raise ValueError("a Wilson interval needs at least one trial")
    if not 0 <= successes <= trials:
        raise ValueError(f"{successes} successes in {trials} trials is impossible")
    n = trials
    p = successes / n
    z2 = z * z
    denominator = 1 + z2 / n
    centre = (p + z2 / (2 * n)) / denominator
    half = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denominator
    return max(0.0, centre - half), min(1.0, centre + half)


class Proportion(ContractModel):
    """A count over a count, with its Wilson 95 percent interval beside it.

    The interval is part of the value, not an annotation: a proportion cannot be
    reported without it, and the validator refuses one whose interval does not follow
    from its counts. An empty denominator has no estimate and no interval.
    """

    numerator: StrictNonNegativeInt
    denominator: StrictNonNegativeInt
    estimate: float | None
    low: float | None
    high: float | None

    @classmethod
    def of(cls, numerator: int, denominator: int) -> "Proportion":
        if denominator == 0:
            return cls(numerator=0, denominator=0, estimate=None, low=None, high=None)
        low, high = wilson(numerator, denominator)
        return cls(
            numerator=numerator,
            denominator=denominator,
            estimate=numerator / denominator,
            low=low,
            high=high,
        )

    @property
    def defined(self) -> bool:
        return self.estimate is not None

    def render(self) -> str:
        if self.estimate is None or self.low is None or self.high is None:
            return f"{self.numerator}/{self.denominator} n/a"
        return (
            f"{self.numerator}/{self.denominator} = {self.estimate:.2f} "
            f"[{self.low:.2f}, {self.high:.2f}]"
        )

    @model_validator(mode="after")
    def _interval_follows_from_the_counts(self) -> "Proportion":
        if self.denominator == 0:
            if self.numerator or self.estimate is not None or self.low is not None:
                raise ValueError("an empty denominator has no estimate and no interval")
            return self
        if self.numerator > self.denominator:
            raise ValueError("the numerator is at most the denominator")
        if self.estimate is None or self.low is None or self.high is None:
            raise ValueError("a proportion with trials carries its estimate and interval")
        low, high = wilson(self.numerator, self.denominator)
        if not (
            math.isclose(self.estimate, self.numerator / self.denominator)
            and math.isclose(self.low, low)
            and math.isclose(self.high, high)
        ):
            raise ValueError("the estimate and interval do not follow from the counts")
        return self
