"""Wilson intervals, in code, on every proportion."""

import math

import pytest

from alert_forensics.evaluation import Proportion, wilson


@pytest.mark.parametrize(
    ("k", "n", "low", "high"),
    [
        (0, 3, 0.0, 0.5615),
        (3, 3, 0.4385, 1.0),
        (1, 2, 0.0945, 0.9055),
        (50, 100, 0.4038, 0.5962),
        (0, 1, 0.0, 0.7935),
        (1, 1, 0.2065, 1.0),
    ],
)
def test_wilson_matches_the_textbook_values(k, n, low, high):
    got_low, got_high = wilson(k, n)
    assert math.isclose(got_low, low, abs_tol=5e-4)
    assert math.isclose(got_high, high, abs_tol=5e-4)


def test_wilson_is_never_the_normal_interval():
    # 0 of 3: the normal interval is [0, 0], which says nothing; Wilson says up to 0.56.
    _, high = wilson(0, 3)
    assert high > 0.5


def test_wilson_refuses_an_empty_or_impossible_count():
    with pytest.raises(ValueError):
        wilson(0, 0)
    with pytest.raises(ValueError):
        wilson(4, 3)
    with pytest.raises(ValueError):
        wilson(-1, 3)


def test_a_proportion_always_carries_its_interval():
    p = Proportion.of(2, 3)
    assert p.numerator == 2 and p.denominator == 3
    assert p.estimate == pytest.approx(2 / 3)
    assert p.low is not None and p.high is not None and p.low < p.estimate < p.high
    text = p.render()
    assert "2/3" in text and "0.67" in text and "[" in text and "]" in text
    assert p.model_dump()["low"] == pytest.approx(wilson(2, 3)[0])


def test_an_empty_denominator_is_absent_not_zero():
    p = Proportion.of(0, 0)
    assert p.estimate is None and p.low is None and p.high is None
    assert "n/a" in p.render()
    assert "0/0" in p.render()
