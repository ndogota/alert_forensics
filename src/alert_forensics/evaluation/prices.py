"""The price table, and cost derived from usage at report time.

No contract carries money. A ``ModelUsageRecord`` carries tokens; the price lives here,
keyed by the ``provider:model`` string, with the source and date of each row, so a price
change never rewrites an artifact. A model absent from the table has no cost, and the
report says so rather than printing zero.
"""

from collections.abc import Mapping, Sequence

from pydantic import Field

from alert_forensics.contracts import ModelUsageRecord
from alert_forensics.contracts._base import ContractModel, NonEmptyStr


class Price(ContractModel):
    """US dollars per million tokens, per token class."""

    input_per_mtok: float = Field(ge=0)
    output_per_mtok: float = Field(ge=0)
    cache_read_per_mtok: float = Field(ge=0)
    cache_write_per_mtok: float = Field(ge=0)
    source: NonEmptyStr
    as_of: NonEmptyStr
    """The date the price was read, ISO 8601."""


_ANTHROPIC_SOURCE = (
    "Anthropic first-party API pricing as cached in the claude-api reference on "
    "2026-06-24; cache reads at 0.1x and five-minute cache writes at 1.25x the input rate"
)


def _anthropic(input_per_mtok: float, output_per_mtok: float) -> Price:
    return Price(
        input_per_mtok=input_per_mtok,
        output_per_mtok=output_per_mtok,
        cache_read_per_mtok=input_per_mtok * 0.1,
        cache_write_per_mtok=input_per_mtok * 1.25,
        source=_ANTHROPIC_SOURCE,
        as_of="2026-06-24",
    )


PRICES: dict[str, Price] = {
    "scripted:demo": Price(
        input_per_mtok=0.0,
        output_per_mtok=0.0,
        cache_read_per_mtok=0.0,
        cache_write_per_mtok=0.0,
        source="the scripted client makes no model call; its usage is synthetic",
        as_of="2026-09-14",
    ),
    "anthropic:claude-opus-5": _anthropic(5.0, 25.0),
    "anthropic:claude-sonnet-5": _anthropic(2.0, 10.0),
    "anthropic:claude-haiku-4-5": _anthropic(1.0, 5.0),
}
"""Keyed by the ``provider:model`` string a run was started with. Extend it here; a
model that is missing is reported as unpriced, never as free."""


def unpriced_models(
    usage: Sequence[ModelUsageRecord], prices: Mapping[str, Price] = PRICES
) -> list[str]:
    return sorted({record.model for record in usage if record.model not in prices})


def cost_usd(
    usage: Sequence[ModelUsageRecord], prices: Mapping[str, Price] = PRICES
) -> float | None:
    """The cost of the model turns in ``usage``, or None when any turn's model has no
    price. ``input_tokens`` is the whole input, of which ``cache_read`` and
    ``cache_creation`` are the parts served from and written to the cache; the rest is
    billed at the input rate."""
    total = 0.0
    for record in usage:
        price = prices.get(record.model)
        if price is None:
            return None
        cache_read = record.input_token_details.cache_read
        cache_write = record.input_token_details.cache_creation
        fresh = max(record.input_tokens - cache_read - cache_write, 0)
        total += (
            fresh * price.input_per_mtok
            + cache_read * price.cache_read_per_mtok
            + cache_write * price.cache_write_per_mtok
            + record.output_tokens * price.output_per_mtok
        ) / 1_000_000
    return total
