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


_ANTHROPIC_PRICING = "https://platform.claude.com/docs/en/about-claude/pricing"
_OPENAI_PRICING = "https://developers.openai.com/api/docs/pricing"
PRICED_ON = "2026-09-15"
"""The day the OpenAI and Anthropic pages were read. Neither page carries a date of its
own, so the read date is the only date a row can name."""


def _anthropic(input_per_mtok: float, output_per_mtok: float, cache_write_5m: float) -> Price:
    """A row from the Claude pricing page. Cache reads are 0.1x the input rate on these
    models and the five-minute cache write is 1.25x; both are read from the page, not
    derived. Writes are priced at the five-minute rate, the default TTL, so a one-hour
    write, 2x, is under-priced. Not exercised: the client zeroes ``cache_creation`` when
    the response carries the per-TTL breakdown and files the counts under keys the usage
    record does not read, so a write would reach the cost as fresh input; the harness
    sets no ``cache_control``, so no write occurs on its runs."""
    return Price(
        input_per_mtok=input_per_mtok,
        output_per_mtok=output_per_mtok,
        cache_read_per_mtok=input_per_mtok * 0.1,
        cache_write_per_mtok=cache_write_5m,
        source=(
            f"Claude pricing page, {_ANTHROPIC_PRICING}, read {PRICED_ON}; the page carries "
            "no date; base input, five-minute cache write, cache read and output as printed; "
            "cache writes are priced at the five-minute rate, the default TTL, so a one-hour "
            "write at 2x is under-priced by this row"
        ),
        as_of=PRICED_ON,
    )


def _openai(input_per_mtok: float, cached_input_per_mtok: float, output_per_mtok: float) -> Price:
    """A row from the OpenAI pricing page, standard tier. The cache-write column reads a
    dash for these models: the prompt-caching guide bills writes only from GPT-5.6 on and
    says there is no additional cache-write charge before it, so writes are priced at
    zero. Caching is automatic on that API and the client reports cached tokens as
    ``cache_read``; output includes reasoning tokens."""
    return Price(
        input_per_mtok=input_per_mtok,
        output_per_mtok=output_per_mtok,
        cache_read_per_mtok=cached_input_per_mtok,
        cache_write_per_mtok=0.0,
        source=(
            f"OpenAI pricing page, {_OPENAI_PRICING}, standard tier, read {PRICED_ON}; the "
            "page carries no date; input, cached input and output as printed; the cache-write "
            "column is a dash for this model and the prompt-caching guide says there is no "
            "additional cache-write charge before GPT-5.6, so writes are priced at zero; "
            "output includes reasoning tokens; flex and batch tiers are cheaper and are not "
            "the tier the harness calls"
        ),
        as_of=PRICED_ON,
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
    "openai:gpt-5-nano": _openai(0.05, 0.005, 0.40),
    "openai:gpt-5-mini": _openai(0.25, 0.025, 2.00),
    "anthropic:claude-haiku-4-5": _anthropic(1.0, 5.0, 1.25),
    "anthropic:claude-sonnet-5": _anthropic(2.0, 10.0, 2.50),
    "anthropic:claude-opus-5": _anthropic(5.0, 25.0, 6.25),
    "google_genai:gemini-3.5-flash-lite": Price(
        input_per_mtok=0.30,
        output_per_mtok=2.50,
        cache_read_per_mtok=0.03,
        cache_write_per_mtok=0.30,
        source=(
            "Gemini API pricing, https://ai.google.dev/gemini-api/docs/pricing, paid tier, "
            "page dated 2026-09-11, read 2026-09-15; output includes thinking tokens; cache "
            "writes are ordinary input at the input rate, and the storage charge of 1.00 USD "
            "per million tokens per hour is not per token and is not carried; the free tier "
            "bills nothing, so a free-tier run's cost is what its tokens would cost billed"
        ),
        as_of="2026-09-15",
    ),
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
