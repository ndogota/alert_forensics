"""Shared base classes and constrained types for the project's own contracts."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


class ContractModel(BaseModel):
    """Base for contracts we own. A field we did not declare is a bug, not data."""

    model_config = ConfigDict(frozen=True, extra="forbid")


NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
"""A string that still has content after stripping whitespace."""

StrictNonNegativeInt = Annotated[int, Field(strict=True, ge=0)]
"""An integer, never coerced from a float, zero or greater. Used for every count and duration."""
