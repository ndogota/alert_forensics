"""Scopes, roles, principals, and the check that produces a denial rather than raising."""

from typing import Any, Literal

from pydantic import field_validator

from alert_forensics.contracts._base import ContractModel, NonEmptyStr
from alert_forensics.tools.adapter import ToolDefinition

ALL_SCOPES: frozenset[str] = frozenset(
    {
        "hunting:read",
        "siem:search",
        "identity:read",
        "asset:read",
        "ioc:lookup",
        "alerts:read",
        "runbook:read",
        "attack:read",
    }
)
"""Every scope a tool may declare. A role holding a scope outside this set is a typo."""


class Role(ContractModel):
    name: NonEmptyStr
    scopes: frozenset[str]

    @field_validator("scopes")
    @classmethod
    def _known_scopes(cls, scopes: frozenset[str]) -> frozenset[str]:
        unknown = sorted(scopes - ALL_SCOPES)
        if unknown:
            raise ValueError(f"unknown scopes: {unknown}")
        return scopes


ANALYST_ROLE = Role(name="analyst", scopes=ALL_SCOPES)
"""The role the agent runs under by default: every read scope."""

TIER1_ROLE = Role(name="tier1", scopes=ALL_SCOPES - {"siem:search"})
"""A genuinely restricted role: raw SPL search is commonly gated above tier one."""


class Principal(ContractModel):
    """Who a call is made as. ``name`` is journalled as the record's caller."""

    name: NonEmptyStr
    role: Role

    @property
    def scopes(self) -> frozenset[str]:
        return self.role.scopes


class ScopeDenial(ContractModel):
    """What the model receives when a call is outside the principal's scope.

    It names the missing scope and the role, never the scopes the role does hold.
    """

    error: Literal["scope_denied"] = "scope_denied"
    tool: str
    required_scope: str
    caller: str
    role: str
    message: str


def check_scope(
    principal: Principal, definition: ToolDefinition[Any, Any, Any]
) -> ScopeDenial | None:
    """Return a denial when the principal lacks the tool's scope, else None. Never raises."""
    if definition.required_scope in principal.scopes:
        return None
    return ScopeDenial(
        tool=definition.name,
        required_scope=definition.required_scope,
        caller=principal.name,
        role=principal.role.name,
        message=(
            f"{definition.name} requires scope {definition.required_scope}, which role "
            f"{principal.role.name} does not hold. The call was not made. Record what it "
            "would have established as missing context and how an analyst with that scope "
            "obtains it."
        ),
    )
