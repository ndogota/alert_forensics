import pytest
from pydantic import ValidationError

from alert_forensics.tools import (
    ALL_SCOPES,
    ANALYST_ROLE,
    DEFINITIONS,
    TIER1_ROLE,
    Principal,
    Role,
    ScopeDenial,
    check_scope,
)


def test_every_tool_declares_a_scope_and_the_analyst_holds_all_of_them():
    declared = {d.required_scope for d in DEFINITIONS.values()}
    assert declared == ALL_SCOPES
    assert ANALYST_ROLE.scopes == ALL_SCOPES
    assert ANALYST_ROLE.name == "analyst"


def test_tier1_lacks_raw_siem_search_and_the_write_scope():
    assert ALL_SCOPES - TIER1_ROLE.scopes == {"siem:search", "alerts:write"}
    assert DEFINITIONS["search_siem"].required_scope == "siem:search"
    assert DEFINITIONS["propose_alert_disposition"].required_scope == "alerts:write"
    assert "alerts:write" in ANALYST_ROLE.scopes


def test_check_scope_returns_a_denial_rather_than_raising():
    tier1 = Principal(name="t1-oncall", role=TIER1_ROLE)
    denial = check_scope(tier1, DEFINITIONS["search_siem"])
    assert isinstance(denial, ScopeDenial)
    assert denial.error == "scope_denied"
    assert denial.tool == "search_siem"
    assert denial.required_scope == "siem:search"
    assert denial.caller == "t1-oncall"
    assert denial.role == "tier1"
    assert "siem:search" in denial.message and "tier1" in denial.message
    # A denial is JSON the model can read; it never leaks the scopes the role does hold.
    dumped = denial.model_dump(mode="json")
    assert set(dumped) == {"error", "tool", "required_scope", "caller", "role", "message"}


def test_check_scope_passes_when_the_scope_is_held():
    analyst = Principal(name="analyst", role=ANALYST_ROLE)
    assert check_scope(analyst, DEFINITIONS["search_siem"]) is None
    tier1 = Principal(name="t1", role=TIER1_ROLE)
    gated = {"search_siem", "propose_alert_disposition"}
    assert all(check_scope(tier1, d) is None for n, d in DEFINITIONS.items() if n not in gated)
    assert check_scope(tier1, DEFINITIONS["propose_alert_disposition"]) is not None


def test_roles_are_closed_values():
    with pytest.raises(ValidationError):
        Role(name="", scopes=frozenset({"hunting:read"}))
    with pytest.raises(ValidationError):
        Role(name="custom", scopes=frozenset({"hunting:read", "not:a:scope"}))
    custom = Role(name="custom", scopes=frozenset({"hunting:read"}))
    assert custom.scopes == frozenset({"hunting:read"})
