"""``get_attack_technique``: ATT&CK STIX bundle, resolved deterministically by external id."""

import re
from typing import Literal

from pydantic import Field

from alert_forensics.contracts import MitreTechniqueId, SourceSystem
from alert_forensics.tools.adapter import (
    LiveContract,
    ToolDefinition,
    ToolRequest,
    ToolResponse,
    ToolView,
)

_CITATION = re.compile(r"\s*\(Citation:[^)]*\)")


class GetAttackTechniqueRequest(ToolRequest):
    technique_id: MitreTechniqueId = Field(description="T#### or T####.###")


class ExternalReference(ToolResponse):
    source_name: str
    external_id: str | None = None
    url: str | None = None


class KillChainPhase(ToolResponse):
    kill_chain_name: str
    phase_name: str


class AttackPattern(ToolResponse):
    """A STIX 2.1 ``attack-pattern`` with the ATT&CK extensions the view uses."""

    type: Literal["attack-pattern"]
    id: str
    name: str
    description: str = ""
    external_references: list[ExternalReference] = Field(default_factory=list)
    kill_chain_phases: list[KillChainPhase] = Field(default_factory=list)
    revoked: bool = False
    x_mitre_deprecated: bool = False
    x_mitre_is_subtechnique: bool = False
    x_mitre_platforms: list[str] = Field(default_factory=list)
    x_mitre_version: str | None = None

    def attack_reference(self) -> ExternalReference | None:
        return next((r for r in self.external_references if r.source_name == "mitre-attack"), None)


class AttackTechniqueResponse(ToolResponse):
    """The technique, plus the object that replaces it when it has been revoked."""

    technique: AttackPattern
    superseded_by: AttackPattern | None = None


class SupersededBy(ToolView):
    technique_id: str | None
    name: str


class AttackTechniqueView(ToolView):
    technique_id: str | None
    name: str
    url: str | None
    tactics: list[str]
    is_subtechnique: bool
    platforms: list[str]
    description: str
    version: str | None
    revoked: bool
    deprecated: bool
    superseded_by: SupersededBy | None


def strip_citations(text: str) -> str:
    return _CITATION.sub("", text).strip()


def _project(
    response: AttackTechniqueResponse, request: GetAttackTechniqueRequest | None
) -> AttackTechniqueView:
    technique = response.technique
    reference = technique.attack_reference()
    superseded = None
    if response.superseded_by is not None:
        replacement_ref = response.superseded_by.attack_reference()
        superseded = SupersededBy(
            technique_id=replacement_ref.external_id if replacement_ref else None,
            name=response.superseded_by.name,
        )
    return AttackTechniqueView(
        technique_id=reference.external_id if reference else None,
        name=technique.name,
        url=reference.url if reference else None,
        tactics=[
            p.phase_name for p in technique.kill_chain_phases if p.kill_chain_name == "mitre-attack"
        ],
        is_subtechnique=technique.x_mitre_is_subtechnique,
        platforms=list(technique.x_mitre_platforms),
        description=strip_citations(technique.description),
        version=technique.x_mitre_version,
        revoked=technique.revoked,
        deprecated=technique.x_mitre_deprecated,
        superseded_by=superseded,
    )


GET_ATTACK_TECHNIQUE = ToolDefinition(
    name="get_attack_technique",
    description=(
        "Resolve an ATT&CK technique id such as T1110.003 to its name, tactics, platforms "
        "and description from the official STIX bundle. Deterministic, never guessed."
    ),
    source_system=SourceSystem.attack,
    required_scope="attack:read",
    request_model=GetAttackTechniqueRequest,
    response_model=AttackTechniqueResponse,
    view_model=AttackTechniqueView,
    projector=_project,
    live=LiveContract(
        status="live",
        system="MITRE ATT&CK, enterprise STIX 2.1 bundle",
        endpoint=(
            "GET https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
            "enterprise-attack/enterprise-attack.json"
        ),
        auth="none",
        permission="none; the bundle is public",
        notes=(
            "The bundle is around 50 MB and is cached on disk after the first download. "
            "Lookup is by external_references[source_name == mitre-attack].external_id."
        ),
    ),
)
