"""The harness: run cells, keep every artifact, derive the summary.

One directory per run under ``DIR/<model>/<role>/<scenario>/<k>/``: ``run.json``, the
artifact ``triage`` would have written; ``run.raw/``, its raw store; ``eval.json``, the
harness's measurement; ``score.json``, the derived score. ``summary.json`` at the top is
derived from whatever run directories are there and can be recomputed at any time.
``campaign.json`` at the top names the fixture revision every run under it was handed:
a directory is one campaign, and a campaign is one fixture revision.
"""

import re
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from langchain_core.language_models.chat_models import BaseChatModel
from pydantic import AwareDatetime, ValidationError

from alert_forensics.agent.run import AnalystDecision, run_triage
from alert_forensics.artifact import RunArtifact
from alert_forensics.contracts import Alert, ModelLimits
from alert_forensics.contracts._base import ContractModel, NonEmptyStr
from alert_forensics.evaluation.prices import PRICES, Price
from alert_forensics.evaluation.scoring import RunScore, score_run
from alert_forensics.evaluation.summary import (
    RunMeasurement,
    ScoredRun,
    Summary,
    summarise,
)
from alert_forensics.evaluation.truth import Scenario
from alert_forensics.tools.fixtures import fixture_digest
from alert_forensics.tools.runner import AnyAdapter
from alert_forensics.tools.scope import Principal, Role
from alert_forensics.tools.store import DirectoryRawStore

RUN_FILE = "run.json"
RAW_DIR = "run.raw"
MEASUREMENT_FILE = "eval.json"
SCORE_FILE = "score.json"
SUMMARY_FILE = "summary.json"
CAMPAIGN_FILE = "campaign.json"

ModelFactory = Callable[[Alert], BaseChatModel]
"""A model per run: the scripted client carries a cursor and a script derived from the
alert, so it is built per run; a provider client is reused."""


class HarnessError(Exception):
    """A results directory that cannot be read as runs, or written into as a campaign."""


class Campaign(ContractModel):
    """What a results directory is: one fixture revision, recorded when the first run
    was made into it. Every later run must be handed the same fixtures."""

    fixture_digest: NonEmptyStr
    fixtures: NonEmptyStr
    """The fixture directory as it was given, for a reader; the digest is the identity."""
    started_at: AwareDatetime


def open_campaign(results_dir: Path, fixtures_dir: Path) -> Campaign:
    """The campaign a run may be made into, checked before any run. A directory with a
    ``campaign.json`` must name the same fixture revision; a directory holding runs and
    no ``campaign.json`` predates the rule and cannot say what its runs were handed, so
    it is refused; an empty or absent directory starts a campaign."""
    digest = fixture_digest(fixtures_dir)
    path = results_dir / CAMPAIGN_FILE
    if path.exists():
        try:
            campaign = Campaign.model_validate_json(path.read_text("utf-8"))
        except (OSError, ValidationError) as exc:
            raise HarnessError(f"{path} cannot be read as a campaign: {exc}") from exc
        if campaign.fixture_digest != digest:
            raise HarnessError(
                f"{results_dir} is a campaign under fixtures {campaign.fixture_digest}; the "
                f"fixtures given are {digest}. A campaign is one fixture revision: name "
                "another --results directory for these fixtures"
            )
        return campaign
    if any(results_dir.rglob(MEASUREMENT_FILE)):
        raise HarnessError(
            f"{results_dir} holds runs and no {CAMPAIGN_FILE}: a campaign from before "
            "fixtures were versioned, which cannot say what its runs were handed. It can "
            "be re-scored with eval-report; name another --results directory for new runs"
        )
    campaign = Campaign(
        fixture_digest=digest, fixtures=str(fixtures_dir), started_at=datetime.now(UTC)
    )
    results_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(campaign.model_dump_json(indent=2), encoding="utf-8")
    return campaign


def model_slug(model_id: str) -> str:
    """The model string as a directory name: every character a path cannot carry
    becomes a hyphen."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", model_id).strip("-") or "model"


def _accept(proposal: object) -> AnalystDecision:
    return AnalystDecision(accept=True)


def run_suite(
    *,
    scenarios: Sequence[Scenario],
    model_factory: ModelFactory,
    model_id: str,
    role: Role,
    adapters: Callable[[Alert], Iterable[AnyAdapter]],
    fixtures_dir: Path,
    results_dir: Path,
    runs: int,
    max_corrections: int = 1,
    recursion_limit: int = 50,
    model_limits: ModelLimits | None = None,
    on_run: Callable[[RunMeasurement, RunScore], None] | None = None,
) -> list[Path]:
    """Run every scenario ``runs`` times and write a directory per run. Indices continue
    from what the cell already holds, so a second invocation adds runs rather than
    overwriting them, within one fixture revision: the directory is a campaign, opened
    before any run, and ``fixtures_dir`` must be the revision it records. ``adapters``
    is called with each run's alert, so fixture adapters are bound to the scenario
    under investigation. Every proposal is accepted: the human decision is not what
    the harness measures."""
    if runs < 1:
        raise ValueError("runs is one or more")
    campaign = open_campaign(results_dir, fixtures_dir)
    written: list[Path] = []
    for scenario in scenarios:
        cell_dir = results_dir / model_slug(model_id) / role.name / scenario.name
        start = _next_index(cell_dir)
        for k in range(start, start + runs):
            run_dir = cell_dir / str(k)
            run_dir.mkdir(parents=True, exist_ok=False)
            started_at = datetime.now(UTC)
            clock = time.perf_counter()
            artifact = run_triage(
                alert=scenario.alert,
                model=model_factory(scenario.alert),
                model_id=model_id,
                principal=Principal(name=role.name, role=role),
                adapters=adapters(scenario.alert),
                store=DirectoryRawStore(run_dir / RAW_DIR),
                raw_store=RAW_DIR,
                decide=_accept,
                max_corrections=max_corrections,
                recursion_limit=recursion_limit,
                model_limits=model_limits,
            )
            wall = time.perf_counter() - clock
            measurement = RunMeasurement(
                scenario=scenario.name,
                model=model_id,
                role=role.name,
                index=k,
                started_at=started_at,
                wall_clock_s=wall,
                fixture_digest=campaign.fixture_digest,
            )
            score = score_run(artifact, scenario.truth)
            (run_dir / RUN_FILE).write_text(artifact.model_dump_json(indent=2), encoding="utf-8")
            (run_dir / MEASUREMENT_FILE).write_text(
                measurement.model_dump_json(indent=2), encoding="utf-8"
            )
            (run_dir / SCORE_FILE).write_text(score.model_dump_json(indent=2), encoding="utf-8")
            written.append(run_dir)
            if on_run is not None:
                on_run(measurement, score)
    return written


def _next_index(cell_dir: Path) -> int:
    if not cell_dir.is_dir():
        return 0
    taken = [int(p.name) for p in cell_dir.iterdir() if p.is_dir() and p.name.isdigit()]
    return max(taken, default=-1) + 1


def collect(results_dir: Path, scenarios: Sequence[Scenario]) -> list[ScoredRun]:
    """Every run under ``results_dir``, re-scored from its artifact and the current ground
    truth; ``score.json`` is rewritten to match. The runs, and the ``campaign.json`` if
    there is one, must name one fixture revision between them: a directory assembled
    from two campaigns is refused rather than pooled. A run without a digest predates
    the rule and is not held against the others."""
    truths = {s.name: s.truth for s in scenarios}
    runs: list[ScoredRun] = []
    digests: set[str] = set()
    campaign_path = results_dir / CAMPAIGN_FILE
    if campaign_path.exists():
        try:
            digests.add(
                Campaign.model_validate_json(campaign_path.read_text("utf-8")).fixture_digest
            )
        except (OSError, ValidationError) as exc:
            raise HarnessError(f"{campaign_path} cannot be read as a campaign: {exc}") from exc
    for measurement_path in sorted(results_dir.rglob(MEASUREMENT_FILE)):
        run_dir = measurement_path.parent
        try:
            measurement = RunMeasurement.model_validate_json(measurement_path.read_text("utf-8"))
            artifact = RunArtifact.model_validate_json((run_dir / RUN_FILE).read_text("utf-8"))
        except OSError as exc:
            raise HarnessError(f"cannot read the run under {run_dir}: {exc.strerror}") from exc
        except ValidationError as exc:
            raise HarnessError(f"the run under {run_dir} does not validate: {exc}") from exc
        truth = truths.get(measurement.scenario)
        if truth is None:
            raise HarnessError(
                f"the run under {run_dir} is of scenario {measurement.scenario!r}, which has "
                "no ground truth among the scenarios given"
            )
        try:
            score = score_run(artifact, truth)
        except ValueError as exc:
            raise HarnessError(f"the run under {run_dir} cannot be scored: {exc}") from exc
        (run_dir / SCORE_FILE).write_text(score.model_dump_json(indent=2), encoding="utf-8")
        runs.append(ScoredRun(measurement=measurement, score=score, usage=artifact.trace.usage))
        if measurement.fixture_digest is not None:
            digests.add(measurement.fixture_digest)
    if len(digests) > 1:
        raise HarnessError(
            f"the runs under {results_dir} were handed more than one fixture revision and "
            "are not one campaign: " + ", ".join(sorted(digests))
        )
    return runs


def report(
    results_dir: Path, scenarios: Sequence[Scenario], *, prices: Mapping[str, Price] = PRICES
) -> Summary:
    """Recompute ``summary.json`` from the run directories and return it."""
    runs = collect(results_dir, scenarios)
    if not runs:
        raise HarnessError(f"no run under {results_dir}")
    try:
        summary = summarise(runs, prices=prices)
    except ValueError as exc:
        raise HarnessError(str(exc)) from exc
    (results_dir / SUMMARY_FILE).write_text(summary.model_dump_json(indent=2), encoding="utf-8")
    return summary
