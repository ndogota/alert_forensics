"""``reports/model-matrix.json``, the committed view of a campaign: it validates against
the matrix contract, every model in it is priced, and no model judges it."""

import re
from pathlib import Path

from alert_forensics.evaluation import PRICES, Matrix

REPORTS = Path("reports")
MATRIX = REPORTS / "model-matrix.json"


def test_the_committed_matrix_validates_and_names_no_judge():
    matrix = Matrix.model_validate_json(MATRIX.read_text())
    assert matrix.metadata.judge_model is None
    assert matrix.cells and matrix.by_model
    assert matrix.metadata.fixture_digest is not None
    assert re.fullmatch(r"[0-9a-f]{64}", matrix.metadata.fixture_digest)
    assert matrix.metadata.campaign_started_at is not None


def test_every_model_in_the_committed_matrix_is_priced():
    matrix = Matrix.model_validate_json(MATRIX.read_text())
    for model in matrix.metadata.models:
        assert model in PRICES, f"{model} has no price row"
    for cell in matrix.cells:
        assert cell.cost_usd is not None, f"{cell.model} on {cell.scenario} is unpriced"


def test_the_readme_says_how_to_regenerate_it():
    readme = (REPORTS / "README.md").read_text()
    assert "alert-forensics matrix" in readme
    assert "-o reports/model-matrix.json" in readme
