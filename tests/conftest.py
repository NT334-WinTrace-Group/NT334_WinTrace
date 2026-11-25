from pathlib import Path

import pytest

from src.pipeline import run_pipeline

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def case01_pipeline(tmp_path_factory):
    """Run the real CASE01 pipeline once; correlating every pair is slow."""
    root = tmp_path_factory.mktemp("case01-pipeline")
    run_pipeline(
        input_file=str(ROOT / "analysis/phuc-artifacts/case01_supporting_events.csv"),
        shellbags_file=str(ROOT / "results/case01_shellbags_events.csv"),
        case_id="CASE01", source_label="case01-supporting-tools", case_output_dir=str(root),
        output_file="normalized.json", database_file="timeline.db", findings_file="findings.json",
    )
    return str(root / "CASE01/timeline.db"), str(root / "CASE01/findings.json")
