"""Keep the Day 15 UI contract examples equal to real pipeline output."""

import json
from dataclasses import fields
from pathlib import Path

import pytest

from src.correlation import CorrelationEngine
from src.normalizer import PlasoNormalizer, ShellBagsNormalizer
from src.schema import CorrelationFinding, ForensicEvent

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "docs" / "examples"


def load_example(name):
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def case01_events():
    supporting, errors = PlasoNormalizer.normalize_file_with_report(
        str(ROOT / "analysis/phuc-artifacts/case01_supporting_events.csv"),
        "case01-supporting-tools",
        case_id="CASE01",
    )
    shellbags, shellbag_errors = ShellBagsNormalizer.normalize_file_with_report(
        str(ROOT / "results/case01_shellbags_events.csv")
    )
    assert not errors and not shellbag_errors
    for event in shellbags:  # same label the pipeline applies
        event.extra_attributes.setdefault("source_label", "shellbags")
    return {event.event_id: event for event in supporting + shellbags}


def test_event_examples_match_pipeline_output(case01_events):
    for example in load_example("ui_events.json"):
        assert set(example) == {field.name for field in fields(ForensicEvent)}
        assert case01_events[example["event_id"]].to_dict() == example


def test_finding_example_matches_engine_output(case01_events):
    for example in load_example("ui_findings.json"):
        assert set(example) == {field.name for field in fields(CorrelationFinding)}
        pair = [case01_events[event_id] for event_id in example["event_ids"]]
        assert [f.to_dict() for f in CorrelationEngine().correlate(pair)] == [example]


def test_finding_example_references_existing_events():
    events = {(e["case_id"], e["event_id"]): e for e in load_example("ui_events.json")}
    for finding in load_example("ui_findings.json"):
        linked = [events[(finding["case_id"], event_id)] for event_id in finding["event_ids"]]
        assert finding["evidence_references"] == [e["evidence_reference"] for e in linked]


def test_new_engine_finding_is_not_verified():
    findings = load_example("ui_findings.json")
    assert findings
    assert all(
        f["validation_status"] == "unverified"
        for f in findings
    )


def test_reference_text_is_not_the_validation_status():
    """A reference may say 'verified:' while the event itself is unverified."""
    events = {e["event_id"]: e for e in load_example("ui_events.json")}
    metadata_event = events["CASE01-SB0031"]
    assert "verified:" in metadata_event["evidence_reference"]
    assert metadata_event["validation_status"] == "unverified"
    assert metadata_event["extra_attributes"]["semantic_class"] == "target_metadata"


def test_case01_classes_are_covered_by_the_contract(case01_events):
    contract = (ROOT / "docs/week3_schema_ui_contract.md").read_text(encoding="utf-8")
    for key in ("semantic_class", "semantic_basis", "fs_path_basis"):
        values = {e.extra_attributes.get(key) for e in case01_events.values()} - {None, ""}
        assert values
        assert all(f"`{value}`" in contract for value in values), (key, values)
