"""Day 18: findings view over the real CASE01 pipeline and engine output."""

import copy
import hashlib
import json
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from src import ui_data, ui_findings
from src.correlation import CorrelationEngine
from src.pipeline import run_pipeline
from src.schema import ForensicEvent
from src.storage import TimelineStore

ROOT = Path(__file__).resolve().parent.parent
CANDIDATES = {
    "C1": (("CASE01-SB0133", "CASE01-JL0022"), ["R01", "R02", "R03"]),
    "C2": (("CASE01-SB0147", "CASE01-JL0020"), ["R01", "R02", "R03"]),
    "C5": (("CASE01-PF0173", "CASE01-LNK0037"), ["R01", "R03", "R04"]),
}


@pytest.fixture(scope="module")
def case01(tmp_path_factory):
    root = tmp_path_factory.mktemp("findings")
    run_pipeline(
        input_file=str(ROOT / "analysis/phuc-artifacts/case01_supporting_events.csv"),
        shellbags_file=str(ROOT / "results/case01_shellbags_events.csv"),
        case_id="CASE01", source_label="case01-supporting-tools", case_output_dir=str(root),
        output_file="normalized.json", database_file="timeline.db", findings_file="findings.json",
    )
    return str(root / "CASE01/timeline.db"), str(root / "CASE01/findings.json")


@pytest.fixture(scope="module")
def loaded(case01):
    findings, _ = ui_data.load_findings(case01[1], ["CASE01"])
    return findings, ui_findings.load_event_index(case01[0], findings)


def search(loaded, text="", sort="File order", **kwargs):
    criteria = ui_findings.FindingFilter(text=text, **kwargs)
    return ui_findings.select_findings(*loaded, criteria, sort)


def open_app(database, findings, text=None):
    app = AppTest.from_file(str(ROOT / "src/app.py"), default_timeout=60)
    app.session_state["database"] = str(database)
    app.session_state["findings"] = str(findings)
    app.run()
    if text is not None:
        app.text_input(key="finding_text").input(text).run()
    assert not app.exception
    return app


def values(elements):
    return [element.value for element in elements]


def test_every_engine_finding_links_to_its_source_events(loaded):
    findings, index = loaded
    assert findings
    assert all(ui_findings.problems(finding, index) == [] for finding in findings)


def test_engine_output_is_all_candidates(loaded):
    findings, _ = loaded
    assert {ui_findings.review_status(finding) for finding in findings} == {"Candidate"}
    assert any(finding["confidence_level"] == "HIGH" for finding in findings)


@pytest.mark.parametrize("name", CANDIDATES)
def test_reviewed_candidate_traces_to_events(loaded, name):
    ids, rules = CANDIDATES[name]
    (finding,) = search(loaded, " ".join(ids))
    assert set(ui_findings.event_ids(finding)) == set(ids)
    assert finding["matched_rules"] == rules
    events = ui_findings.linked_events(finding, loaded[1])
    assert {event.event_id for event in events} == set(ids)
    assert all(event.evidence_reference in finding["evidence_references"] for event in events)
    assert ui_findings.review_status(finding) == "Candidate"


@pytest.mark.parametrize("status, label", [
    (None, "Candidate"), ("", "Candidate"), ("unverified", "Candidate"),
    ("verified", "Validated"), ("disputed", "Unresolved"), ("synthetic", "Synthetic"),
    ("VERIFIED by score", "Unrecognized status"),
])
def test_review_status_only_follows_stored_value(status, label):
    finding = {"validation_status": status, "confidence_level": "HIGH", "confidence_score": 100}
    assert ui_findings.review_status(finding) == label


def test_row_shows_window_path_and_basis(loaded):
    (finding,) = search(loaded, "CASE01-SB0133 CASE01-JL0022")
    row = ui_findings.finding_row(finding, loaded[1])
    assert list(row) == ui_findings.FINDING_COLUMNS
    assert row["Time window (UTC)"] == "2015-03-23 20:24:15 to 20:26:53"
    assert row["Gap (s)"] == 158.0
    assert "secured_drive" in row["Path"]
    assert row["Evidence basis"] == "Interaction evidence"


def test_filters(loaded):
    everything = search(loaded)
    r04 = search(loaded, rules=("R04",))
    assert len(everything) == len(loaded[0])
    assert r04 and all("R04" in finding["matched_rules"] for finding in r04)
    assert search(loaded, rules=("R02", "R04")) == []
    assert search(loaded, statuses=("Validated",)) == []

    supported = search(loaded, exclude_limited=True)
    assert 0 < len(supported) < len(everything)
    for finding in supported:
        basis = ui_findings.finding_row(finding, loaded[1])["Evidence basis"]
        assert "Metadata only" not in basis and "Registry write" not in basis


def test_sort_orders(loaded):
    scores = [f["confidence_score"] for f in search(loaded, sort="Highest score")]
    gaps = [f["time_delta_seconds"] for f in search(loaded, sort="Shortest time gap")]
    assert scores == sorted(scores, reverse=True)
    assert gaps == sorted(gaps)
    with pytest.raises(ValueError):
        search(loaded, sort="unknown")


def test_problems_report_broken_links_and_references(loaded):
    findings, index = loaded
    finding = copy.deepcopy(findings[0])
    finding["event_ids"][0] = "CASE01-MISSING"
    assert any("CASE01-MISSING is not in this database" in p for p in ui_findings.problems(finding, index))

    other_case = {**findings[0], "case_id": "OTHER"}
    assert len([p for p in ui_findings.problems(other_case, index) if "case OTHER" in p]) == 2
    assert ui_findings.linked_events(other_case, index) == []

    changed = {**findings[0], "evidence_references": ["invented.csv:L1"]}
    assert any("differ" in p for p in ui_findings.problems(changed, index))

    text = " ".join(ui_findings.problems({}, {}))
    for expected in ("finding ID", "fewer than two", "matched rules", "evidence references"):
        assert expected in text


def test_ambiguous_event_id_is_not_silently_resolved():
    event = ForensicEvent("E1", "2026-01-01T00:00:00+00:00", "d", "EVTX", "s", "C:\\x", "m")
    finding = {"event_ids": ["E1"]}
    index = {(None, "E1"): [event, event]}
    assert ui_findings.linked_events(finding, index) == []
    assert any("matches 2 database records" in p for p in ui_findings.problems(finding, index))


@pytest.mark.parametrize("name", CANDIDATES)
def test_app_opens_candidate_and_source_event(case01, name):
    ids, rules = CANDIDATES[name]
    app = open_app(*case01, text=" ".join(ids))
    markdown = " ".join(values(app.markdown))
    assert "Showing findings **1–1** of **1**" in markdown
    assert "Candidate" in markdown and "Validated" not in markdown
    assert all(any(text.startswith(f"{rule}: ") for text in values(app.text)) for rule in rules)

    box = next(b for b in app.selectbox if b.label == "Source event to inspect")
    assert len(box.options) == 2
    for position in range(2):
        box = next(b for b in app.selectbox if b.label == "Source event to inspect")
        expected_id = box.options[position].split(" | ")[0]
        box.set_value(position).run()
        assert not app.exception
        assert expected_id in ids and expected_id in values(app.text)


def test_source_event_opens_outside_the_timeline_filter(case01):
    app = open_app(*case01, text="CASE01-SB0133 CASE01-JL0022")
    app.text_input(key="filter_keyword").input("nothing-matches-this")
    next(b for b in app.button if b.label == "Apply filters").click().run()
    assert "No events match these filters." in values(app.info)
    assert "CASE01-SB0133" in values(app.text)


def test_app_pages_and_resets_findings(case01):
    app = open_app(*case01)
    app.button(key="finding_next_page").click().run()
    assert any("findings **51–100**" in value for value in values(app.markdown))
    app.text_input(key="finding_text").input("nothing-matches-this").run()
    assert "No findings match these filters." in values(app.info)
    next(b for b in app.button if b.label == "Reset finding filters").click().run()
    assert not app.exception
    assert any("findings **1–50**" in value for value in values(app.markdown))


def test_rewritten_findings_file_is_not_served_from_cache(tmp_path, case01):
    path = tmp_path / "findings.json"
    example = json.loads((ROOT / "docs/examples/ui_findings.json").read_text(encoding="utf-8"))
    path.write_text(json.dumps(example), encoding="utf-8")
    app = open_app(case01[0], path)
    assert any("**1** Candidate" in value for value in values(app.markdown))
    example[0]["validation_status"] = "disputed"
    path.write_text(json.dumps(example), encoding="utf-8")
    app.run()
    assert any("**1** Unresolved" in value for value in values(app.markdown))


def test_malformed_findings_do_not_crash(tmp_path, case01):
    path = tmp_path / "findings.json"
    path.write_text(json.dumps([
        {"case_id": "CASE01", "matched_rules": None, "event_ids": None, "confidence_score": "x"},
        {"case_id": "CASE01", "finding_id": "F2", "event_ids": ["CASE01-SB0133", "GONE"]},
    ]), encoding="utf-8")
    app = open_app(case01[0], path, text="F2")
    assert any("GONE is not in this database" in value for value in values(app.warning))


def test_viewing_findings_changes_nothing(case01):
    before = [hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in case01]
    open_app(*case01, text="CASE01-SB0133")
    assert [hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in case01] == before


def test_engine_contract_still_uses_known_rules(case01):
    with TimelineStore(case01[0], read_only=True) as store:
        events = store.events_by_id(["CASE01-PF0173", "CASE01-LNK0037"])
    for finding in CorrelationEngine().correlate(events):
        assert set(finding.matched_rules) <= set(ui_findings.RULES)
