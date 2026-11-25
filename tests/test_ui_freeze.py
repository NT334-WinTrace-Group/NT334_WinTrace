"""Day 21: evidence protection, schema migration and validation status freeze."""

import hashlib
import os
from pathlib import Path
import shutil
import sqlite3

import pytest
from streamlit.testing.v1 import AppTest

from src import ui_data, ui_findings
from src.pipeline import PipelineInputError, run_pipeline
from src.report_generator import ReportGenerator
from src.schema import VALID_VALIDATION_STATUSES, ForensicEvent
from src.storage import TimelineStore
from src.ui_export import EVENT_FIELDS, export_event, read_csv, events_to_csv

ROOT = Path(__file__).resolve().parent.parent


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def open_app(database, findings="missing.json"):
    app = AppTest.from_file(str(ROOT / "src/app.py"), default_timeout=60)
    app.session_state["database"] = str(database)
    app.session_state["findings"] = str(findings)
    app.run()
    assert not app.exception
    return app


@pytest.mark.parametrize("role", ["output_file", "database_file", "findings_file", "error_log"])
@pytest.mark.parametrize("source", ["input", "shellbags"])
def test_pipeline_refuses_to_overwrite_its_inputs(tmp_path, role, source):
    files = {
        "input": tmp_path / "events.csv", "shellbags": tmp_path / "shellbags.csv",
    }
    shutil.copy(ROOT / "analysis/phuc-artifacts/case01_supporting_events.csv", files["input"])
    shutil.copy(ROOT / "results/case01_shellbags_events.csv", files["shellbags"])
    before = {name: digest(path) for name, path in files.items()}
    arguments = {"output_file": str(tmp_path / "out.json"), role: str(files[source])}
    with pytest.raises(PipelineInputError, match="overwrite the input"):
        run_pipeline(
            input_file=str(files["input"]), shellbags_file=str(files["shellbags"]), **arguments
        )
    assert {name: digest(path) for name, path in files.items()} == before
    assert not (tmp_path / "out.json").exists()


def test_pipeline_refuses_a_hard_link_to_its_input(tmp_path):
    source, link = tmp_path / "events.csv", tmp_path / "link.json"
    shutil.copy(ROOT / "results/plaso_raw_output.csv", source)
    try:
        os.link(source, link)
    except OSError:
        pytest.skip("hard links are not available")
    with pytest.raises(PipelineInputError, match="overwrite the input"):
        run_pipeline(input_file=str(source), output_file=str(link))


def test_full_ui_session_changes_no_source_file(case01_pipeline):
    before = [digest(path) for path in case01_pipeline]
    app = open_app(*case01_pipeline)
    app.text_input(key="filter_keyword").input("SB0133")
    for label in ("Apply filters", "Prepare export", "Reset filters"):
        next(button for button in app.button if button.label == label).click().run()
        assert not app.exception
    assert [digest(path) for path in case01_pipeline] == before
    assert sorted(p.name for p in Path(case01_pipeline[0]).parent.iterdir()) == [
        "findings.json", "normalized.json", "timeline.db"]


def test_legacy_database_is_untouched_by_the_ui_and_usable_after_migration(tmp_path):
    path = tmp_path / "legacy.db"
    with TimelineStore(str(path)) as store:
        store.insert_events([ForensicEvent(
            "E1", "2026-01-01T00:00:00+00:00", "d", "EVTX", "s", "C:\\x", "m")])
    connection = sqlite3.connect(path)
    connection.execute("DROP INDEX idx_events_validation")
    connection.execute("ALTER TABLE events DROP COLUMN validation_status")
    connection.commit()
    connection.close()
    before = digest(path)

    app = open_app(path)
    assert any("missing columns: validation_status" in e.value for e in app.error)
    assert digest(path) == before

    TimelineStore(str(path)).close()
    (event,) = ui_data.load_matching(str(path), {})
    assert (event.event_id, event.validation_status) == ("E1", None)
    assert any("of **1** matching" in m.value for m in open_app(path).markdown)


@pytest.mark.parametrize("status", sorted(VALID_VALIDATION_STATUSES) + [None])
def test_status_is_identical_from_database_to_export(tmp_path, status):
    path = str(tmp_path / "timeline.db")
    with TimelineStore(path) as store:
        store.insert_events([ForensicEvent(
            "E1", "2026-01-01T00:00:00+00:00", "d", "EVTX", "s", "C:\\x", "m",
            validation_status=status, confidence_level="HIGH")])
    (event,) = ui_data.load_matching(path, {})
    assert event.validation_status == status
    assert ui_data.timeline_row(event)["Validation"] == (status or "Not recorded")
    assert export_event(event)["validation_status"] == status
    assert read_csv(events_to_csv([event]), EVENT_FIELDS)[0]["validation_status"] == status


def test_every_schema_status_has_a_review_label():
    assert set(ui_findings.REVIEW_LABELS) == VALID_VALIDATION_STATUSES


def test_unknown_stored_status_is_announced(tmp_path, case01_pipeline):
    path = tmp_path / "timeline.db"
    shutil.copy(case01_pipeline[0], path)
    connection = sqlite3.connect(path)
    connection.execute("UPDATE events SET validation_status='confirmed' WHERE id=1")
    connection.commit()
    connection.close()
    app = open_app(path)
    assert any("outside the schema" in w.value and "confirmed" in w.value for w in app.warning)


def test_html_report_keeps_high_scoring_candidate_a_candidate():
    html = ReportGenerator.generate_html_report([], [
        {"finding_id": "F1", "confidence_level": "HIGH", "confidence_score": 100},
        {"finding_id": "F2", "validation_status": "disputed"},
    ])
    assert "<td>Candidate</td>" in html and "<td>Unresolved</td>" in html
    assert "Validated" not in html and "does not validate" in html
