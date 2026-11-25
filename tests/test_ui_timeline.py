"""Day 16: timeline browsing and filtering on committed CASE01 data."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest
from streamlit.testing.v1 import AppTest

from src import ui_data
from src.normalizer import PlasoNormalizer, ShellBagsNormalizer
from src.schema import ForensicEvent
from src.storage import NOT_RECORDED, TimelineStore

ROOT = Path(__file__).resolve().parent.parent
FILTER_CASES = json.loads(
    (ROOT / "tests/fixtures/ui_filter_cases.json").read_text(encoding="utf-8")
)


@pytest.fixture(scope="module")
def case01_db(tmp_path_factory):
    supporting, errors = PlasoNormalizer.normalize_file_with_report(
        str(ROOT / "analysis/phuc-artifacts/case01_supporting_events.csv"),
        "case01-supporting-tools", case_id="CASE01",
    )
    shellbags, shellbag_errors = ShellBagsNormalizer.normalize_file_with_report(
        str(ROOT / "results/case01_shellbags_events.csv")
    )
    assert not errors and not shellbag_errors
    for event in shellbags:
        event.extra_attributes.setdefault("source_label", "shellbags")
    path = str(tmp_path_factory.mktemp("ui") / "timeline.db")
    with TimelineStore(path) as store:
        store.insert_events(supporting + shellbags)
    return path


def make_event(event_id, timestamp="2026-01-01T00:00:00+00:00", **kwargs):
    return ForensicEvent(
        event_id=event_id, timestamp=timestamp, timestamp_desc="Event time",
        artifact_source="EVTX", source_file="Security.evtx",
        target_path="C:\\x.txt", message="m", **kwargs,
    )


def run_app(database, findings="missing.json"):
    app = AppTest.from_file(str(ROOT / "src/app.py"), default_timeout=30)
    app.session_state["database"] = str(database)
    app.session_state["findings"] = str(findings)
    return app.run()


def rendered_text(app):
    elements = list(app.markdown) + list(app.info) + list(app.warning) + list(app.error)
    return "\n".join(element.value for element in elements)


@pytest.mark.parametrize("case", FILTER_CASES, ids=lambda case: case["name"])
def test_combined_filters_return_expected_events(case01_db, case):
    page = ui_data.load_page(case01_db, ui_data.build_filters(**case["filters"]), 1, 50)
    assert [event.event_id for event in page.events] == case["expected_ids"]
    assert page.total == len(case["expected_ids"])


def test_pages_cover_every_event_once_in_order(case01_db):
    filters = ui_data.build_filters(case_id="CASE01")
    first = ui_data.load_page(case01_db, filters, 1, 100)
    pages = [ui_data.load_page(case01_db, filters, n, 100) for n in range(1, first.page_count + 1)]
    events = [event for page in pages for event in page.events]
    assert (first.total, first.page_count) == (692, 7)
    assert len({event.event_id for event in events}) == 692
    assert [event.dt for event in events] == sorted(event.dt for event in events)
    assert (pages[-1].first, pages[-1].last) == (601, 692)


def test_out_of_range_page_is_clamped(case01_db):
    assert ui_data.load_page(case01_db, {}, 999, 250).page == 3
    assert ui_data.load_page(case01_db, {}, 0, 250).page == 1


def test_rows_keep_timestamp_type_source_and_unc_path(case01_db):
    page = ui_data.load_page(case01_db, {}, 1, 1000)
    rows = {event.event_id: ui_data.timeline_row(event) for event in page.events}
    assert all(list(row) == ui_data.TIMELINE_COLUMNS for row in rows.values())
    for event in page.events:
        assert rows[event.event_id]["Timestamp type"] == event.timestamp_type
        assert rows[event.event_id]["Source record"] == event.extra_attributes["source_line"]
        assert rows[event.event_id]["Source file"] == event.source_file
    row = rows["CASE01-SB0133"]
    assert row["Timestamp (UTC)"] == "2015-03-23 20:24:15 UTC"
    assert row["Path"].startswith("\\\\10.11.11.128\\secured_drive\\")


def test_utc_bounds():
    parse = ui_data.parse_utc_input
    assert parse("  ") is None
    assert parse("2015-03-23") == datetime(2015, 3, 23, tzinfo=timezone.utc)
    assert parse("2015-03-23", end_of_range=True) == datetime(
        2015, 3, 23, 23, 59, 59, 999999, tzinfo=timezone.utc)
    assert parse("2015-03-23 16:24:15-04:00") == datetime(2015, 3, 23, 20, 24, 15, tzinfo=timezone.utc)
    assert parse("2015-03-23 20:24 UTC", end_of_range=True) == datetime(
        2015, 3, 23, 20, 24, 59, 999999, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="YYYY-MM-DD"):
        parse("23/03/2015")
    with pytest.raises(ValueError, match="later"):
        ui_data.build_filters(start_text="2015-03-24", end_text="2015-03-23")


def test_sub_second_event_is_kept_by_whole_second_end(tmp_path):
    path = str(tmp_path / "timeline.db")
    with TimelineStore(path) as store:
        store.insert_events([make_event("E1", "2026-01-01T00:00:05.250000+00:00")])
    filters = ui_data.build_filters(start_text="2026-01-01 00:00:05", end_text="2026-01-01 00:00:05")
    page = ui_data.load_page(path, filters, 1, 10)
    assert ui_data.format_utc(page.events[0]) == "2026-01-01 00:00:05.250000 UTC"


def test_missing_values_can_be_filtered(tmp_path):
    path = str(tmp_path / "timeline.db")
    with TimelineStore(path) as store:
        store.insert_events([
            make_event("E1"),
            make_event("E2", case_id="C", validation_status="verified"),
        ])
    for name in ("case_id", "validation_status"):
        assert [e.event_id for e in ui_data.load_matching(path, {name: NOT_RECORDED})] == ["E1"]
    assert ui_data.load_summary(path).case_ids == ["C", None]


def test_read_only_store_does_not_create_or_change_files(tmp_path, case01_db):
    missing = tmp_path / "missing.db"
    with pytest.raises(FileNotFoundError):
        ui_data.load_summary(str(missing))
    assert not missing.exists()

    before = hashlib.sha256(Path(case01_db).read_bytes()).hexdigest()
    ui_data.load_page(case01_db, {}, 1, 10)
    with TimelineStore(case01_db, read_only=True) as store:
        with pytest.raises(sqlite3.OperationalError):
            store.insert_events([make_event("NEW")])
    assert hashlib.sha256(Path(case01_db).read_bytes()).hexdigest() == before


def test_query_rejects_negative_offset(case01_db):
    with TimelineStore(case01_db, read_only=True) as store:
        with pytest.raises(ValueError, match="offset"):
            store.query(offset=-1)


def test_findings_from_other_cases_are_excluded(tmp_path):
    path = tmp_path / "findings.json"
    path.write_text(json.dumps([
        {"finding_id": "A", "case_id": "CASE01"}, {"finding_id": "ALICE"},
    ]), encoding="utf-8")
    kept, excluded = ui_data.load_findings(str(path), ["CASE01"])
    assert ([f["finding_id"] for f in kept], excluded) == (["A"], 1)


def test_app_filters_and_pages_case01(case01_db):
    app = run_app(case01_db)
    assert not app.exception
    assert "of **692** matching" in rendered_text(app)
    assert list(app.dataframe[0].value.columns) == ui_data.TIMELINE_COLUMNS

    app.button(key="next_page").click().run()
    assert app.selectbox(key="filter_status").value == ""
    assert "**51–100** of **692**" in rendered_text(app)

    app.text_input(key="filter_keyword").input("CASE01-SB0133")
    next(b for b in app.button if b.label == "Apply filters").click().run()
    assert not app.exception
    assert list(app.dataframe[0].value["Event ID"]) == ["CASE01-SB0133"]

    next(b for b in app.button if b.label == "Reset filters").click().run()
    assert "**1–50** of **692**" in rendered_text(app)


def test_app_empty_and_error_states(tmp_path, case01_db):
    missing = tmp_path / "missing.db"
    assert "No timeline database" in rendered_text(run_app(missing))
    assert not missing.exists()

    invalid = tmp_path / "invalid.db"
    invalid.write_text("not a database", encoding="utf-8")
    assert "Cannot read" in rendered_text(run_app(invalid))

    empty = tmp_path / "empty.db"
    TimelineStore(str(empty)).close()
    assert "contains no events" in rendered_text(run_app(empty))

    app = run_app(case01_db)
    app.text_input(key="filter_keyword").input("nothing-matches-this")
    next(b for b in app.button if b.label == "Apply filters").click().run()
    assert "No events match" in rendered_text(app)
    assert not app.exception

    app.text_input(key="filter_start").input("yesterday")
    next(b for b in app.button if b.label == "Apply filters").click().run()
    assert "not a valid UTC time" in rendered_text(app)
    assert not app.exception


def test_no_matching_event_does_not_hide_findings(tmp_path, case01_db):
    findings = tmp_path / "findings.json"
    findings.write_bytes((ROOT / "docs/examples/ui_findings.json").read_bytes())
    app = run_app(case01_db, findings)
    app.text_input(key="filter_keyword").input("nothing-matches-this")
    next(b for b in app.button if b.label == "Apply filters").click().run()
    assert "**1** candidate findings" in rendered_text(app)


def test_switching_database_drops_filters_of_the_old_one(tmp_path, case01_db):
    other = tmp_path / "other.db"
    with TimelineStore(str(other)) as store:
        store.insert_events([make_event("E1", case_id="OTHER")])
    app = run_app(case01_db)
    app.multiselect(key="filter_artifacts").select("ShellBags")
    next(b for b in app.button if b.label == "Apply filters").click().run()
    app.text_input(key="database").input(str(other)).run()
    assert not app.exception
    assert list(app.dataframe[0].value["Event ID"]) == ["E1"]


def test_prepared_export_covers_all_pages(case01_db):
    app = run_app(case01_db)
    next(b for b in app.button if b.label.startswith("Prepare export")).click().run()
    assert not app.exception
    assert "Export contains **692** matching events" in rendered_text(app)
