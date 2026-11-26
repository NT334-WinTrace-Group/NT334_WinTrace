"""Day 20: end-to-end smoke test and hostile inputs for the dashboard."""

import json
from pathlib import Path
import shutil
import sqlite3

import pytest
from streamlit.testing.v1 import AppTest

from src import ui_data
from src.schema import ForensicEvent
from src.storage import MalformedEventError, TimelineStore

ROOT = Path(__file__).resolve().parent.parent
CANDIDATES = [
    "CASE01-SB0133 CASE01-JL0022",
    "CASE01-SB0147 CASE01-JL0020",
    "CASE01-PF0173 CASE01-LNK0037",
]


def open_app(database, findings):
    app = AppTest.from_file(str(ROOT / "src/app.py"), default_timeout=60)
    app.session_state["database"] = str(database)
    app.session_state["findings"] = str(findings)
    app.run()
    return app


def values(elements):
    return [element.value for element in elements]


def click(app, label):
    next(button for button in app.button if button.label == label).click().run()
    assert not app.exception


def labels(app):
    return [element.proto.label for element in app.get("download_button")]


@pytest.fixture
def damaged(tmp_path, case01_pipeline):
    """Copy the CASE01 database without NOT NULL rules and damage one row."""
    def damage(sql):
        path = tmp_path / "damaged.db"
        shutil.copy(case01_pipeline[0], path)
        connection = sqlite3.connect(path)
        connection.executescript(
            "CREATE TABLE copy AS SELECT * FROM events; DROP TABLE events; "
            "ALTER TABLE copy RENAME TO events;" + sql
        )
        connection.close()
        return path
    return damage


def test_full_investigation_flow(case01_pipeline):
    app = open_app(*case01_pipeline)
    assert not app.exception and not app.error and not app.warning
    assert any("of **692** matching" in value for value in values(app.markdown))

    app.text_input(key="filter_keyword").input("CASE01-SB0133")
    click(app, "Apply filters")
    assert list(app.dataframe[0].value["Event ID"]) == ["CASE01-SB0133"]
    assert any("Deduplicated.csv:L106" in value for value in values(app.code))

    click(app, "Prepare export")
    assert "Download timeline (CSV)" in labels(app)
    assert "Download findings with source events (JSON)" in labels(app)
    assert any("**1** matching events" in value for value in values(app.markdown))

    for candidate in CANDIDATES:
        app.text_input(key="finding_text").input(candidate).run()
        assert not app.exception
        assert any("of **1**" in value for value in values(app.markdown))
        box = next(b for b in app.selectbox if b.label == "Source event to inspect")
        assert {option.split(" | ")[0] for option in box.options} == set(candidate.split())


@pytest.mark.parametrize("sql", [
    "UPDATE events SET extra_attributes='{bad' WHERE id=1",
    "UPDATE events SET extra_attributes='[]' WHERE id=1",
    "UPDATE events SET extra_attributes=NULL WHERE id=1",
    "UPDATE events SET timestamp='garbage' WHERE id=1",
    "UPDATE events SET timestamp=NULL WHERE id=1",
    "UPDATE events SET target_path=x'ff00' WHERE id=1",
    "UPDATE events SET message=NULL WHERE id=1",
    "UPDATE events SET validation_status=x'07' WHERE id=1",
])
def test_one_damaged_row_is_named_and_the_rest_stays_usable(damaged, case01_pipeline, sql):
    path = damaged(sql)
    with TimelineStore(str(path), read_only=True) as store:
        with pytest.raises(MalformedEventError, match="database row 1"):
            store.query()
        messages = []
        assert len(store.query(malformed=messages)) == 691
        assert len(messages) == 1

    app = open_app(path, case01_pipeline[1])
    assert not app.exception
    assert any("of **692** matching" in value for value in values(app.markdown))

    app.selectbox(key="page_size").set_value(250).run()
    seen = []
    for _ in range(3):
        seen += values(app.text)
        following = app.button(key="next_page")
        if not following.disabled:
            following.click().run()
            assert not app.exception
    assert any("(database row 1) cannot be read" in text for text in seen)


def test_damaged_row_blocks_export_until_left_out(damaged, case01_pipeline):
    path = damaged("UPDATE events SET extra_attributes='{bad' WHERE id=1")
    app = open_app(path, case01_pipeline[1])
    click(app, "Prepare export")
    assert "Download timeline (CSV)" not in labels(app)
    assert any("1 stored events cannot be read" in value for value in values(app.error))

    app.checkbox(key="skip_invalid").check()
    click(app, "Prepare export")
    assert "Download timeline (CSV)" in labels(app)
    assert any("**691** matching events" in value for value in values(app.markdown))


def test_page_holding_only_a_damaged_row_still_explains_itself(tmp_path):
    path = tmp_path / "one.db"
    with TimelineStore(str(path)) as store:
        store.insert_events([ForensicEvent(
            "E1", "2026-01-01T00:00:00+00:00", "d", "EVTX", "s", "C:\\x", "m")])
        store.connection.execute("UPDATE events SET extra_attributes='{bad'")
        store.connection.commit()
    app = open_app(path, tmp_path / "none.json")
    assert not app.exception
    assert any("1 stored events on this page" in value for value in values(app.error))
    assert not any("No events match" in value for value in values(app.info))


def test_database_missing_a_column_is_refused(tmp_path):
    path = tmp_path / "old.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE events (id INTEGER, event_id TEXT, timestamp TEXT)")
    connection.commit()
    connection.close()
    app = open_app(path, tmp_path / "none.json")
    assert not app.exception
    assert any("missing columns" in value for value in values(app.error))


def test_replaced_database_is_not_served_from_cache(tmp_path, case01_pipeline):
    path = tmp_path / "timeline.db"
    shutil.copy(case01_pipeline[0], path)
    app = open_app(path, case01_pipeline[1])
    click(app, "Next page")
    path.unlink()
    with TimelineStore(str(path)) as store:
        store.insert_events([ForensicEvent(
            "NEW", "2026-01-01T00:00:00+00:00", "d", "EVTX", "s", "C:\\" + "x" * 900, "m",
            case_id="CASE01")])
    app.run()
    assert not app.exception
    assert list(app.dataframe[0].value["Event ID"]) == ["NEW"]
    # Findings still cite events of the replaced database, so they must be flagged.
    assert any("is not in this database" in value for value in values(app.warning))


def test_removed_database_shows_a_message(tmp_path, case01_pipeline):
    path = tmp_path / "timeline.db"
    shutil.copy(case01_pipeline[0], path)
    app = open_app(path, case01_pipeline[1])
    path.unlink()
    app.run()
    assert not app.exception and not path.exists()
    assert any("No timeline database" in value for value in values(app.info))


@pytest.mark.parametrize("content", [
    "", "{", "{}", "[1]", '[{"finding_id": ["x"]}]', '[{"case_id": {"a": 1}}]',
])
def test_invalid_findings_file_does_not_hide_the_timeline(tmp_path, case01_pipeline, content):
    path = tmp_path / "findings.json"
    path.write_text(content, encoding="utf-8")
    app = open_app(case01_pipeline[0], path)
    assert not app.exception
    assert any("Cannot read the findings file" in value for value in values(app.warning))
    assert any("of **692** matching" in value for value in values(app.markdown))


def test_empty_source_paths(case01_pipeline):
    app = open_app("", "")
    assert not app.exception and app.info
    app = open_app(case01_pipeline[0], "")
    assert not app.exception


def test_binary_findings_file(tmp_path, case01_pipeline):
    path = tmp_path / "findings.json"
    path.write_bytes(b"\xff\xfe\x00\x81")
    with pytest.raises(ValueError):
        ui_data.load_findings(str(path), ["CASE01"])
    assert not open_app(case01_pipeline[0], path).exception


def test_default_paths_match_the_documented_pipeline_command():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    source = (ROOT / "src/app.py").read_text(encoding="utf-8")
    assert r"streamlit run src\app.py" in readme
    assert "--case-id CASE01" in readme and "--output-dir results" in readme
    for name in ("timeline.db", "findings.json"):
        assert name in readme
        assert json.dumps(f"results/CASE01/{name}") in source
