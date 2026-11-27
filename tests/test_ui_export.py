"""Day 19: exports round-trip, follow the filters and refuse broken evidence."""

import json
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from src import ui_data, ui_export, ui_findings
from src.correlation import CorrelationEngine
from src.normalizer import PlasoNormalizer, ShellBagsNormalizer
from src.schema import ForensicEvent
from src.storage import TimelineStore

ROOT = Path(__file__).resolve().parent.parent
CITED = [
    "CASE01-SB0133", "CASE01-JL0022", "CASE01-SB0147", "CASE01-JL0020",
    "CASE01-PF0173", "CASE01-LNK0037",
]


def make_event(event_id="E1", **kwargs):
    values = dict(
        timestamp="2026-01-01T00:00:00.123456+00:00", timestamp_desc="Event time",
        artifact_source="EVTX", source_file="Security.evtx", target_path="C:\\x.txt",
        message="m", timestamp_type="EVTX_EventGenerated", evidence_reference="log:1",
        validation_status="unverified", case_id="C",
    )
    return ForensicEvent(event_id=event_id, **{**values, **kwargs})


@pytest.fixture(scope="module")
def case01(tmp_path_factory):
    supporting, _ = PlasoNormalizer.normalize_file_with_report(
        str(ROOT / "analysis/phuc-artifacts/case01_supporting_events.csv"),
        "case01-supporting-tools", case_id="CASE01",
    )
    shellbags, _ = ShellBagsNormalizer.normalize_file_with_report(
        str(ROOT / "results/case01_shellbags_events.csv")
    )
    root = tmp_path_factory.mktemp("export")
    database, findings = str(root / "timeline.db"), str(root / "findings.json")
    with TimelineStore(database) as store:
        store.insert_events(supporting + shellbags)
    cited = [event for event in supporting + shellbags if event.event_id in CITED]
    CorrelationEngine.export_findings_json(CorrelationEngine().correlate(cited), findings)
    return database, findings


@pytest.fixture(scope="module")
def findings(case01):
    items, _ = ui_data.load_findings(case01[1], ["CASE01"])
    return items, ui_findings.load_event_index(case01[0], items)


def values(elements):
    return [element.value for element in elements]


def prepare(database, findings, keyword=None, skip=False):
    app = AppTest.from_file(str(ROOT / "src/app.py"), default_timeout=60)
    app.session_state["database"] = str(database)
    app.session_state["findings"] = str(findings)
    app.run()
    if keyword:
        app.text_input(key="filter_keyword").input(keyword)
        next(b for b in app.button if b.label == "Apply filters").click().run()
    if skip:
        app.checkbox(key="skip_invalid").check()
    next(b for b in app.button if b.label == "Prepare export").click().run()
    assert not app.exception
    return app


def download_labels(app):
    return [element.proto.label for element in app.get("download_button")]


@pytest.mark.parametrize("filters", [
    {}, {"keyword": "CASE01-SB0133"},
    {"start_text": "2015-03-23", "end_text": "2015-03-23", "artifacts": ["JumpLists", "LNK"]},
])
def test_events_round_trip_and_follow_the_filter(case01, filters):
    store_filters = ui_data.build_filters(case_id="CASE01", **filters)
    events = ui_data.load_matching(case01[0], store_filters)
    assert events and ui_export.event_errors(events) == {}
    expected = [ui_export.export_event(event) for event in events]

    text = ui_export.events_to_csv(events)
    assert ui_export.read_csv(text, ui_export.EVENT_FIELDS) == expected
    assert ui_export.read_csv("\ufeff" + text, ui_export.EVENT_FIELDS) == expected
    document = ui_export.read_json(
        ui_export.events_to_json(events, store_filters, [ui_export.source_info(case01[0])])
    )
    assert document["records"] == expected
    assert document["record_count"] == ui_data.load_page(case01[0], store_filters, 1, 10).total
    for event, record in zip(events, expected):
        for name in ui_export.REQUIRED_EVENT_FIELDS:
            assert record[name] == getattr(event, name)


def test_findings_round_trip_with_source_events(findings):
    items, index = findings
    assert len(items) >= 3 and ui_export.finding_errors(items, index) == {}
    expected = [ui_export.export_finding(item) for item in items]
    assert ui_export.read_csv(ui_export.findings_to_csv(items), ui_export.FINDING_FIELDS) == expected

    document = ui_export.read_json(ui_export.findings_to_json(items, index, {}, []))
    assert document["records"] == expected
    references = {e["event_id"]: e["evidence_reference"] for e in document["source_events"]}
    for record in document["records"]:
        assert record["validation_status"] == "unverified"
        assert set(record["evidence_references"]) == {references[i] for i in record["event_ids"]}


@pytest.mark.parametrize("text", [
    "=HYPERLINK(1)", "+1", "-1", "@x", "'quoted", "  =1+1", "''two", "plain",
    "a,b", 'say "hi"', "line1\nline2", "line1\r\nline2", "\t=1", "đường dẫn", "",
])
def test_awkward_text_round_trips_and_cannot_be_a_formula(text):
    events = [make_event(message=text)]
    csv_text = ui_export.events_to_csv(events)
    assert ui_export.read_csv(csv_text, ui_export.EVENT_FIELDS)[0]["message"] == text
    assert ui_export._guard(text).lstrip()[:1] not in ui_export.FORMULA_PREFIXES
    document = ui_export.read_json(ui_export.events_to_json(events, {}, []))
    assert document["records"][0]["message"] == text


def test_sub_second_time_and_missing_username_are_preserved():
    (record,) = ui_export.read_csv(
        ui_export.events_to_csv([make_event()]), ui_export.EVENT_FIELDS)
    assert record["timestamp"] == "2026-01-01T00:00:00.123456+00:00"
    assert record["username"] is None


def test_sensitive_attributes_are_not_exported(case01):
    events = ui_data.load_matching(case01[0], {})
    document = json.loads(ui_export.events_to_json(events, {}, []))
    for record in document["records"]:
        assert set(record) == set(ui_export.EVENT_FIELDS)
        assert set(record["extra_attributes"]) <= set(ui_export.EXTRA_FIELDS)
    text = json.dumps(document, ensure_ascii=False) + ui_export.events_to_csv(events)
    hidden = {event.user_sid for event in events if event.user_sid}
    for key in ("machine_id", "hostname"):
        hidden |= {e.extra_attributes[key] for e in events if e.extra_attributes.get(key)}
    assert hidden and not any(value in text for value in hidden)


def test_manifest_records_filters_and_source_hash_without_folder(case01):
    filters = ui_data.build_filters(case_id="CASE01", start_text="2015-03-23", keyword="x")
    source = ui_export.source_info(case01[0])
    document = json.loads(ui_export.events_to_json([], filters, [source]))
    assert document["filters"] == {
        "case_id": "CASE01", "start": "2015-03-23T00:00:00+00:00", "keyword": "x"}
    assert document["sources"][0]["name"] == "timeline.db"
    assert len(document["sources"][0]["sha256"]) == 64
    assert str(Path(case01[0]).parent) not in json.dumps(document)


@pytest.mark.parametrize("field", ["timestamp_type", "evidence_reference", "validation_status", "case_id"])
def test_missing_required_field_is_reported(field):
    errors = ui_export.event_errors([make_event("E1"), make_event("E2", **{field: None})])
    assert errors == {1: [f"missing {field}"]}


def test_duplicate_event_and_finding_ids_are_reported(findings):
    assert set(ui_export.event_errors([make_event(), make_event(message="other")])) == {0, 1}
    assert ui_export.event_errors([make_event(), make_event(case_id="D")]) == {}
    items, index = findings
    assert set(ui_export.finding_errors([items[0], items[0]], index)) == {0, 1}


def test_finding_with_broken_reference_or_invalid_event_is_reported(findings):
    items, index = findings
    broken = {**items[0], "event_ids": ["CASE01-SB0133", "GONE"]}
    assert any("GONE" in m for m in ui_export.finding_errors([broken], index)[0])

    a, b = make_event("E1", evidence_reference=None), make_event("E2")
    finding = {
        "finding_id": "F", "case_id": "C", "event_ids": ["E1", "E2"],
        "matched_rules": ["R01"], "evidence_references": ["log:1"],
    }
    local = {("C", "E1"): [a], ("C", "E2"): [b]}
    assert any("evidence_reference" in m for m in ui_export.finding_errors([finding], local)[0])


def test_reader_rejects_altered_exports(findings):
    items, index = findings
    document = json.loads(ui_export.findings_to_json(items, index, {}, []))
    for change, message in (
        ({"source_events": []}, "missing event"),
        ({"records": document["records"][1:]}, "record count"),
        ({"export_version": 99}, "version"),
        ({"kind": "other"}, "kind"),
    ):
        with pytest.raises(ui_export.ExportError, match=message):
            ui_export.read_json(json.dumps({**document, **change}))
    with pytest.raises(ui_export.ExportError, match="columns"):
        ui_export.read_csv("a,b\n1,2\n", ui_export.EVENT_FIELDS)


def test_app_offers_every_download(case01):
    app = prepare(*case01)
    assert download_labels(app) == [
        "Download findings (CSV)", "Download findings with source events (JSON)",
        "Download timeline (CSV)", "Download timeline (JSON)", "Download HTML report",
    ]
    assert any("**692** matching events" in value for value in values(app.markdown))


def test_app_export_follows_the_filter(case01):
    app = prepare(*case01, keyword="CASE01-SB0133")
    assert any("**1** matching events" in value for value in values(app.markdown))


def test_app_blocks_missing_evidence_until_it_is_left_out(tmp_path):
    database = tmp_path / "timeline.db"
    with TimelineStore(str(database)) as store:
        store.insert_events([make_event("GOOD"), make_event("BAD", evidence_reference=None)])
    missing = tmp_path / "none.json"

    app = prepare(database, missing)
    assert download_labels(app) == []
    assert any("1 of 2 events are not exportable" in value for value in values(app.error))
    problems = app.dataframe[-1].value
    assert list(problems["Record"]) == ["BAD"]
    assert "evidence_reference" in problems["Problem"].iloc[0]

    app = prepare(database, missing, skip=True)
    assert "Download timeline (JSON)" in download_labels(app)
    assert any("**1** matching events" in value for value in values(app.markdown))


def test_excluded_records_are_named_in_the_json_export():
    text = ui_export.events_to_json(
        [make_event()], {}, [], [{"record": "BAD", "problem": "missing evidence_reference"}])
    assert json.loads(text)["excluded_records"][0]["record"] == "BAD"


def test_safe_name():
    assert ui_export.safe_name("../CASE 01") == "CASE_01"
    assert ui_export.safe_name(None) == "all-cases"
