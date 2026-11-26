"""Day 17: evidence detail must keep provenance and not overstate it."""

from collections import Counter
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from src import ui_data, ui_evidence
from src.normalizer import PlasoNormalizer, ShellBagsNormalizer
from src.schema import ForensicEvent
from src.storage import TimelineStore

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def case01():
    supporting, _ = PlasoNormalizer.normalize_file_with_report(
        str(ROOT / "analysis/phuc-artifacts/case01_supporting_events.csv"),
        "case01-supporting-tools", case_id="CASE01",
    )
    shellbags, _ = ShellBagsNormalizer.normalize_file_with_report(
        str(ROOT / "results/case01_shellbags_events.csv")
    )
    return {event.event_id: event for event in supporting + shellbags}


def make_event(**kwargs):
    values = dict(
        event_id="E1", timestamp="2026-01-01T00:00:00+00:00", timestamp_desc="Event time",
        artifact_source="EVTX", source_file="Security.evtx", target_path="C:\\x.txt", message="m",
    )
    return ForensicEvent(**{**values, **kwargs})


def open_detail(tmp_path, event):
    database = tmp_path / "detail.db"
    with TimelineStore(str(database)) as store:
        store.insert_events([event])
    app = AppTest.from_file(str(ROOT / "src/app.py"), default_timeout=30)
    app.session_state["database"] = str(database)
    app.session_state["findings"] = str(tmp_path / "missing.json")
    app.run()
    assert not app.exception
    return app


def values(elements):
    return [element.value for element in elements]


def test_every_case01_event_has_the_contract_label(case01):
    counts = Counter(ui_evidence.evidence_basis(e).label for e in case01.values())
    assert counts == {
        "Metadata only": 207,
        "Registry write": 80,
        "Approximate execution": 95,
        "Inferred interaction": 82,
        "Interaction evidence": 131,
        "Program execution evidence": 95,
        "Device connection evidence": 2,
    }


def test_metadata_is_never_presented_as_interaction(case01):
    for event in case01.values():
        if event.extra_attributes["semantic_class"] == "target_metadata":
            assert ui_evidence.evidence_basis(event) is ui_evidence.METADATA_ONLY
            assert event.validation_status != "verified"


def test_unknown_class_is_not_promoted():
    for extra in ({}, {"semantic_class": "new_class"}, {"is_user_activity": True}):
        event = make_event(extra_attributes=extra)
        assert ui_evidence.evidence_basis(event) is ui_evidence.NOT_CLASSIFIED


def test_verified_wording_in_reference_is_flagged(case01):
    flagged = [
        e.event_id for e in case01.values()
        if any("event status remains unverified" in w for w in ui_evidence.warnings(e))
    ]
    assert len(flagged) == 17 and "CASE01-SB0031" in flagged
    assert ui_evidence.warnings(case01["CASE01-SB0133"]) == []


def test_source_and_normalized_paths(case01):
    shellbag = case01["CASE01-SB0133"]
    assert ui_evidence.source_path(shellbag).startswith("Desktop\\Computers and Devices\\")
    assert ui_evidence.normalized_path(shellbag).startswith("\\\\10.11.11.128\\secured_drive\\")

    prefetch = case01["CASE01-PF0173"]
    assert ui_evidence.source_path(prefetch).startswith("\\DEVICE\\HARDDISKVOLUME2\\")
    assert ui_evidence.normalized_path(prefetch).endswith("WINWORD.EXE")

    virtual = case01["CASE01-SB0016"]
    assert ui_evidence.normalized_path(virtual) is None
    assert "virtual Shell item" in ui_evidence.normalized_path_text(virtual)

    unmapped = next(e for e in case01.values() if not e.target_path)
    assert ui_evidence.normalized_path_text(unmapped) == "Not recorded"


def test_limitations_keep_source_caveats(case01):
    def has(event_id, text):
        return any(text in note for note in ui_evidence.limitations(case01[event_id]))

    assert has("CASE01-SB0133", "CASE01-SB0141")
    assert has("CASE01-SB0031", "two-second")
    assert has("CASE01-SB0282", "not proof")
    assert has("CASE01-PF0173", "not attributed")
    for event in case01.values():
        if event.extra_attributes.get("caveat"):
            assert event.extra_attributes["caveat"] in ui_evidence.limitations(event)


def test_missing_provenance_is_reported():
    text = " ".join(ui_evidence.warnings(make_event()))
    for expected in ("evidence reference", "source record", "timestamp type", "case ID"):
        assert expected in text
    assert "Synthetic" in " ".join(ui_evidence.warnings(make_event(validation_status="synthetic")))


def test_detail_shows_complete_verified_event(tmp_path, case01):
    event = case01["CASE01-SB0133"]
    app = open_detail(tmp_path, event)
    texts, codes, markdown = values(app.text), values(app.code), " ".join(values(app.markdown))
    for value in (
        event.event_id, "CASE01", "ShellBags", "2015-03-23 20:24:15 UTC",
        event.timestamp_type, event.timestamp_desc, event.source_file, "Deduplicated.csv:L106",
    ):
        assert value in texts
    for value in (
        event.evidence_reference, event.message,
        ui_evidence.source_path(event), ui_evidence.normalized_path(event),
    ):
        assert value in codes
    assert "verified" in markdown and "Interaction evidence" in markdown


def test_detail_of_metadata_event_does_not_look_verified(tmp_path, case01):
    app = open_detail(tmp_path, case01["CASE01-SB0031"])
    markdown = " ".join(values(app.markdown))
    assert "Metadata only" in markdown and "does not show a user action" in markdown
    assert ":green" not in markdown
    assert any("remains unverified" in w for w in values(app.warning))


def test_hostile_and_long_text_is_shown_literally(tmp_path):
    path = "C:\\" + "a" * 600 + "\\`**x**` [script] alert.txt"
    event = make_event(target_path=path, message="**bold** :red[x]", source_file="`s`.lnk")
    app = open_detail(tmp_path, event)
    assert path in values(app.code) and "**bold** :red[x]" in values(app.code)
    assert "`s`.lnk" in values(app.text)
    assert not any("**bold**" in value for value in values(app.markdown))


def test_timeline_table_shows_evidence_basis(case01):
    row = ui_data.timeline_row(case01["CASE01-SB0031"])
    assert (row["Validation"], row["Evidence basis"]) == ("unverified", "Metadata only")
