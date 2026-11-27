from pathlib import Path
from dataclasses import replace

from streamlit.testing.v1 import AppTest

from src import ui_data
from src.report_generator import ReportGenerator
from src.ui_manual_review import manual_findings_for_export

ROOT = Path(__file__).resolve().parent.parent


def open_app(database, findings):
    app = AppTest.from_file(
        str(ROOT / "src/app.py"),
        default_timeout=60,
    )
    app.session_state["database"] = str(database)
    app.session_state["findings"] = str(findings)
    app.run()
    assert not app.exception
    return app


def click(app, label):
    next(
        b for b in app.button if b.label == label
    ).click().run()
    assert not app.exception


def test_manual_candidates_link_to_source_events(case01_pipeline):
    database, _ = case01_pipeline

    events = ui_data.load_matching(
        database, {"case_id": "CASE01"}
    )

    findings = manual_findings_for_export(events)
    indexed = {f["finding_id"]: f for f in findings}
    available = {e.event_id for e in events}

    assert len(findings) == 3
    assert set(indexed) == {
        "CASE01-C1", "CASE01-C2", "CASE01-C5"
    }

    assert {
        "CASE01-PF0173",
        "CASE01-LNK0037",
        "CASE01-JL0018",
    } == set(indexed["CASE01-C5"]["event_ids"])

    for finding in findings:
        assert finding["validation_status"] == "unverified"
        assert finding["confidence_level"] == "NOT_SCORED"
        assert set(finding["event_ids"]).issubset(available)
        assert finding["evidence_references"]


def test_manual_candidates_respect_scope(case01_pipeline):
    database, _ = case01_pipeline

    events = ui_data.load_matching(
        database, {"case_id": "CASE01"}
    )

    assert manual_findings_for_export([]) == []

    selected = [
        e for e in events
        if e.event_id == "CASE01-SB0133"
    ]

    assert len(selected) == 1
    assert manual_findings_for_export(selected) == []

    mixed = events + [
        replace(events[0], case_id="CASE02")
    ]

    assert manual_findings_for_export(mixed) == []


def test_manual_review_ui(case01_pipeline):
    app = open_app(*case01_pipeline)

    for candidate in ("CASE01-C1", "CASE01-C2", "CASE01-C5"):
        app.selectbox(
            key="manual_candidate"
        ).set_value(candidate).run()

        assert not app.exception
        assert not any(
            "Missing source event" in e.value
            for e in app.error
        )

    labels = [e.label for e in app.expander]

    assert any(
        "CASE01-PF0173" in label for label in labels
    )
    assert any(
        "CASE01-LNK0037" in label for label in labels
    )
    assert any(
        "CASE01-JL0018" in label for label in labels
    )


def test_html_contains_manual_candidates(
    case01_pipeline, monkeypatch
):
    captured = []
    original = ReportGenerator.generate_html_report

    def capture(*args, **kwargs):
        html = original(*args, **kwargs)
        captured.append(html)
        return html

    monkeypatch.setattr(
        ReportGenerator,
        "generate_html_report",
        staticmethod(capture),
    )

    app = open_app(*case01_pipeline)
    click(app, "Prepare export")

    assert captured

    for candidate in ("CASE01-C1", "CASE01-C2", "CASE01-C5"):
        assert f"<td>{candidate}</td>" in captured[-1]

    app.text_input(
        key="filter_keyword"
    ).input("CASE01-SB0133")

    click(app, "Apply filters")
    click(app, "Prepare export")

    for candidate in ("CASE01-C1", "CASE01-C2", "CASE01-C5"):
        assert f"<td>{candidate}</td>" not in captured[-1]
