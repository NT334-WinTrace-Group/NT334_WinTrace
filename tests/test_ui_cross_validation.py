from pathlib import Path

from streamlit.testing.v1 import AppTest
from src.report_generator import ReportGenerator
from src.schema import ForensicEvent
from src.storage import TimelineStore

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


def test_cross_validation_uses_full_case(case01_pipeline):
    app = open_app(*case01_pipeline)

    assert any(
        "Events checked: **692**" in m.value
        for m in app.markdown
    )

    app.text_input(
        key="filter_keyword"
    ).input("CASE01-SB0133")

    click(app, "Apply filters")

    assert list(
        app.dataframe[0].value["Event ID"]
    ) == ["CASE01-SB0133"]

    assert any(
        "Events checked: **692**" in m.value
        for m in app.markdown
    )


def test_html_validation_respects_export_scope(
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
    assert "Exported timeline events only" in captured[-1]
    assert "<strong>Events checked:</strong> 692" in captured[-1]

    app.text_input(
        key="filter_keyword"
    ).input("CASE01-SB0133")

    click(app, "Apply filters")
    click(app, "Prepare export")

    assert "<strong>Events checked:</strong> 1</p>" in captured[-1]
    assert "NO_DATA" in captured[-1]


def test_cross_validation_requires_single_case(tmp_path):
    database = tmp_path / "timeline.db"
    findings = tmp_path / "findings.json"
    findings.write_text("[]", encoding="utf-8")

    events = [
        ForensicEvent(
            event_id=event_id,
            timestamp="2026-01-01T00:00:00+00:00",
            timestamp_desc="Event time",
            artifact_source="EVTX",
            source_file="Security.evtx",
            target_path=r"C:\test.txt",
            message="Synthetic test event",
            case_id=case_id,
            validation_status="synthetic",
        )
        for event_id, case_id in [
            ("E1", "CASE01"),
            ("E2", "CASE02"),
        ]
    ]

    with TimelineStore(str(database)) as store:
        store.insert_events(events)

    app = open_app(database, findings)

    assert any(
        "Select one named case" in item.value
        for item in app.info
    )

    app.selectbox(
        key="filter_case"
    ).set_value("CASE01").run()

    assert not app.exception

    assert any(
        "Events checked: **1**" in m.value
        for m in app.markdown
    )
