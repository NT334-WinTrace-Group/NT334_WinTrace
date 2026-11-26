"""Regression coverage for non-UI Week 3 exports and benchmark fixtures."""

import csv
import json

from scripts.benchmark_timeline import build_synthetic_events, measure_size
from scripts.export_case_report import export_case_report
from src.schema import ForensicEvent
from src.storage import TimelineStore


def test_synthetic_benchmark_rows_are_marked_and_deterministic():
    first = build_synthetic_events(4)
    second = build_synthetic_events(4)
    assert [event.to_dict() for event in first] == [event.to_dict() for event in second]
    assert all(event.validation_status == "synthetic" for event in first)
    assert all(event.extra_attributes["benchmark_fixture"] for event in first)
    assert measure_size(8, 2)["events_inserted"] == 8


def test_non_ui_case_export_preserves_case_event_provenance_and_candidates(tmp_path):
    database = tmp_path / "case01.sqlite"
    event = ForensicEvent(
        event_id="CASE01-EVT-TEST",
        timestamp="2015-03-23T20:24:15+00:00",
        timestamp_desc="ShellBags interaction",
        timestamp_type="ShellBag_FirstInteracted",
        artifact_source="ShellBags",
        source_file="Deduplicated.csv",
        target_path=r"C:\Case\Documents",
        message="Synthetic export fixture",
        evidence_reference="Deduplicated.csv:L106",
        validation_status="unverified",
        case_id="CASE01",
    )
    with TimelineStore(str(database)) as store:
        store.insert_events([event])

    candidates = tmp_path / "candidates.csv"
    fields = [
        "case_id", "candidate_id", "time_delta_seconds", "candidate_rules",
        "supported_observation", "safe_interpretation", "not_proven", "caveat",
        "source_references",
    ]
    with candidates.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for candidate_id in ("CASE01-C1", "CASE01-C2", "CASE01-C5"):
            writer.writerow({
                "case_id": "CASE01", "candidate_id": candidate_id,
                "time_delta_seconds": "60", "candidate_rules": "R01",
                "supported_observation": "Observed context",
                "safe_interpretation": "Review candidate",
                "not_proven": "intent", "caveat": "No claim of intent",
                "source_references": "source.csv:L2",
            })

    paths = export_case_report(database, "CASE01", tmp_path / "reports", candidates)
    with paths["csv"].open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    payload = json.loads(paths["json"].read_text(encoding="utf-8"))
    html = paths["html"].read_text(encoding="utf-8")
    assert rows[0]["event_id"] == event.event_id
    assert rows[0]["timestamp_type"] == event.timestamp_type
    assert rows[0]["evidence_reference"] == event.evidence_reference
    assert [item["candidate_id"] for item in payload["review_candidates"]] == [
        "CASE01-C1", "CASE01-C2", "CASE01-C5"
    ]
    assert event.event_id in html
    assert event.timestamp_type in html
    assert event.evidence_reference in html
    assert "NO_DATA" in html
