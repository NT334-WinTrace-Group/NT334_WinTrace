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
    assert rows[0]["case_id"] == "CASE01"
    assert rows[0]["parser"] == "generic"
    assert json.loads(rows[0]["extra_attributes"]) == {}
    assert [item["candidate_id"] for item in payload["review_candidates"]] == [
        "CASE01-C1", "CASE01-C2", "CASE01-C5"
    ]
    assert event.event_id in html
    assert event.timestamp_type in html
    assert event.evidence_reference in html
    assert "NO_DATA" in html

    engine_findings = tmp_path / "engine-findings.json"
    engine_findings.write_text(json.dumps({"findings": [{
        "finding_id": "AUTO-1", "case_id": "CASE01", "event_ids": [event.event_id],
        "evidence_references": [event.evidence_reference], "matched_rules": ["R03"],
        "confidence_level": "LOW", "confidence_score": 25,
        "validation_status": "unverified", "explanation": "Automated candidate",
    }]}), encoding="utf-8")
    integrated_paths = export_case_report(
        database, "CASE01", tmp_path / "integrated", candidates, engine_findings
    )
    integrated = json.loads(integrated_paths["json"].read_text(encoding="utf-8"))
    integrated_html = integrated_paths["html"].read_text(encoding="utf-8")
    assert len(integrated["review_candidates"]) == 3
    assert len(integrated["rule_engine_candidates"]) == 1
    assert "Manual review candidate" in integrated_html
    assert "Automated correlation candidate" in integrated_html
    assert "AUTO-1" in integrated_html

    # A different case can be exported without CASE01's C1/C2/C5 candidate set.
    case02_event = ForensicEvent(
        event_id="CASE02-EVT-1", timestamp="2015-03-23T20:24:15Z",
        timestamp_desc="Test", artifact_source="LNK", source_file="case02.lnk",
        target_path=r"C:\Case02\file.txt", message="Other case", case_id="CASE02",
    )
    with TimelineStore(str(database)) as store:
        store.insert_events([case02_event])
    case02_paths = export_case_report(
        database, "CASE02", tmp_path / "case02-report", candidates
    )
    case02_data = json.loads(case02_paths["json"].read_text(encoding="utf-8"))
    assert case02_data["review_candidates"] == []
