"""Export a case-scoped CSV, JSON, and HTML report without starting Streamlit."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.cross_validation import CrossValidator
from src.report_generator import ReportGenerator
from src.storage import TimelineStore


def load_review_candidates(path: Path, case_id: str) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return [row for row in csv.DictReader(handle) if row.get("case_id") == case_id]


def load_engine_findings(path: Path | None, case_id: str) -> list[dict]:
    if path is None:
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        rows = payload.get("rule_engine_candidates", payload.get("findings", []))
    else:
        rows = payload
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("Findings JSON must be a list or contain a findings list")
    return [row for row in rows if not row.get("case_id") or row.get("case_id") == case_id]


def export_case_report(
    database: Path,
    case_id: str,
    output_dir: Path,
    candidates_file: Path,
    findings_file: Path | None = None,
) -> dict[str, Path]:
    if not database.is_file():
        raise FileNotFoundError(f"SQLite database does not exist: {database}")
    output_dir.mkdir(parents=True, exist_ok=True)

    with TimelineStore(str(database)) as store:
        events = store.query(case_id=case_id)
    if not events:
        raise ValueError(f"No events found for case {case_id!r} in {database}")

    candidates = load_review_candidates(candidates_file, case_id)
    validation = CrossValidator(events).run_all_checks()
    manual_findings = [{
        **item,
        "candidate_type": "Manual review candidate",
        "finding_id": item.get("candidate_id", "Unknown"),
        "case_id": item.get("case_id", case_id),
        "confidence_level": "UNVERIFIED",
        "confidence_score": "Not assessed",
        "validation_status": item.get("validation_status", "unverified"),
        "time_delta_minutes": round(float(item.get("time_delta_seconds") or 0) / 60, 2),
        "matched_rules": (item.get("candidate_rules") or "").split(";"),
        "evidence_references": item.get("source_references", ""),
        "explanation": (
            f"{item.get('supported_observation', '')} "
            f"Safe interpretation: {item.get('safe_interpretation', '')} "
            f"Not established: {item.get('not_proven', '')} "
            f"Caveat: {item.get('caveat', '')} "
            f"Sources: {item.get('source_references', '')}"
        ),
    } for item in candidates]
    engine_findings = load_engine_findings(findings_file, case_id)
    html_findings = manual_findings + [{
        **item,
        "candidate_type": "Automated correlation candidate",
        "finding_id": item.get("finding_id", item.get("id", "Unknown")),
        "case_id": item.get("case_id", case_id),
        "validation_status": item.get("validation_status", "unverified"),
        "matched_rules": item.get("matched_rules", []),
    } for item in engine_findings]

    paths = {
        "csv": output_dir / f"{case_id}_timeline.csv",
        "json": output_dir / f"{case_id}_report.json",
        "html": output_dir / f"{case_id}_report.html",
    }
    paths["csv"].write_text(ReportGenerator.generate_csv_report(events), encoding="utf-8-sig", newline="")
    paths["json"].write_text(
        ReportGenerator.generate_json_report(
            events, case_id, review_candidates=candidates,
            rule_engine_candidates=engine_findings, validation_report=validation,
        ),
        encoding="utf-8",
    )
    paths["html"].write_text(
        ReportGenerator.generate_html_report(events, html_findings, case_id, validation),
        encoding="utf-8",
    )

    # Acceptance guards: all exports must retain traceability and the candidate set.
    csv_text = paths["csv"].read_text(encoding="utf-8-sig")
    html_text = paths["html"].read_text(encoding="utf-8")
    json_data = json.loads(paths["json"].read_text(encoding="utf-8"))
    required_columns = (
        "event_id", "case_id", "timestamp", "timestamp_type", "parser",
        "source_file", "evidence_reference", "validation_status", "extra_attributes",
    )
    header = csv_text.splitlines()[0]
    if any(column not in header for column in required_columns):
        raise AssertionError("CSV export omitted a required provenance column")
    if events[0].event_id not in html_text or (
        events[0].timestamp_type and events[0].timestamp_type not in html_text
    ):
        raise AssertionError("HTML export omitted event/timestamp provenance")
    if case_id == "CASE01" and candidates:
        if not all(item.get("source_references") for item in json_data["review_candidates"]):
            raise AssertionError("A CASE01 review candidate has no source references")
    if len(json_data["rule_engine_candidates"]) != len(engine_findings):
        raise AssertionError("JSON export omitted automated candidate findings")
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=ROOT / "results/case01_timeline.db")
    parser.add_argument("--case-id", default="CASE01")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "results/reports")
    parser.add_argument(
        "--candidates", type=Path,
        default=ROOT / "analysis/thi-timeline/week3_findings_validation.csv",
    )
    parser.add_argument(
        "--findings", type=Path, default=None,
        help="Optional Correlation Engine findings JSON (kept separate from manual candidates)",
    )
    args = parser.parse_args()
    for kind, path in export_case_report(
        args.database, args.case_id, args.output_dir, args.candidates, args.findings
    ).items():
        print(f"{kind.upper()}: {path}")


if __name__ == "__main__":
    main()
