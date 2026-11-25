"""
WinTrace - Plaso Pipeline Prototype Script
End-to-end prototype for ingesting, normalizing, filtering, and exporting Plaso timelines.
"""

import argparse
import csv
import json
import re
import sqlite3
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

# Add project root to sys.path for direct script execution
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.normalizer import PlasoNormalizer, ShellBagsNormalizer
from src.correlation import CorrelationEngine
from src.schema import VALID_ARTIFACTS
from src.storage import TimelineStore
from src.timeline_parser import TimelineParser, TargetedFilter


class PipelineInputError(ValueError):
    """Raised when an input file cannot produce a complete valid event set."""


def print_banner():
    banner = """
============================================================
       WinTrace - Plaso Timeline Normalization Pipeline     
============================================================
"""
    print(banner)


def run_pipeline(
    input_file: str,
    output_file: str,
    output_format: str = "json",
    filter_user: str = None,
    filter_artifact: str = None,
    shellbags_file: Optional[str] = None,
    database_file: Optional[str] = None,
    error_log: Optional[str] = None,
    case_id: Optional[str] = None,
    findings_file: Optional[str] = None,
    correlation_window: float = 5.0,
    source_label: Optional[str] = "plaso",
    case_output_dir: Optional[str] = None,
):
    if case_output_dir:
        if not case_id or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", case_id):
            raise PipelineInputError(
                "--output-dir requires a safe --case-id (letters, digits, dot, underscore, hyphen)"
            )
        case_directory = Path(case_output_dir) / case_id
        case_directory.mkdir(parents=True, exist_ok=True)

        def case_output(path: Optional[str], default_name: Optional[str] = None) -> Optional[str]:
            if path is None and default_name is None:
                return None
            filename = Path(path).name if path is not None else default_name
            return str(case_directory / filename)

        output_file = case_output(output_file)
        database_file = case_output(database_file)
        findings_file = case_output(findings_file)
        error_log = case_output(error_log, "errors.json")

        output_paths = [
            Path(path).resolve()
            for path in (output_file, database_file, findings_file, error_log)
            if path is not None
        ]
        if len(output_paths) != len(set(output_paths)):
            raise PipelineInputError("Case output files must have distinct names.")

    print_banner()
    print(f"[*] Loading and normalizing {source_label or 'event'} CSV from: {input_file}")

    # Step 1: Normalize event CSV input
    events, errors = PlasoNormalizer.normalize_file_with_report(
        input_file, source_label, case_id=case_id
    )
    if shellbags_file:
        shellbag_events, shellbag_errors = ShellBagsNormalizer.normalize_file_with_report(
            shellbags_file
        )
        for event in shellbag_events:
            event.extra_attributes.setdefault("source_label", "shellbags")
            if case_id:
                event.case_id = case_id
        if any(event.artifact_source == "ShellBags" for event in events):
            raise PipelineInputError(
                "ShellBags events were supplied by both --input and --shellbags; "
                "import one canonical ShellBags event source."
            )
        events.extend(shellbag_events)
        errors.extend(shellbag_errors)
        print(f"[+] Imported {len(shellbag_events)} ShellBags events.")
    if errors:
        if error_log:
            error_path = Path(error_log)
            error_path.parent.mkdir(parents=True, exist_ok=True)
            error_path.write_text(json.dumps(errors, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[WARNING] Records rejected during normalization: {len(errors)}")
        first_error = errors[0]["error"]
        raise PipelineInputError(
            f"Rejected {len(errors)} malformed input record(s); first error: {first_error}"
        )
    total_ingested = len(events)
    if total_ingested == 0:
        raise PipelineInputError("Input files contained no valid events.")
    print(f"[+] Successfully normalized {total_ingested} forensic events.")

    # Step 2: Optional Targeted Filtering
    if filter_user:
        print(f"[*] Applying filter for user: {filter_user}")
        events = TargetedFilter.filter_by_user(events, username=filter_user)
        print(f"[+] Events after user filter: {len(events)}")

    if filter_artifact:
        allowed_artifacts = {artifact.casefold() for artifact in VALID_ARTIFACTS}
        allowed_artifacts.add("generic")
        if filter_artifact.casefold() not in allowed_artifacts:
            raise PipelineInputError(
                f"Unsupported artifact filter: {filter_artifact!r}"
            )
        print(f"[*] Applying filter for artifact: {filter_artifact}")
        events = TargetedFilter.filter_by_artifacts(events, artifacts=[filter_artifact])
        print(f"[+] Events after artifact filter: {len(events)}")

    # Step 3: Export normalized events
    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if output_format.lower() == "csv":
        TimelineParser.export_to_csv(events, str(out_path))
        print(f"[+] Exported normalized timeline (CSV) to: {out_path}")
    else:
        TimelineParser.export_to_json(events, str(out_path))
        print(f"[+] Exported normalized timeline (JSON) to: {out_path}")

    if database_file:
        with TimelineStore(database_file) as store:
            inserted = store.insert_events(events)
            print(
                f"[+] SQLite timeline: {inserted} new events, "
                f"{store.count()} total events at {database_file}"
            )

    if findings_file:
        engine = CorrelationEngine(window_minutes=correlation_window)
        findings = []
        case_groups = {}
        for event in events:
            case_groups.setdefault(event.case_id or "Unspecified", []).append(event)
        for _, case_events in sorted(case_groups.items()):
            findings.extend(engine.correlate(case_events))

        findings_path = Path(findings_file)
        findings_path.parent.mkdir(parents=True, exist_ok=True)
        CorrelationEngine.export_findings_json(findings, str(findings_path))
        print(
            f"[+] Correlation findings: {len(findings)} candidates at {findings_path}"
        )

    # Step 4: Summary Statistics Dashboard
    artifact_counts = Counter(e.artifact_source for e in events)
    users_found = {e.username for e in events if e.username}
    sids_found = {e.user_sid for e in events if e.user_sid}

    sorted_events = sorted(events, key=lambda e: e.dt)
    earliest = sorted_events[0].timestamp if sorted_events else "N/A"
    latest = sorted_events[-1].timestamp if sorted_events else "N/A"

    print("\n------------------ PIPELINE STATISTICS ------------------")
    print(f"Total Events Processed : {len(events)} / {total_ingested}")
    print(f"Timeline Start (UTC)   : {earliest}")
    print(f"Timeline End   (UTC)   : {latest}")
    print(f"Identified Users       : {', '.join(users_found) if users_found else 'None'}")
    print(f"Identified SIDs        : {', '.join(sids_found) if sids_found else 'None'}")
    print("\nArtifact Breakdown:")
    for art, count in sorted(artifact_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  - {art:<15}: {count:>4} events")
    print("---------------------------------------------------------\n")
    print("[SUCCESS] Pipeline completed successfully!\n")


def main():
    parser = argparse.ArgumentParser(description="WinTrace Plaso Pipeline Prototype")
    parser.add_argument(
        "--input", "-i",
        default="results/plaso_raw_output.csv",
        help="Path to raw Plaso CSV file (default: results/plaso_raw_output.csv)"
    )
    parser.add_argument(
        "--output", "-o",
        default="results/normalized_events.json",
        help="Path to save normalized output (default: results/normalized_events.json)"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "csv"],
        default="json",
        help="Output format: json or csv (default: json)"
    )
    parser.add_argument(
        "--user", "-u",
        default=None,
        help="Filter events by username"
    )
    parser.add_argument(
        "--artifact", "-a",
        default=None,
        help="Filter events by artifact type (Prefetch, LNK, ShellBags, RecycleBin, EVTX)"
    )
    parser.add_argument("--shellbags", default=None, help="CASE01 ShellBags CSV to import")
    parser.add_argument("--database", default=None, help="SQLite database output path")
    parser.add_argument("--error-log", default=None, help="JSON file for rejected records")
    parser.add_argument("--case-id", default=None, help="Case identifier applied to all imported events")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Case output root; writes all requested outputs under <root>/<case-id>",
    )
    parser.add_argument(
        "--source-label",
        default="plaso",
        help="Provenance label for the primary event CSV (default: plaso)",
    )
    parser.add_argument("--findings", default=None, help="JSON path for correlation findings")
    parser.add_argument("--correlation-window", type=float, default=5.0, help="Correlation time window in minutes")

    args = parser.parse_args()
    try:
        run_pipeline(
            input_file=args.input,
            output_file=args.output,
            output_format=args.format,
            filter_user=args.user,
            filter_artifact=args.artifact,
            shellbags_file=args.shellbags,
            database_file=args.database,
            error_log=args.error_log,
            case_id=args.case_id,
            findings_file=args.findings,
            correlation_window=args.correlation_window,
            source_label=args.source_label,
            case_output_dir=args.output_dir,
        )
        return 0
    except (
        PipelineInputError,
        FileNotFoundError,
        OSError,
        ValueError,
        sqlite3.Error,
        csv.Error,
    ) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
