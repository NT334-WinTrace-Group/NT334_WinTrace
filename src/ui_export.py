"""Validated CSV/JSON export of filtered events and correlation findings.

Only allowlisted fields leave the application. Values are exported exactly as
stored; the single exception is the reversible CSV formula guard below.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from src.schema import VALID_VALIDATION_STATUSES, ForensicEvent
from src.ui_findings import EventIndex, Finding, as_list, event_ids, linked_events, problems

EXPORT_VERSION = 1
EVENT_FIELDS = [
    "event_id", "case_id", "timestamp", "timestamp_type", "timestamp_desc",
    "artifact_source", "source_file", "target_path", "message", "parser", "data_type",
    "username", "confidence_level", "validation_status", "evidence_reference",
    "extra_attributes",
]
REQUIRED_EVENT_FIELDS = [
    "event_id", "case_id", "timestamp", "timestamp_type", "artifact_source",
    "source_file", "validation_status", "evidence_reference",
]
FINDING_FIELDS = [
    "finding_id", "case_id", "event_ids", "event_a_id", "event_b_id",
    "event_a_desc", "event_b_desc", "matched_rules", "time_delta_seconds",
    "time_delta_minutes", "confidence_score", "confidence_level", "validation_status",
    "explanation", "investigation_note", "evidence_references",
]
# Provenance needed to trace and interpret an event. Everything else, such as
# SIDs, host and volume identifiers or loaded-file lists, stays in the database.
EXTRA_FIELDS = [
    "source_line", "also_source_lines", "source_label", "raw_path", "raw_full_path",
    "shellbag_path", "fs_path", "fs_path_basis", "semantic_class", "semantic_basis",
    "timestamp_precision", "actor_basis", "cdburn_staging", "cross_hive_twin_ids",
    "caveat", "registry_timestamp_meaning", "verification_note", "verified_by",
    "value_cross_checked_by",
]
JSON_COLUMNS = {
    "extra_attributes", "event_ids", "matched_rules", "evidence_references",
    "time_delta_seconds", "time_delta_minutes", "confidence_score",
}
TEXT_COLUMNS = {"target_path", "message"}  # empty text is a value, not a missing one
FORMULA_PREFIXES = ("=", "+", "-", "@")


class ExportError(ValueError):
    """Raised when an exported file cannot be read back safely."""


def export_event(event: ForensicEvent) -> Dict[str, Any]:
    data = event.to_dict()
    record = {name: data[name] for name in EVENT_FIELDS if name != "extra_attributes"}
    record["extra_attributes"] = {
        name: event.extra_attributes[name]
        for name in EXTRA_FIELDS if name in event.extra_attributes
    }
    return record


def export_finding(finding: Finding) -> Dict[str, Any]:
    record = {name: finding.get(name) for name in FINDING_FIELDS}
    record["event_ids"] = event_ids(finding)
    for name in ("matched_rules", "evidence_references"):
        record[name] = as_list(finding.get(name))
    return record


def event_errors(events: Sequence[ForensicEvent]) -> Dict[int, List[str]]:
    """Return problems by position; events without problems are absent."""
    positions: Dict[Tuple[Optional[str], str], List[int]] = {}
    errors: Dict[int, List[str]] = {}
    for position, event in enumerate(events):
        positions.setdefault((event.case_id or None, event.event_id), []).append(position)
        missing = [name for name in REQUIRED_EVENT_FIELDS if not getattr(event, name)]
        if missing:
            errors.setdefault(position, []).append("missing " + ", ".join(missing))
        status = event.validation_status
        if status and status not in VALID_VALIDATION_STATUSES:
            errors.setdefault(position, []).append(f"unknown validation_status {status!r}")
    for duplicates in positions.values():
        if len(duplicates) > 1:
            for position in duplicates:
                errors.setdefault(position, []).append("duplicate event_id in this case")
    return errors


def finding_errors(findings: Sequence[Finding], index: EventIndex) -> Dict[int, List[str]]:
    """Check required fields, event references and evidence references."""
    errors: Dict[int, List[str]] = {}
    positions: Dict[Tuple[Any, Any], List[int]] = {}
    for position, finding in enumerate(findings):
        messages = list(problems(finding, index))
        if not finding.get("case_id"):
            messages.append("No case ID is recorded.")
        # A finding is only exportable when its source events are exportable.
        for problem in event_errors(linked_events(finding, index)).values():
            messages.append("Source event: " + "; ".join(problem) + ".")
        if messages:
            errors[position] = messages
        positions.setdefault(
            (finding.get("case_id") or None, finding.get("finding_id")), []
        ).append(position)
    for (_, finding_id), duplicates in positions.items():
        if finding_id and len(duplicates) > 1:
            for position in duplicates:
                errors.setdefault(position, []).append("Duplicate finding ID in this case.")
    return errors


def source_info(path: str) -> Dict[str, str]:
    """Identify a source file without revealing its folder."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return {"name": Path(path).name, "sha256": digest.hexdigest()}


def describe_filters(filters: Mapping[str, Any]) -> Dict[str, Any]:
    described = {}
    for name, value in filters.items():
        if value in (None, "", (), [], False):
            continue
        if isinstance(value, datetime):
            value = value.astimezone(timezone.utc).isoformat()
        described[name] = list(value) if isinstance(value, tuple) else value
    return described


def _manifest(kind: str, count: int, filters, sources, excluded) -> Dict[str, Any]:
    return {
        "export_version": EXPORT_VERSION,
        "kind": kind,
        "exported_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "record_count": count,
        "filters": describe_filters(filters),
        "sources": list(sources),
        "excluded_records": list(excluded),
    }


def events_to_json(events, filters, sources, excluded=()) -> str:
    document = _manifest("events", len(events), filters, sources, excluded)
    document["records"] = [export_event(event) for event in events]
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"


def findings_to_json(findings, index: EventIndex, filters, sources, excluded=()) -> str:
    """Include the cited events so references resolve inside the file itself."""
    document = _manifest("findings", len(findings), filters, sources, excluded)
    document["records"] = [export_finding(finding) for finding in findings]
    cited: Dict[Tuple[Optional[str], str], ForensicEvent] = {}
    for finding in findings:
        for event in linked_events(finding, index):
            cited[(event.case_id or None, event.event_id)] = event
    ordered = sorted(cited.values(), key=lambda event: (event.dt, event.event_id))
    document["source_events"] = [export_event(event) for event in ordered]
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"


def _guard(text: str) -> str:
    """Stop spreadsheets from running evidence text as a formula (reversible)."""
    return "'" + text if text.lstrip().startswith((*FORMULA_PREFIXES, "'")) else text


def _unguard(text: str) -> str:
    if text.startswith("'"):
        return text[1:]
    return text


def _to_csv(records: Iterable[Mapping[str, Any]], fields: Sequence[str]) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(fields)
    for record in records:
        row = []
        for name in fields:
            value = record[name]
            if value is None:
                row.append("")
            elif name in JSON_COLUMNS:
                # Numbers are never guarded: a JSON number cannot be a formula.
                row.append(json.dumps(value, ensure_ascii=False, sort_keys=True))
            else:
                row.append(_guard(str(value)))
        writer.writerow(row)
    return buffer.getvalue()


def events_to_csv(events: Sequence[ForensicEvent]) -> str:
    return _to_csv((export_event(event) for event in events), EVENT_FIELDS)


def findings_to_csv(findings: Sequence[Finding]) -> str:
    return _to_csv((export_finding(finding) for finding in findings), FINDING_FIELDS)


def read_csv(text: str, fields: Sequence[str]) -> List[Dict[str, Any]]:
    """Read an exported CSV back into the records it was written from."""
    reader = csv.reader(io.StringIO(text.removeprefix("﻿"), newline=""), strict=True)
    if next(reader, None) != list(fields):
        raise ExportError("The CSV columns do not match this export format.")
    records = []
    for number, row in enumerate(reader, start=1):
        if len(row) != len(fields):
            raise ExportError(f"CSV record {number} has {len(row)} columns, expected {len(fields)}.")
        record: Dict[str, Any] = {}
        for name, value in zip(fields, row):
            if name in JSON_COLUMNS:
                try:
                    record[name] = json.loads(value) if value else None
                except ValueError:
                    raise ExportError(f"CSV record {number} has an invalid {name}.") from None
            elif value == "" and name not in TEXT_COLUMNS:
                record[name] = None
            else:
                record[name] = _unguard(value)
        records.append(record)
    return records


def read_json(text: str) -> Dict[str, Any]:
    """Read an exported JSON document and check its counts and references."""
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise ExportError(f"The export is not valid JSON: {exc}") from None
    if not isinstance(document, dict) or document.get("export_version") != EXPORT_VERSION:
        raise ExportError("Unsupported export version.")
    records = document.get("records")
    if not isinstance(records, list) or len(records) != document.get("record_count"):
        raise ExportError("The record count does not match the exported records.")
    if document.get("kind") == "findings":
        known = {
            (event.get("case_id"), event.get("event_id"))
            for event in document.get("source_events", [])
        }
        for record in records:
            for event_id in record["event_ids"]:
                if (record["case_id"], event_id) not in known:
                    raise ExportError(
                        f"Finding {record['finding_id']} cites missing event {event_id}."
                    )
    elif document.get("kind") != "events":
        raise ExportError("Unknown export kind.")
    return document


def safe_name(value: Optional[str]) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value or "all-cases").strip("._") or "case"
