"""Check the local Python/tool environment and CASE01 input manifest."""

from __future__ import annotations

import csv
import hashlib
import importlib.metadata
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "docs" / "evidence_manifest.csv"
SHELLBAGS_PATH = ROOT / "results" / "case01_shellbags_events.csv"
EXPECTED_SHELLBAGS_ITEM_ID = "CASE01-EVT-001"
EXPECTED_SHELLBAGS_EVENTS = 383

REQUIRED_MANIFEST_COLUMNS = {
    "item_id",
    "relative_path",
    "artifact_type",
    "file_size_bytes",
    "sha256",
    "data_status",
    "integrity_status",
}
REQUIRED_SHELLBAGS_COLUMNS = {
    "event_id",
    "timestamp",
    "timestamp_type",
    "artifact_source",
    "source_file",
    "target_path",
    "evidence_reference",
    "validation_status",
    "case_id",
    "extra_attributes",
}
DEPENDENCIES = (
    "pytest",
    "pandas",
    "numpy",
    "pydantic",
    "python-registry",
    "liblnk-python",
    "evtx",
    "python-dateutil",
    "streamlit",
)
TOOLS = ("log2timeline.py", "psort.py", "docker", "wsl")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_for_scope(path: Path, hash_scope: str) -> str:
    if hash_scope == "normalized_lf_file_sha256":
        data = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        return hashlib.sha256(data).hexdigest()
    return _sha256(path)


def _read_manifest() -> Tuple[List[Dict[str, str]], List[str]]:
    errors: List[str] = []
    if not MANIFEST_PATH.is_file():
        return [], [f"Manifest not found: {MANIFEST_PATH.relative_to(ROOT)}"]

    with MANIFEST_PATH.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        columns = set(reader.fieldnames or [])
        missing_columns = REQUIRED_MANIFEST_COLUMNS - columns
        if missing_columns:
            errors.append(f"Manifest is missing columns: {', '.join(sorted(missing_columns))}")
        return list(reader), errors


def _check_manifest_rows(rows: List[Dict[str, str]]) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    seen_item_ids = set()

    for row in rows:
        item_id = (row.get("item_id") or "").strip()
        if not item_id:
            errors.append("Manifest contains a row without item_id")
        elif item_id in seen_item_ids:
            errors.append(f"Duplicate manifest item_id: {item_id}")
        seen_item_ids.add(item_id)

        relative_path = (row.get("relative_path") or "").strip()
        if not relative_path:
            errors.append(f"{item_id or '<unknown>'}: relative_path is empty")
            continue

        path = (ROOT / Path(relative_path)).resolve()
        try:
            path.relative_to(ROOT.resolve())
        except ValueError:
            errors.append(f"{item_id}: source path escapes repository root ({relative_path})")
            continue
        if not path.exists():
            scope = (row.get("hash_scope") or "unspecified hash scope").strip()
            message = (
                f"{item_id}: source is missing ({relative_path}); "
                f"cannot locally rehash scope {scope}"
            )
            if item_id == EXPECTED_SHELLBAGS_ITEM_ID:
                errors.append(message)
            else:
                warnings.append(message)
            continue

        try:
            expected_size = int(row.get("file_size_bytes") or 0)
        except ValueError:
            errors.append(f"{item_id}: invalid file_size_bytes")
            expected_size = 0

        if path.is_file():
            actual_size = path.stat().st_size
            hash_scope = (row.get("hash_scope") or "single_file_sha256").strip()
            actual_hash = _sha256_for_scope(path, hash_scope)
            expected_hash = (row.get("sha256") or "").strip().lower()
            if expected_size and actual_size != expected_size:
                errors.append(
                    f"{item_id}: size mismatch (manifest={expected_size}, actual={actual_size})"
                )
            if expected_hash and actual_hash != expected_hash:
                errors.append(
                    f"{item_id}: SHA-256 mismatch "
                    f"(manifest={expected_hash}, actual={actual_hash})"
                )
            elif not expected_hash:
                warnings.append(f"{item_id}: no SHA-256 recorded for {relative_path}")
        elif path.is_dir():
            files = [child for child in path.rglob("*") if child.is_file()]
            actual_size = sum(child.stat().st_size for child in files)
            if expected_size and actual_size != expected_size:
                errors.append(
                    f"{item_id}: directory size mismatch "
                    f"(manifest={expected_size}, actual={actual_size}, files={len(files)})"
                )
            if not (row.get("sha256") or "").strip():
                warnings.append(f"{item_id}: directory has no aggregate SHA-256")

    canonical = [
        row for row in rows
        if (row.get("item_id") or "").strip() == EXPECTED_SHELLBAGS_ITEM_ID
    ]
    if len(canonical) != 1:
        errors.append(
            f"Expected exactly one canonical ShellBags manifest row "
            f"({EXPECTED_SHELLBAGS_ITEM_ID}), found {len(canonical)}"
        )
    elif canonical[0].get("relative_path") != "results/case01_shellbags_events.csv":
        errors.append(
            f"{EXPECTED_SHELLBAGS_ITEM_ID} must point to "
            "results/case01_shellbags_events.csv"
        )
    normalized_shellbags = [
        row for row in rows
        if row.get("data_status") == "normalized_data"
        and "shellbag" in (
            f"{row.get('filename', '')} {row.get('artifact_type', '')}"
        ).casefold()
    ]
    if len(normalized_shellbags) != 1:
        errors.append(
            "Expected one normalized ShellBags manifest source to prevent "
            f"double import, found {len(normalized_shellbags)}"
        )

    return errors, warnings


def _parse_utc(value: str) -> Optional[datetime]:
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if timestamp.tzinfo is None or timestamp.utcoffset() != timezone.utc.utcoffset(timestamp):
        return None
    return timestamp


def _check_shellbags() -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    if not SHELLBAGS_PATH.is_file():
        return [f"Canonical ShellBags input is missing: {SHELLBAGS_PATH.relative_to(ROOT)}"], warnings

    with SHELLBAGS_PATH.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        columns = set(reader.fieldnames or [])
        missing_columns = REQUIRED_SHELLBAGS_COLUMNS - columns
        if missing_columns:
            errors.append(
                f"ShellBags CSV is missing columns: {', '.join(sorted(missing_columns))}"
            )
        records = list(reader)

    event_ids = [record.get("event_id", "").strip() for record in records]
    if any(not event_id for event_id in event_ids):
        errors.append("ShellBags CSV contains blank event_id values")
    if len(event_ids) != len(set(event_ids)):
        errors.append("ShellBags CSV contains duplicate event_id values")
    if not records:
        errors.append("ShellBags CSV contains no event records")
    elif len(records) != EXPECTED_SHELLBAGS_EVENTS:
        errors.append(
            f"Expected {EXPECTED_SHELLBAGS_EVENTS} CASE01 ShellBags rows, found {len(records)}"
        )

    timestamps_without_utc = [
        record.get("event_id", "<unknown>")
        for record in records
        if not _parse_utc(record.get("timestamp", ""))
    ]
    if timestamps_without_utc:
        errors.append(
            f"{len(timestamps_without_utc)} ShellBags timestamps are invalid or not UTC"
        )

    case_ids = set()
    missing_case_id = 0
    for record in records:
        event_id = record.get("event_id", "").strip()
        try:
            extra = json.loads(record.get("extra_attributes") or "{}")
        except json.JSONDecodeError:
            errors.append(f"{event_id}: malformed extra_attributes JSON")
            continue
        if not isinstance(extra, dict):
            errors.append(f"{event_id}: extra_attributes must be a JSON object")
            continue

        direct_fields = (
            "timestamp_type",
            "evidence_reference",
            "validation_status",
            "case_id",
        )
        if all(field in columns for field in direct_fields) and any(
            not (record.get(field) or "").strip() for field in direct_fields
        ):
            errors.append(f"{event_id}: missing direct Schema v2 provenance fields")

        case_id = (record.get("case_id") or extra.get("case_id") or "").strip()
        if not case_id and event_id.startswith("CASE01-"):
            case_id = "CASE01"
            missing_case_id += 1
        if not case_id:
            errors.append(f"{event_id or '<unknown>'}: cannot determine case_id")
        else:
            case_ids.add(case_id)

    if case_ids - {"CASE01"}:
        errors.append(f"Unexpected case IDs in CASE01 ShellBags CSV: {sorted(case_ids)}")
    if missing_case_id:
        warnings.append(
            f"{missing_case_id} rows lack direct case_id; CASE01 is inferred from event_id prefix"
        )
    print(
        f"CASE01 ShellBags: {len(records)} rows, {len(set(event_ids))} unique event IDs, "
        f"case IDs={sorted(case_ids)}"
    )
    return errors, warnings


def _print_environment() -> List[str]:
    warnings: List[str] = []
    print(f"Python: {sys.version.split()[0]} ({sys.executable})")
    lockfiles = (
        "requirements-lock.txt",
        "requirements.lock",
        "poetry.lock",
        "uv.lock",
        "Pipfile.lock",
    )
    found_lockfiles = [name for name in lockfiles if (ROOT / name).is_file()]
    print(f"Dependency lockfile: {', '.join(found_lockfiles) or 'NOT FOUND'}")
    if not found_lockfiles:
        warnings.append("No dependency lockfile found; requirements.txt uses version ranges")
    print("Dependency versions:")
    for dependency in DEPENDENCIES:
        try:
            version = importlib.metadata.version(dependency)
        except importlib.metadata.PackageNotFoundError:
            version = "NOT INSTALLED"
            warnings.append(f"Python dependency is not installed: {dependency}")
        print(f"  {dependency}: {version}")

    print("External tools:")
    for tool in TOOLS:
        location = shutil.which(tool)
        print(f"  {tool}: {location or 'NOT FOUND'}")
    if not (shutil.which("log2timeline.py") and shutil.which("psort.py")):
        warnings.append(
            "Native Plaso commands are not both available; check Docker/WSL runtime separately"
        )
    return warnings


def main() -> int:
    print("WinTrace Week 3 environment and input-manifest check")
    errors: List[str] = []
    warnings = _print_environment()

    manifest_rows, manifest_errors = _read_manifest()
    errors.extend(manifest_errors)
    if manifest_rows:
        print(f"Manifest: {len(manifest_rows)} rows ({MANIFEST_PATH.relative_to(ROOT)})")
        row_errors, row_warnings = _check_manifest_rows(manifest_rows)
        errors.extend(row_errors)
        warnings.extend(row_warnings)

    shellbags_errors, shellbags_warnings = _check_shellbags()
    errors.extend(shellbags_errors)
    warnings.extend(shellbags_warnings)

    for warning in warnings:
        print(f"WARNING: {warning}")
    for error in errors:
        print(f"ERROR: {error}")

    if errors:
        print(f"CHECK FAILED: {len(errors)} error(s), {len(warnings)} warning(s)")
        return 1
    print(f"CHECK PASSED: no errors, {len(warnings)} warning(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
