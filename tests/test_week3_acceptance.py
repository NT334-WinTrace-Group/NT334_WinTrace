"""Week 3 evidence manifest and CASE01 review-candidate regressions."""

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _csv(path):
    with (ROOT / path).open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def test_manifest_corrects_derived_dataset_size_and_hash():
    import hashlib
    manifest = {row["item_id"]: row for row in _csv("docs/evidence_manifest.csv")}
    row = manifest["CASE01-EVT-001"]
    data = (ROOT / row["relative_path"]).read_bytes()
    if row["hash_scope"] == "normalized_lf_file_sha256":
        data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    elif row["hash_scope"] != "working_tree_file_sha256":
        raise AssertionError(f"Unsupported hash scope: {row['hash_scope']}")
    assert row["file_size_bytes"] == "575015"
    assert row["sha256"] == hashlib.sha256(data).hexdigest()
    assert row["integrity_status"] == "REGENERABLE"
    assert row["hash_scope"] == "normalized_lf_file_sha256"

    supporting = manifest["CASE01-EVT-002"]
    data = (ROOT / supporting["relative_path"]).read_bytes()
    import hashlib
    assert supporting["file_size_bytes"] == str(len(data))
    assert supporting["sha256"] == hashlib.sha256(data).hexdigest()


def test_manifest_does_not_mark_synthetic_or_missing_sources_verified():
    rows = _csv("docs/evidence_manifest.csv")
    for row in rows:
        if row["data_status"] == "synthetic":
            assert row["integrity_status"] != "VERIFIED"
            assert row["sha256"] == ""
    image = next(row for row in rows if row["item_id"] == "CASE01-IMG-001")
    assert image["file_size_bytes"] == ""
    assert image["acquisition_date"] == ""
    assert image["md5"] == "A49D1254C873808C58E6F1BCD60B5BDE"


def test_manifest_tool_output_hashes_match_current_repository_bytes():
    import hashlib
    manifest = {row["item_id"]: row for row in _csv("docs/evidence_manifest.csv")}
    for item_id in ("CASE01-OUT-002", "CASE01-OUT-003", "CASE01-OUT-004", "CASE01-OUT-005", "CASE01-OUT-006"):
        row = manifest[item_id]
        data = (ROOT / row["relative_path"]).read_bytes()
        assert int(row["file_size_bytes"]) == len(data)
        assert row["sha256"] == hashlib.sha256(data).hexdigest()
        assert row["integrity_status"] == "REGENERABLE"


def test_case01_has_three_unverified_review_candidates_with_source_references():
    rows = _csv("analysis/thi-timeline/week3_findings_validation.csv")
    case_rows = [row for row in rows if row["case_id"] == "CASE01"]
    assert [row["candidate_id"] for row in case_rows] == [
        "CASE01-C1", "CASE01-C2", "CASE01-C5"
    ]
    for row in case_rows:
        assert row["validation_status"] == "unverified"
        assert row["source_references"]
        assert row["not_proven"]
        assert row["caveat"]


