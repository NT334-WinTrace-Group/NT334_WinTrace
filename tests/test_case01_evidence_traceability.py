"""Evidence traceability CASE01 (Phúc, tuần 3, ngày 17 + 20).

- Mọi event ShellBags và event bổ trợ (LNK, Jump List, Prefetch, Registry) truy ngược được về đúng dòng
  output gốc của tool, và timestamp khớp giá trị tại dòng đó.
- Import qua normalizer + SQLite của nhóm không mất provenance và không đếm trùng.
"""
import csv
import importlib.util
import json
from pathlib import Path

import pytest

from src.normalizer import PlasoNormalizer
from src.storage import TimelineStore

ROOT = Path(__file__).resolve().parent.parent
PHUC = ROOT / "analysis" / "phuc-artifacts"
SHELLBAGS = ROOT / "results" / "case01_shellbags_events.csv"
SUPPORTING = PHUC / "case01_supporting_events.csv"


def _trace_module():
    spec = importlib.util.spec_from_file_location("trace_evidence", PHUC / "scripts" / "trace_evidence.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _rows(path):
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


@pytest.mark.parametrize("path", [SHELLBAGS, SUPPORTING], ids=["shellbags", "supporting"])
def test_every_event_traces_to_raw_tool_row(path):
    trace = _trace_module().trace
    results = [trace(e) for e in _rows(path)]
    bad = [r for r in results if r["status"] != "match"]
    assert not bad, bad[:3]


def test_supporting_events_have_origin_type_and_case():
    schema = pytest.importorskip("src.schema")
    if not hasattr(schema, "VALID_TIMESTAMP_TYPES"):
        pytest.skip("cần schema v2 (VALID_TIMESTAMP_TYPES)")
    VALID_ARTIFACTS, VALID_TIMESTAMP_TYPES = schema.VALID_ARTIFACTS, schema.VALID_TIMESTAMP_TYPES
    rows = _rows(SUPPORTING)
    assert len(rows) == 309
    assert len({r["event_id"] for r in rows}) == len(rows)
    for r in rows:
        x = json.loads(r["extra_attributes"])
        assert r["case_id"] == "CASE01"
        assert r["timestamp_type"] in VALID_TIMESTAMP_TYPES
        assert r["artifact_source"] in VALID_ARTIFACTS
        assert x["origin"] == "raw_tool_output"
        assert "input=F: read-only mount" in r["evidence_reference"] or r["artifact_source"] == "Registry"
        assert r["validation_status"] == "unverified"


def test_supporting_event_actor_attribution_matches_artifact_scope():
    rows = _rows(SUPPORTING)
    for r in rows:
        x = json.loads(r["extra_attributes"])
        assert x["case_profile"] == "informant"
        if r["artifact_source"] == "Prefetch":
            assert not r["username"] and not r["user_sid"]
            assert x["actor_basis"] == "machine_level_unattributed"
        elif r["artifact_source"] in {"LNK", "JumpLists"}:
            assert r["username"] == "informant"
            assert r["user_sid"].endswith("-1000")
            assert x["actor_basis"] == "artifact_in_user_profile"
        elif r["artifact_source"] == "Registry":
            if r["source_file"].upper() == "NTUSER.DAT":
                assert r["username"] == "informant"
                assert r["user_sid"].endswith("-1000")
                assert x["actor_basis"] == "user_hive"
            else:
                assert r["source_file"].upper() in {"SYSTEM", "SOFTWARE"}
                assert not r["username"] and not r["user_sid"]
                assert x["actor_basis"] == "machine_level_unattributed"


def test_no_analysis_time_contamination():
    """SourceAccessed (= lúc tool đọc file, 2026-10-28) không được thành event."""
    for path in (SHELLBAGS, SUPPORTING):
        assert all(not r["timestamp"].startswith("2026") for r in _rows(path))


def test_word_loaded_the_letter_and_its_lock_file():
    """R04 positive: Prefetch WINWORD có cả file .docx lẫn file khóa ~$ (Word mở để chỉnh sửa)."""
    pf = [json.loads(r["extra_attributes"]) for r in _rows(SUPPORTING)
          if r["timestamp_type"] == "Prefetch_LastRun"]
    word = next(x for x in pf if x["executable"] == "WINWORD.EXE")
    names = {p.split("\\")[-1] for p in word["files_loaded_user"]}
    assert "RESIGNATION_LETTER_(IAMAN_INFORMANT).DOCX" in names
    assert "~$SIGNATION_LETTER_(IAMAN_INFORMANT).DOCX" in names


def test_full_import_no_double_count(tmp_path):
    sb, e1 = PlasoNormalizer.normalize_file_with_report(str(SHELLBAGS), "shellbags")
    sup, e2 = PlasoNormalizer.normalize_file_with_report(str(SUPPORTING), "supporting")
    assert e1 == [] and e2 == []
    with TimelineStore(str(tmp_path / "t.db")) as s:
        s.insert_events(sb)
        s.insert_events(sup)
        assert s.insert_events(sb + sup) == 0
        total, distinct = s.connection.execute(
            "SELECT COUNT(*), COUNT(DISTINCT event_id) FROM events").fetchone()
    assert total == distinct == 383 + 309


# SHA-256 công bố trong artifact_validation_week2.md §8 (tính trên byte gốc của tool, CRLF).
PUBLISHED_SHA256 = {
    "sbecmd/Deduplicated.csv": "1bad7daaf24e87efccd37d19902b142f08b6bbe06aedeee8979e20b6ffcd770b",
    "lecmd/LECmd_Output_fromF.csv": "cf364cd3aa58ee559895faa2f4e5ad9a7367e785201a38d28f8a680d4085f162",
    "jlecmd/AutomaticDestinations_fromF.csv": "2f5b90c0bbd68bd4c8de9e59bde1a8bdde10055a87cf27e26a22d3d7897fe282",
    "pecmd/PECmd_Output_fromF.csv": "d1ee9a520059b374d253ec1d8af7c6dc1195924407f3b75367195ec4293f3ac3",
    "pecmd/PECmd_Output_Timeline_fromF.csv": "b11dc0b6642d70b31d1c66d247361affbbbad0c4d7f77096162b2cd4597b8824",
    "registry/registry_usb_network.csv": "522f2e053cd870231de7eb0199c36a891fca1c2397136976dcf8ca68f95cb4c2",
}


@pytest.mark.parametrize("rel, expected", sorted(PUBLISHED_SHA256.items()))
def test_tool_output_matches_published_hash(rel, expected):
    """Kiểm tra trên byte gốc; chuẩn hóa về CRLF để không phụ thuộc cấu hình git của máy clone."""
    import hashlib
    data = (PHUC / "tool_output" / rel).read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    assert hashlib.sha256(data).hexdigest() == expected
