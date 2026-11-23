"""Ánh xạ path ShellBags CASE01 -> filesystem / volume (Phúc, tuần 3, ngày 16).

Giá trị mong đợi được viết NGUYÊN VĂN trong tests/fixtures/case01_path_mapping_cases.csv.
"""
import csv
import importlib.util
import json
from pathlib import Path

import pytest

import src.schema

SCHEMA_V2 = hasattr(src.schema, "VALID_TIMESTAMP_TYPES")
requires_schema_v2 = pytest.mark.skipif(not SCHEMA_V2, reason="cần schema v2 (sửa normalize_windows_path cho UNC)")

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "case01_path_mapping_cases.csv"
EVENTS = ROOT / "results" / "case01_shellbags_events.csv"
VOLUME_MAP = ROOT / "analysis" / "phuc-artifacts" / "volume_map_case01.csv"


def _load_volume_map():
    spec = importlib.util.spec_from_file_location(
        "volume_map", ROOT / "analysis" / "phuc-artifacts" / "scripts" / "volume_map.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.VolumeMap.load(VOLUME_MAP)


with FIXTURE.open(encoding="utf-8", newline="") as _f:
    CASES = list(csv.DictReader(_f))

with EVENTS.open(encoding="utf-8", newline="") as _f:
    _EXTRA = [json.loads(r["extra_attributes"]) for r in csv.DictReader(_f)]
BY_SHELLBAG_PATH = {}
for _x in _EXTRA:
    BY_SHELLBAG_PATH.setdefault(_x["shellbag_path"], []).append(_x)


def test_fixture_literals_are_raw():
    """Fixture phải chứa đúng hai dấu \\ ở đầu UNC (không bị escape/gộp khi lưu)."""
    unc = [c for c in CASES if c["expected_basis"] == "unc"]
    assert unc and all(c["expected_fs_path"].startswith("\\\\10.11.11.128\\") for c in unc)
    assert all(not c["expected_fs_path"].startswith("\\\\\\") for c in CASES)


@pytest.mark.parametrize("case", CASES, ids=[c["case"] for c in CASES])
def test_converter_mapping_matches_fixture(case):
    events = BY_SHELLBAG_PATH.get(case["shellbag_path"])
    assert events, f"không có event nào với shellbag_path={case['shellbag_path']!r}"
    for x in events:
        assert x["fs_path"] == case["expected_fs_path"]
        assert x["volume"] == case["expected_volume"]
        assert x["fs_path_basis"] == case["expected_basis"]


@requires_schema_v2
@pytest.mark.parametrize("case", [c for c in CASES if c["expected_basis"] == "unc"],
                         ids=lambda c: c["case"])
def test_team_normalizer_keeps_unc_prefix(case):
    """normalize_windows_path của nhóm không được gộp \\\\host thành \\host.
    Phụ thuộc bản sửa trong nhánh nam-week2-v2."""
    from src.schema import normalize_windows_path
    assert normalize_windows_path(case["expected_fs_path"]) == case["expected_fs_path"]


@pytest.mark.parametrize("case", [c for c in CASES if c["expected_basis"] in ("unc", "drive_letter")],
                         ids=lambda c: c["case"])
def test_schema_v2_helper_agrees_on_drive_and_unc(case):
    """So với helper extract_drive_path_from_bagmru của schema v2 (nếu nhánh đang có)."""
    schema = pytest.importorskip("src.schema")
    helper = getattr(schema, "extract_drive_path_from_bagmru", None)
    if helper is None:
        pytest.skip("schema v2 chưa có extract_drive_path_from_bagmru trên nhánh này")
    root, rel = helper(case["shellbag_path"])
    joined = root + ("\\" + rel if rel else "") if root else rel
    if case["expected_basis"] == "drive_letter" and not rel:
        joined = root + "\\"
    assert joined.rstrip("\\").lower() == case["expected_fs_path"].rstrip("\\").lower()


def test_unresolved_and_inferred_mappings_are_labelled():
    status = {c["case"]: c["mapping_status"] for c in CASES}
    assert status["P06-D-de-CDBurn"] == "unresolved"
    assert status["P07-V-alias"] == "inferred"
    assert all(status[c["case"]] == "inferred" for c in CASES if c["expected_basis"] == "user_profile_inferred")


# ---- alias / thiết bị theo thời gian (volume_map_case01.csv) ----

def test_v_alias_only_inside_proven_window():
    vm = _load_volume_map()
    inside = vm.canonical_path(r"V:\Secret Project Data\final\x.pptx", "2015-03-23T20:27:33Z")
    assert inside == r"\\10.11.11.128\secured_drive\Secret Project Data\final\x.pptx"
    assert vm.canonical_path(r"V:\Secret Project Data", "2015-03-24T14:00:00Z") is None


@pytest.mark.parametrize("when, device_serial", [
    ("2015-03-23T18:37:20Z", "4C530012450531101593"),   # LNK E:\RM#1 (RM#1)
    ("2015-03-24T13:38:31Z", "4C530012450531101593"),   # ShellBag E:\RM#1 (RM#1)
    ("2015-03-24T14:01:29Z", "4C530012550531106501"),   # ShellBag zip trên E: (RM#2)
])
def test_e_drive_resolves_to_device_by_time(when, device_serial):
    rows = _load_volume_map().resolve("E:", when)
    assert len(rows) == 1 and device_serial in rows[0]["device"]


def test_no_alias_outside_map_is_unresolved():
    assert _load_volume_map().resolve("E:", "2015-03-22T00:00:00Z") == []
