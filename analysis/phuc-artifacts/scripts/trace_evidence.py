"""
Truy ngược event -> dòng output gốc của tool, và kiểm tra giá trị timestamp có đúng như dòng đó không.

Đầu vào: một hoặc nhiều CSV event (results/case01_shellbags_events.csv, case01_supporting_events.csv)
hoặc SQLite timeline (bảng `events` của src/storage.py).
Đầu ra: CSV mỗi event một dòng: event_id, source_line, raw_column, raw_value, event_timestamp, status.
status: match | mismatch | source_missing | no_source_line

Chạy (ở thư mục gốc repo):
    python analysis/phuc-artifacts/scripts/trace_evidence.py \\
        results/case01_shellbags_events.csv analysis/phuc-artifacts/case01_supporting_events.csv \\
        -o analysis/phuc-artifacts/week3_evidence_traceability.csv
    python analysis/phuc-artifacts/scripts/trace_evidence.py --db results/case01_timeline.db -o ...
"""
import argparse
import csv
import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TOOL = ROOT / "analysis" / "phuc-artifacts" / "tool_output"
SOURCES = {
    "Deduplicated.csv": TOOL / "sbecmd" / "Deduplicated.csv",
    "LECmd_Output_fromF.csv": TOOL / "lecmd" / "LECmd_Output_fromF.csv",
    "AutomaticDestinations_fromF.csv": TOOL / "jlecmd" / "AutomaticDestinations_fromF.csv",
    "PECmd_Output_fromF.csv": TOOL / "pecmd" / "PECmd_Output_fromF.csv",
    "registry_usb_network.csv": TOOL / "registry" / "registry_usb_network.csv",
}
# timestamp_type -> cột trong output gốc
COLUMN = {
    "ShellBag_FirstInteracted": "FirstInteracted", "ShellBag_LastInteracted": "LastInteracted",
    "ShellBag_KeyLastWrite": "LastWriteTime", "ShellItem_FolderCreated": "CreatedOn",
    "ShellItem_FolderModified": "ModifiedOn", "ShellItem_FolderAccessed": "AccessedOn",
    "LNK_FileCreated": "SourceCreated", "LNK_FileModified": "SourceModified",
    "LNK_TargetCreated": "TargetCreated", "LNK_TargetModified": "TargetModified",
    "LNK_TargetAccessed": "TargetAccessed", "JumpList_TargetModified": "LastModified",
    "Prefetch_LastRun": "LastRun", "Prefetch_FileCreated": "SourceCreated", "Generic": "timestamp_utc",
}
_cache = {}


def rows(name):
    if name not in _cache:
        csv.field_size_limit(2**31 - 1)
        p = SOURCES.get(name)
        if p is None or not p.exists():
            _cache[name] = None
        else:
            with p.open(newline="", encoding="utf-8-sig") as f:
                _cache[name] = list(csv.DictReader(f))
    return _cache[name]


def norm(ts):
    """'2015-03-23 20:28:17.7541480' / '2015-03-23T20:28:17+00:00' / '...Z' -> '2015-03-23T20:28:17'"""
    return (ts or "").replace(" ", "T").replace("Z", "")[:19]


def load_events(paths, db):
    if db:
        con = sqlite3.connect(db)
        con.row_factory = sqlite3.Row
        for r in con.execute("SELECT event_id, timestamp, timestamp_type, evidence_reference, extra_attributes FROM events"):
            yield dict(r)
        return
    for p in paths:
        with open(p, newline="", encoding="utf-8-sig") as f:
            yield from csv.DictReader(f)


def trace(e):
    extra = json.loads(e.get("extra_attributes") or "{}")
    ts_type = e.get("timestamp_type") or extra.get("timestamp_type", "")
    ref = e.get("evidence_reference") or extra.get("evidence_reference", "")
    line = ref.split(" | ")[0].strip()
    base = {"event_id": e["event_id"], "timestamp_type": ts_type, "source_line": line,
            "event_timestamp": norm(e["timestamp"])}
    if ":L" not in line:
        return {**base, "raw_column": "", "raw_value": "", "status": "no_source_line"}
    name, n = line.rsplit(":L", 1)
    data = rows(name)
    col = COLUMN.get(ts_type, "")
    if data is None or not n.isdigit() or not (2 <= int(n) <= len(data) + 1):
        return {**base, "raw_column": col, "raw_value": "", "status": "source_missing"}
    raw = data[int(n) - 2].get(col, "")
    status = "match" if norm(raw) == base["event_timestamp"] else "mismatch"
    return {**base, "raw_column": col, "raw_value": raw, "status": status}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="*")
    ap.add_argument("--db")
    ap.add_argument("-o", "--output", required=True)
    a = ap.parse_args()
    out = [trace(e) for e in load_events(a.csv, a.db)]
    with open(a.output, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)
    c = Counter(r["status"] for r in out)
    dup = [k for k, v in Counter(r["event_id"] for r in out).items() if v > 1]
    print(f"{len(out)} event -> {a.output}: {dict(c)}; event_id trùng: {len(dup)}")
    return 0 if set(c) == {"match"} and not dup else 1


if __name__ == "__main__":
    sys.exit(main())
