"""
Lập inventory các dataset trong repo: SHA-256, số bản ghi, nguồn, CASE01 thật hay synthetic.

Phân loại dựa trên NỘI DUNG file, không dựa vào tên:
- case01_real      : có bản ghi CASE01 và không có dấu hiệu scenario Alice
- synthetic_alice  : có dấu hiệu Alice / DESKTOP-WK1-PC / mốc 2026-10-2x và không có CASE01
- mixed            : có cả hai  -> cần xử lý (không được trộn)
- unknown          : không nhận diện được

Chạy (ở thư mục gốc repo):
    python analysis/phuc-artifacts/scripts/build_dataset_inventory.py \\
        -o analysis/phuc-artifacts/week3_repo_dataset_inventory.csv
"""
import argparse
import csv
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGETS = ["results", "analysis/phuc-artifacts", "analysis/thi-timeline", "docs"]
EXTS = {".csv", ".json"}
ALICE = re.compile(r"alice|DESKTOP-WK1|scenario_wintrace", re.I)
CASE01 = re.compile(r"CASE01|informant|10\.11\.11\.128|cfreds_2015_data_leakage", re.I)

# Nguồn sinh ra từng nhóm file (ghi tay, kiểm bằng lịch sử git)
PRODUCER = [
    ("analysis/phuc-artifacts/tool_output/sbecmd/", "SBECmd 2026.10.2 trên hive bản copy (evidence_work/hives)"),
    ("analysis/phuc-artifacts/tool_output/lecmd/", "LECmd 2026.10.3 trên ổ mount read-only F:"),
    ("analysis/phuc-artifacts/tool_output/jlecmd/", "JLECmd 2026.10.5 trên ổ mount read-only F:"),
    ("analysis/phuc-artifacts/tool_output/pecmd/", "PECmd 2026.10.3 trên ổ mount read-only F:"),
    ("analysis/phuc-artifacts/tool_output/registry/", "scripts/registry_usb_check.py (python-registry 1.3.1) trên hive bản copy"),
    ("analysis/phuc-artifacts/shellbags_findings.csv", "scripts/sbecmd_to_findings.py + apply_verification_policy.py"),
    ("analysis/phuc-artifacts/case01_supporting_events.csv", "scripts/build_supporting_events.py từ tool_output/*_fromF.csv"),
    ("results/case01_shellbags_events.csv", "scripts/to_team_schema.py từ shellbags_findings.csv + Deduplicated.csv"),
    ("results/case01_", "Thi – analysis/thi-timeline/*.py, dẫn xuất từ results/case01_shellbags_events.csv"),
    ("analysis/thi-timeline/", "Thi"),
    ("docs/evidence_manifest.csv", "Quyên/Nam – nhập tay"),
    ("results/", "Nam – scenario/prototype"),
    ("analysis/phuc-artifacts/", "Phúc"),
]


def producer(rel):
    for prefix, who in PRODUCER:
        if rel.startswith(prefix):
            return who
    return ""


def records(path):
    try:
        if path.suffix == ".json":
            d = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(d, list):
                return len(d)
            if isinstance(d, dict):
                for k in ("findings", "events", "results"):
                    if isinstance(d.get(k), list):
                        return len(d[k])
                return 1
        with path.open(encoding="utf-8-sig", newline="") as f:
            return sum(1 for _ in csv.DictReader(f))
    except Exception:
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--output", default="week3_repo_dataset_inventory.csv")
    args = ap.parse_args()
    rows = []
    for t in TARGETS:
        for p in sorted((ROOT / t).rglob("*")):
            if not p.is_file() or p.suffix.lower() not in EXTS:
                continue
            rel = p.relative_to(ROOT).as_posix()
            if rel.endswith("week3_repo_dataset_inventory.csv"):
                continue
            data = p.read_bytes()
            text = data.decode("utf-8", errors="ignore")
            has_case = bool(CASE01.search(text))
            has_alice = bool(ALICE.search(text))
            label = ("mixed" if has_case and has_alice else "case01_real" if has_case
                     else "synthetic_alice" if has_alice else "unknown")
            rows.append({
                "path": rel,
                "sha256": hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest(),
                "bytes": len(data),
                "records": records(p),
                "dataset_class": label,
                "producer": producer(rel),
            })
    out = Path(args.output)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    from collections import Counter
    print(f"{len(rows)} file -> {out}; ", dict(Counter(r["dataset_class"] for r in rows)))
    for r in rows:
        if r["dataset_class"] in ("mixed", "unknown"):
            print("  CẦN XEM:", r["dataset_class"], r["path"])


if __name__ == "__main__":
    main()
