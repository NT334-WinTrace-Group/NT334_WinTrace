"""
Độ lệch thực tế giữa cùng một thư mục được ghi ở NTUSER.DAT và UsrClass.dat (cross-hive twins).

Đầu vào: results/case01_shellbags_events.csv (trường extra_attributes.cross_hive_twin_ids).
Đầu ra : CSV mỗi cặp một dòng + thống kê. Không giả định con số cố định (ví dụ "2 giây").

Chạy (ở thư mục gốc repo):
    python analysis/phuc-artifacts/scripts/cross_hive_deltas.py \\
        -o analysis/phuc-artifacts/week3_cross_hive_deltas.csv
"""
import argparse
import csv
import json
import statistics
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", default=str(ROOT / "results" / "case01_shellbags_events.csv"))
    ap.add_argument("-o", "--output", required=True)
    a = ap.parse_args()
    with open(a.events, newline="", encoding="utf-8") as f:
        ev = {r["event_id"]: r for r in csv.DictReader(f)}
    pairs, seen = [], set()
    for eid, r in ev.items():
        x = json.loads(r["extra_attributes"])
        for t in x.get("cross_hive_twin_ids", []):
            key = tuple(sorted((eid, t)))
            if key in seen:
                continue
            seen.add(key)
            u, n = (r, ev[t]) if r["source_file"] == "UsrClass.dat" else (ev[t], r)
            d = (datetime.fromisoformat(n["timestamp"]) - datetime.fromisoformat(u["timestamp"])).total_seconds()
            pairs.append({"timestamp_type": x["timestamp_type"], "fs_path": x["fs_path"] or x["shellbag_path"],
                          "usrclass_event": u["event_id"], "usrclass_utc": u["timestamp"],
                          "ntuser_event": n["event_id"], "ntuser_utc": n["timestamp"],
                          "delta_seconds_ntuser_minus_usrclass": int(d)})
    pairs.sort(key=lambda p: (p["usrclass_utc"], p["timestamp_type"]))
    with open(a.output, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(pairs[0].keys()))
        w.writeheader()
        w.writerows(pairs)
    ds = [abs(p["delta_seconds_ntuser_minus_usrclass"]) for p in pairs]
    print(f"{len(pairs)} cặp -> {a.output}")
    print(f"  |delta| giây: min {min(ds)}, median {statistics.median(ds)}, max {max(ds)}; "
          f"NTUSER muộn hơn UsrClass ở {sum(p['delta_seconds_ntuser_minus_usrclass'] > 0 for p in pairs)} cặp")


if __name__ == "__main__":
    main()
