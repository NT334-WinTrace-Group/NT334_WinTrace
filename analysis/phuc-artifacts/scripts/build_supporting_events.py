"""
Tạo event bổ trợ CASE01 (LNK, Jump Lists, Prefetch, Registry USB/mạng) theo Schema v2 của nhóm,
từ output gốc của tool (tool_output/*_fromF.csv, tool_output/registry/registry_usb_network.csv).

Nguyên tắc
- Chỉ dùng output chạy TRÊN Ổ MOUNT READ-ONLY (lượt `fromF`). Không dùng output chạy trên bản copy.
- Mỗi event có: origin (tool + file + dòng), timestamp_type theo VALID_TIMESTAMP_TYPES, case_id,
  semantic_class. Không tạo event từ "filestat" của file giả: mọi giá trị lấy từ cột parser.
- BỎ `SourceAccessed`: trên ổ mount, giá trị này là lúc tool đọc file (2026-10-28), không phải evidence.
- validation_status = "unverified" cho mọi event. Đối chiếu độc lập nằm ở week3_validation_matrix.csv.

ID: CASE01-LNK####, CASE01-JL####, CASE01-PF####, CASE01-REG#### (theo thứ tự dòng nguồn -> ổn định).

Chạy (trong analysis/phuc-artifacts/):
    python scripts/build_supporting_events.py -o case01_supporting_events.csv
"""
import argparse
import csv
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
TOOL = HERE / "tool_output"
CASE = "CASE01"
USER, SID = "informant", "S-1-5-21-2425377081-3129163575-2985601102-1000"
VERSIONS = {"LECmd": "2026.10.3", "JLECmd": "2026.10.5", "PECmd": "2026.10.3",
            "python-registry": "1.4 (scripts/registry_usb_check.py)"}
# \DEVICE\HARDDISKVOLUME2 = C: (Volume0Serial CA0C7A48 = C:, xem volume_map_case01.csv)
DEVICE_TO_DRIVE = {"\\DEVICE\\HARDDISKVOLUME2": "C:"}
USER_FILE = re.compile(r"\\USERS\\INFORMANT\\(?!APPDATA\\)|SECRET|RESIGNATION|WINTER_WHETHER", re.I)

FIELDS = ["event_id", "timestamp", "timestamp_desc", "timestamp_type", "artifact_source",
          "source_file", "target_path", "evidence_reference", "message", "data_type", "parser",
          "user_sid", "username", "confidence_level", "validation_status", "case_id",
          "extra_attributes"]


def iso(v):
    v = (v or "").strip()
    if not v or v.startswith("0001-") or v.startswith("2026-"):
        return None  # rỗng / không hợp lệ / mốc của máy phân tích
    v = v.replace(" ", "T")[:19]
    return v + "+00:00"


def read(path):
    csv.field_size_limit(sys.maxsize)
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def device_path(p):
    for dev, drive in DEVICE_TO_DRIVE.items():
        if p.upper().startswith(dev):
            return drive + p[len(dev):]
    return p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--output", default="case01_supporting_events.csv")
    args = ap.parse_args()
    out, excluded = [], {"SourceAccessed (thời điểm tool đọc file trên ổ mount)": 0}

    def add(prefix, ts, ts_type, desc, source, src_file, target, ref, msg, dtype, parser, conf, sem, extra):
        if ts is None:
            return
        out.append({
            "_prefix": prefix, "timestamp": ts, "timestamp_desc": desc, "timestamp_type": ts_type,
            "artifact_source": source, "source_file": src_file, "target_path": target,
            "evidence_reference": ref, "message": msg, "data_type": dtype, "parser": parser,
            "user_sid": SID, "username": USER, "confidence_level": conf,
            "validation_status": "unverified", "case_id": CASE,
            "extra_attributes": {"semantic_class": sem, "is_user_activity": sem == "user_interaction",
                                 "origin": "raw_tool_output", **extra},
        })

    # ---------------- LNK ----------------
    f = "lecmd/LECmd_Output_fromF.csv"
    for i, r in enumerate(read(TOOL / f), start=2):
        lnk = r["SourceFile"].split("\\")[-1]
        target = r["LocalPath"] or (r["NetworkPath"] + "\\" + r["CommonPath"] if r["NetworkPath"] else "") \
            or r["TargetIDAbsolutePath"]
        ref = f"{f.split('/')[-1]}:L{i} | file={lnk} | tool=LECmd {VERSIONS['LECmd']} | input=F: read-only mount"
        ex = {"source_line": f"{f.split('/')[-1]}:L{i}", "lnk_file": lnk, "volume_serial": r["VolumeSerialNumber"],
              "volume_label": r["VolumeLabel"], "drive_type": r["DriveType"], "network_path": r["NetworkPath"],
              "machine_id": r["MachineID"], "target_mft_entry": r["TargetMFTEntryNumber"],
              "target_size": r["FileSize"]}
        if r["SourceAccessed"]:
            excluded["SourceAccessed (thời điểm tool đọc file trên ổ mount)"] += 1
        add("LNK", iso(r["SourceCreated"]), "LNK_FileCreated", "LNK File Created (≈ lần mở đầu qua Shell)",
            "LNK", lnk, target, ref, f"Shortcut tạo khi mở {target}", "windows:lnk:link", "lecmd",
            "MEDIUM", "user_interaction",
            {**ex, "caveat": "Timestamp file system của .lnk; LNK dùng chung theo tên file, path là của lần mở cuối"})
        add("LNK", iso(r["SourceModified"]), "LNK_FileModified", "LNK File Modified (≈ lần mở gần nhất)",
            "LNK", lnk, target, ref, f"Shortcut cập nhật khi mở {target}", "windows:lnk:link", "lecmd",
            "MEDIUM", "user_interaction", ex)
        for col, tt in (("TargetCreated", "LNK_TargetCreated"), ("TargetModified", "LNK_TargetModified"),
                        ("TargetAccessed", "LNK_TargetAccessed")):
            add("LNK", iso(r[col]), tt, f"{col} của file đích (lưu trong LNK)", "LNK", lnk, target, ref,
                f"{col} của {target} tại lần mở", "windows:lnk:link", "lecmd", "LOW", "target_metadata", ex)

    # ---------------- Jump Lists ----------------
    f = "jlecmd/AutomaticDestinations_fromF.csv"
    for i, r in enumerate(read(TOOL / f), start=2):
        jl = r["SourceFile"].split("\\")[-1]
        ref = f"{f.split('/')[-1]}:L{i} | file={jl} | entry={r['EntryNumber']} | tool=JLECmd {VERSIONS['JLECmd']} | input=F: read-only mount"
        add("JL", iso(r["LastModified"]), "JumpList_TargetModified",
            "DestList entry Last Modified (lần mục được dùng gần nhất)", "JumpLists", jl, r["Path"], ref,
            f"{r['AppIdDescription']} dùng {r['Path']}", "windows:jumplist:destlist", "jlecmd", "MEDIUM",
            "user_interaction",
            {"source_line": f"{f.split('/')[-1]}:L{i}", "app_id": r["AppId"], "app_description": r["AppIdDescription"],
             "mru": r["MRU"], "entry_number": r["EntryNumber"], "interaction_count": r["InteractionCount"],
             "pinned": r["PinStatus"], "volume_serial": r["VolumeSerialNumber"], "volume_label": r["VolumeLabel"],
             "hostname": r["Hostname"],
             "caveat": ("Jump List của Explorer và ShellBags cùng do Explorer ghi -> không độc lập"
                        if r["AppId"] == "1b4dd67f29cb1962" else "")})

    # ---------------- Prefetch ----------------
    f = "pecmd/PECmd_Output_fromF.csv"
    for i, r in enumerate(read(TOOL / f), start=2):
        pf = r["SourceFilename"].split("\\")[-1]
        exe_path = device_path(r["FullPath"])
        user_files = [device_path(x) for x in r["FilesLoaded"].split(", ") if USER_FILE.search(x)]
        ref = f"{f.split('/')[-1]}:L{i} | file={pf} | tool=PECmd {VERSIONS['PECmd']} | input=F: read-only mount"
        ex = {"source_line": f"{f.split('/')[-1]}:L{i}", "prefetch_file": pf, "executable": r["ExecutableName"],
              "prefetch_hash": r["Hash"], "run_count": int(r["RunCount"] or 0), "volume_serial": r["Volume0Serial"],
              "raw_full_path": r["FullPath"], "files_loaded_user": user_files,
              "files_loaded_total": len([x for x in r["FilesLoaded"].split(", ") if x])}
        add("PF", iso(r["LastRun"]), "Prefetch_LastRun", "Last Time Executed", "Prefetch", pf, exe_path, ref,
            f"Thực thi {r['ExecutableName']} [run count {r['RunCount']}]", "windows:prefetch:execution",
            "pecmd", "HIGH", "program_execution", ex)
        for k in range(7):
            add("PF", iso(r.get(f"PreviousRun{k}")), "Prefetch_PreviousRun", f"Previous Run {k}", "Prefetch", pf,
                exe_path, ref, f"Thực thi trước đó {r['ExecutableName']}", "windows:prefetch:execution", "pecmd",
                "HIGH", "program_execution", ex)
        add("PF", iso(r["SourceCreated"]), "Prefetch_FileCreated", "Prefetch File Created (≈ lần chạy đầu +~10 s)",
            "Prefetch", pf, exe_path, ref, f"Tạo file prefetch của {r['ExecutableName']}",
            "windows:prefetch:execution", "pecmd", "LOW", "program_execution_approx",
            {**ex, "caveat": "Timestamp file system của .pf; xấp xỉ lần chạy đầu"})

    # ---------------- Registry USB / mạng ----------------
    f = "registry/registry_usb_network.csv"
    for i, r in enumerate(read(TOOL / f), start=2):
        meaning = r["timestamp_meaning"]
        if not r["timestamp_utc"] or "ProfileList" in r["key_path"] or "Control" in r["item"]:
            continue
        sem = "device_first_connection" if meaning.startswith("first_install") else "registry_write_context"
        ref = f"{f.split('/')[-1]}:L{i} | hive={r['source_hive']} | key={r['key_path']} | tool=python-registry"
        add("REG", iso(r["timestamp_utc"].rstrip("Z")), "Generic", f"Registry: {meaning}", "Registry",
            r["source_hive"], r["item"], ref, f"{r['key_path'].split(chr(92))[-1]} ({meaning}) {r['detail']}".strip(),
            "windows:registry:key", "python-registry", "MEDIUM", sem,
            {"source_line": f"{f.split('/')[-1]}:L{i}", "key_path": r["key_path"], "registry_timestamp_meaning": meaning,
             "detail": r["detail"]})

    counters = {}
    for e in out:
        p = e.pop("_prefix")
        counters[p] = counters.get(p, 0) + 1
        e["event_id"] = f"{CASE}-{p}{counters[p]:04d}"
        e["extra_attributes"] = json.dumps(e["extra_attributes"], ensure_ascii=False, sort_keys=True)
    with open(args.output, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(out)
    print(f"{len(out)} event -> {args.output}: {counters}")
    for k, v in excluded.items():
        print(f"  bỏ {v} giá trị {k}")


if __name__ == "__main__":
    main()
