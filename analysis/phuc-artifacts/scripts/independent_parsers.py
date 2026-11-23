"""
Đường đọc độc lập (không dùng Eric Zimmerman Tools) cho LNK, Prefetch (Win7 v23) và Jump List DestList (v1),
so sánh với output LECmd / PECmd / JLECmd -> week3_validation_matrix.csv.

Parser tự viết theo đặc tả định dạng:
- LNK  : [MS-SHLLINK] ShellLinkHeader (0x1C Creation, 0x24 Access, 0x2C Write FILETIME của file đích),
         LinkInfo -> VolumeID.DriveSerialNumber.
- PF   : SCCA v23 (Windows 7, không nén): 0x80 LastRun FILETIME, 0x98 RunCount,
         vùng Filename Strings (offset 0x64, size 0x68).
- JL   : OLE compound file, stream "DestList" v1: header 32 byte; mỗi entry: 0x58 entry number,
         0x64 last-modified FILETIME, 0x70 độ dài path (ký tự), 0x72 path UTF-16LE.
Thư viện ngoài duy nhất: olefile (chỉ để mở container OLE).

Chạy (ở thư mục gốc repo), RAW_DIR = thư mục chứa Recent/, Prefetch/, JumpLists/ (bản copy evidence_work):
    pip install olefile
    python analysis/phuc-artifacts/scripts/independent_parsers.py RAW_DIR \\
        -o analysis/phuc-artifacts/week3_validation_matrix.csv
"""
import argparse
import csv
import struct
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import olefile

try:
    from Registry import Registry  # python-registry
except ImportError:  # chỉ cần khi dùng --hives
    Registry = None

ROOT = Path(__file__).resolve().parents[3]
TOOL = ROOT / "analysis" / "phuc-artifacts" / "tool_output"
EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
VER = {"LECmd": "LECmd 2026.10.3", "PECmd": "PECmd 2026.10.3", "JLECmd": "JLECmd 2026.10.5"}
SELF = "independent_parsers.py (struct/olefile " + olefile.__version__ + ")"


def ft(raw):
    v = struct.unpack("<Q", raw)[0]
    if v == 0:
        return ""
    return (EPOCH + timedelta(microseconds=v // 10)).strftime("%Y-%m-%dT%H:%M:%S")


def sec(s):
    return (s or "").replace(" ", "T")[:19]


def read_csv(p):
    csv.field_size_limit(sys.maxsize)
    with open(p, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


# ---------- parsers ----------
def parse_lnk(path):
    b = path.read_bytes()
    assert struct.unpack("<I", b[:4])[0] == 0x4C, "không phải LNK"
    flags = struct.unpack("<I", b[0x14:0x18])[0]
    out = {"TargetCreated": ft(b[0x1C:0x24]), "TargetAccessed": ft(b[0x24:0x2C]),
           "TargetModified": ft(b[0x2C:0x34]), "VolumeSerialNumber": ""}
    off = 0x4C
    if flags & 0x1:  # HasLinkTargetIDList
        off += 2 + struct.unpack("<H", b[off:off + 2])[0]
    if flags & 0x2:  # HasLinkInfo
        li = off
        li_flags = struct.unpack("<I", b[li + 8:li + 12])[0]
        if li_flags & 0x1:  # VolumeIDAndLocalBasePath
            vol = li + struct.unpack("<I", b[li + 12:li + 16])[0]
            out["VolumeSerialNumber"] = format(struct.unpack("<I", b[vol + 8:vol + 12])[0], "08X")
    return out


def parse_pf(path):
    b = path.read_bytes()
    ver, sig = struct.unpack("<I4s", b[:8])
    assert sig == b"SCCA" and ver == 23, f"chỉ hỗ trợ SCCA v23, gặp v{ver}"
    fs_off, fs_size = struct.unpack("<II", b[0x64:0x6C])
    names = b[fs_off:fs_off + fs_size].decode("utf-16-le", "ignore").split("\x00")
    return {"LastRun": ft(b[0x80:0x88]), "RunCount": str(struct.unpack("<I", b[0x98:0x9C])[0]),
            "ExecutableName": b[0x10:0x4C].decode("utf-16-le", "ignore").split("\x00")[0],
            "FilesLoaded": [n for n in names if n]}


def parse_destlist(path):
    ole = olefile.OleFileIO(str(path))
    if not ole.exists("DestList"):
        return {}
    d = ole.openstream("DestList").read()
    ver, count = struct.unpack("<II", d[:8])
    out, off = {}, 32
    for _ in range(count):
        num = struct.unpack("<I", d[off + 0x58:off + 0x5C])[0]
        last = ft(d[off + 0x64:off + 0x6C])
        n = struct.unpack("<H", d[off + 0x70:off + 0x72])[0]
        p = d[off + 0x72:off + 0x72 + n * 2].decode("utf-16-le", "ignore")
        out[format(num, "X")] = {"LastModified": last, "Path": p}
        off += 0x72 + n * 2
    return out


# ---------- so sánh ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("raw_dir")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--hives", help="Thư mục chứa UsrClass.dat, NTUSER.DAT (bản copy) để đối chiếu BagMRU")
    a = ap.parse_args()
    raw = Path(a.raw_dir)
    rows = []

    def cmp(artifact, src, line, field, tool, tool_val, ind_val, note=""):
        tv, iv = (tool_val or "").strip(), (ind_val or "").strip()
        if " ==> " in tv and tv.split(" ==> ")[0] == iv:
            # JLECmd in "chuỗi gốc ==> tên đã giải CLSID": phần gốc khớp nguyên văn
            status, note = "agreement", "JLECmd hiển thị 'gốc ==> tên đã giải CLSID'; phần gốc khớp"
        elif not tv and not iv:
            status = "agreement"
            note = note or "cả hai công cụ đều không có giá trị (trường không tồn tại trong file)"
        elif tv == iv:
            status = "agreement"
        elif not iv or not tv:
            status = "unresolved"
        else:
            status = "disagreement"
        rows.append({"artifact": artifact, "source_file": src, "tool_row": line, "field": field,
                     "tool": tool, "tool_value": tv, "independent_tool": SELF, "independent_value": iv,
                     "status": status, "note": note})

    for i, r in enumerate(read_csv(TOOL / "lecmd" / "LECmd_Output_fromF.csv"), start=2):
        name = r["SourceFile"].split("\\")[-1]
        p = parse_lnk(raw / "Recent" / name)
        for fld in ("TargetCreated", "TargetModified", "TargetAccessed"):
            cmp("LNK", name, f"LECmd_Output_fromF.csv:L{i}", fld, VER["LECmd"], sec(r[fld]), p[fld])
        cmp("LNK", name, f"LECmd_Output_fromF.csv:L{i}", "VolumeSerialNumber", VER["LECmd"],
            r["VolumeSerialNumber"], p["VolumeSerialNumber"],
            "LNK trỏ share mạng không có VolumeID" if r["NetworkPath"] else "")

    for i, r in enumerate(read_csv(TOOL / "pecmd" / "PECmd_Output_fromF.csv"), start=2):
        name = r["SourceFilename"].split("\\")[-1]
        p = parse_pf(raw / "Prefetch" / name)
        cmp("Prefetch", name, f"PECmd_Output_fromF.csv:L{i}", "LastRun", VER["PECmd"], sec(r["LastRun"]), p["LastRun"])
        cmp("Prefetch", name, f"PECmd_Output_fromF.csv:L{i}", "RunCount", VER["PECmd"], r["RunCount"], p["RunCount"])
        tool_files = sorted(x for x in r["FilesLoaded"].split(", ") if x)
        cmp("Prefetch", name, f"PECmd_Output_fromF.csv:L{i}", "FilesLoaded(count)", VER["PECmd"],
            str(len(tool_files)), str(len(p["FilesLoaded"])))
        for key in ("RESIGNATION_LETTER_(IAMAN_INFORMANT).DOCX", "~$SIGNATION_LETTER_(IAMAN_INFORMANT).DOCX",
                    "RESIGNATION_LETTER_(IAMAN_INFORMANT).XPS"):
            t = any(x.upper().endswith(key) for x in tool_files)
            s = any(x.upper().endswith(key) for x in p["FilesLoaded"])
            if t or s:
                cmp("Prefetch", name, f"PECmd_Output_fromF.csv:L{i}", f"FilesLoaded contains {key}",
                    VER["PECmd"], str(t), str(s))

    dl_cache = {}
    for i, r in enumerate(read_csv(TOOL / "jlecmd" / "AutomaticDestinations_fromF.csv"), start=2):
        name = r["SourceFile"].split("\\")[-1]
        if name not in dl_cache:
            dl_cache[name] = parse_destlist(raw / "JumpLists" / name)
        e = dl_cache[name].get(r["EntryNumber"].upper(), {})
        line = f"AutomaticDestinations_fromF.csv:L{i}"
        cmp("JumpLists", name, line, f"entry {r['EntryNumber']} LastModified", VER["JLECmd"],
            sec(r["LastModified"]), e.get("LastModified", ""))
        cmp("JumpLists", name, line, f"entry {r['EntryNumber']} Path", VER["JLECmd"],
            r["Path"], e.get("Path", ""), "so sánh nguyên văn (không đổi hoa/thường)")

    if a.hives:
        # ShellBags: LastWrite key BagMRU đọc bằng python-registry so với SBECmd.
        # FirstInteracted = LastWrite key con <BagPath>\<Slot>; Last/KeyLastWrite = LastWrite key <BagPath>.
        base = {"UsrClass.dat": "Local Settings\\Software\\Microsoft\\Windows\\Shell\\",
                "NTUSER.DAT": "Software\\Microsoft\\Windows\\Shell\\"}
        regs = {h: Registry.Registry(str(Path(a.hives) / h)) for h in base}
        rver = "python-registry " + getattr(__import__("Registry"), "__version__", "1.4")
        for i, r in enumerate(read_csv(TOOL / "sbecmd" / "Deduplicated.csv"), start=2):
            hive = r["SourceFile"].replace("/", "\\").split("\\")[-1]
            if hive not in regs:
                continue
            for col, key in (("LastWriteTime", r["BagPath"]), ("FirstInteracted", r["BagPath"] + "\\" + r["Slot"]),
                             ("LastInteracted", r["BagPath"])):
                if not r[col]:
                    continue
                try:
                    lw = regs[hive].open(base[hive] + key).timestamp().strftime("%Y-%m-%dT%H:%M:%S")
                except Exception:
                    lw = ""
                rows.append({"artifact": "ShellBags", "source_file": hive, "tool_row": f"Deduplicated.csv:L{i}",
                             "field": f"{col} ({key})", "tool": "SBECmd 2026.10.2", "tool_value": sec(r[col]),
                             "independent_tool": rver, "independent_value": lw,
                             "status": "agreement" if sec(r[col]) == lw else ("unresolved" if not lw else "disagreement"),
                             "note": "" if lw else "không mở được key"})

    with open(a.output, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    from collections import Counter
    c = Counter((r["artifact"], r["status"]) for r in rows)
    print(f"{len(rows)} phép so -> {a.output}")
    for k in sorted(c):
        print("  ", k, c[k])
    for r in rows:
        if r["status"] == "disagreement":
            print("  DISAGREE", r["artifact"], r["source_file"], r["field"], r["tool_value"], "|", r["independent_value"])


if __name__ == "__main__":
    main()
