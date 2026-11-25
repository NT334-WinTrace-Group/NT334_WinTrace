"""
Áp dụng chính sách kiểm chứng tuần 3 cho shellbags_findings.csv (v2).

Quy tắc (kế hoạch tuần 3, ngày 15): KHÔNG gán `verified` khi event chỉ là timestamp metadata.
- ShellItem_Folder{Created,Modified,Accessed}: MAC của đối tượng lưu trong shell item -> metadata.
- ShellBag_KeyLastWrite với MRU != 0: lần ghi key cha, không gán được cho thư mục này.
Các event đó bị hạ về `unverified`. Phần "verified: <tool>" trong evidence_reference được GIỮ NGUYÊN:
nó ghi nhận GIÁ TRỊ đã khớp công cụ độc lập, không phải hành động đã được xác minh.

Script idempotent: chạy lại không đổi gì thêm. In danh sách event đã đổi.

Chạy (trong analysis/phuc-artifacts/):
    python scripts/apply_verification_policy.py shellbags_findings.csv
"""
import argparse
import csv


def is_metadata_only(row):
    t = row["timestamp_type"]
    if t.startswith("ShellItem_"):
        return True
    if t == "ShellBag_KeyLastWrite":
        mru = ""
        for part in row["evidence_reference"].split(" | "):
            if part.startswith("MRU="):
                mru = part[4:]
        return mru != "0"
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    args = ap.parse_args()
    with open(args.path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames
        rows = list(reader)
    changed = []
    for r in rows:
        if r["validation_status"] == "verified" and is_metadata_only(r):
            r["validation_status"] = "unverified"
            changed.append(r["event_id"])
    with open(args.path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print(f"{len(changed)} event hạ từ verified -> unverified: {', '.join(changed) or '-'}")
    print(f"còn verified: {sum(r['validation_status'] == 'verified' for r in rows)}")


if __name__ == "__main__":
    main()
