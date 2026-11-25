# Week 3 – Traceability, Review & Release Checklist – CASE01

**Người thực hiện:** Phúc · **Kế hoạch:** ngày 20 (traceability, regression) và 21 (review, release, bàn giao)

---

## 1. Evidence traceability (ngày 20)

File: **`week3_evidence_traceability.csv`**. Script: `scripts/trace_evidence.py`, đọc CSV hoặc SQLite (`--db`).

Mỗi event được tra theo `extra_attributes.source_line`, mở đúng dòng trong output gốc của tool, đọc cột tương ứng với `timestamp_type` rồi so timestamp.

| Tập event | Số event | match | mismatch | source_missing | no_source_line |
|---|---|---|---|---|---|
| `results/case01_shellbags_events.csv` | 383 | 383 | 0 | 0 | 0 |
| `case01_supporting_events.csv` | 309 | 309 | 0 | 0 | 0 |
| **Tổng** | **692** | **692** | 0 | 0 | 0 |

**Không đếm trùng:**
- Nạp đúng 2 file trên vào storage schema v2 cho ra 692 dòng, 692 `event_id`. Nạp lại lần nữa thêm 0 dòng (test `test_full_import_no_double_count`).
- Nếu nạp nhầm thêm `shellbags_findings.csv`, DB có 1075 dòng và `trace_evidence.py --db` báo **383 event_id trùng** rồi trả exit 1. Đây là kiểm tra chủ động, không dựa vào việc người dùng nhớ quy ước.

**Ba finding truy ngược đầy đủ** (chi tiết trong `week3_validation_cases.md` §2):

| Finding | Chuỗi |
|---|---|
| F004 – mở file Excel trên share | `JL0022` → `AutomaticDestinations_fromF.csv:L23`; `SB0133` → `Deduplicated.csv:L106`; `REG0018` → `registry_usb_network.csv:L26` |
| F005 – zip trên USB RM#2 | `JL0008` → `…fromF.csv:L9` (VSN 9E6A5B82); `SB0266` → `Deduplicated.csv:L59`; `REG0005/0010` → `registry_usb_network.csv:L7/L18` |
| R04 – mở thư xin nghỉ bằng Word | `PF0173` → `PECmd_Output_fromF.csv:L88` (FilesLoaded: `.DOCX` + `~$…DOCX`); `LNK` của docx → `LECmd_Output_fromF.csv:L9` |

**File dẫn xuất của Thi** (`results/case01_shellbags_timestamp_audit.csv`, `case01_candidates_review*.csv`): khớp 383/383 `timestamp` và `evidence_reference` với file tuần 3. Khác biệt duy nhất về **ngữ nghĩa**: Thi xếp 41 event KeyLastWrite MRU 0 là `REGISTRY_UPDATE`, còn Phúc xếp là `user_interaction` với `semantic_basis=mru0_inference`. Hai cách cùng thống nhất rằng đây **không phải ground truth độc lập**. Đề xuất giữ cả hai nhãn, không ép về một.

## 2. Regression notes

| Thay đổi tuần 3 | Ảnh hưởng | Test bảo vệ |
|---|---|---|
| 17 event `verified` → `unverified` (metadata / parent key) | `test_normalizer.py:68` của Nam (nhánh `nam-week2-v2`) assert `SB0001` là verified → **fail** khi ghép | `test_metadata_events_are_never_verified`, `test_value_checks_are_kept_after_downgrade` |
| CSV schema chung thêm 6 cột v2 + `semantic_basis` | Normalizer v2 đọc được; normalizer v1 (dev) bỏ qua cột thừa | `test_full_import_no_double_count` |
| Thêm `case01_supporting_events.csv` (309) | Timeline 383 → 692 event khi nạp cả hai | traceability 692/692 |
| `tool_output/.gitattributes` (`* -text`) | Giữ byte CRLF gốc, hash khớp số công bố tuần 2 | `test_tool_output_matches_published_hash` (6 file) |
| UNC xfail → test thật | Chỉ chạy khi có schema v2 | `test_unc_target_path_keeps_double_backslash`, `test_team_normalizer_keeps_unc_prefix` |

**Kết quả test** (2026-11-23):
- Nền `dev` + nhánh `phuc-week3`: các test mới pass; test phụ thuộc schema v2 **tự bỏ qua** (không fail).
- Nền `dev` + `nam-week2-v2` + `phuc-week3`: tất cả pass **trừ 1**: `test_normalizer.py::test_shellbags_normalizer` (dòng 68, xem trên).

## 3. Review PR evidence của Thi (C1 / C2 / C5) (ngày 21)

Đã kiểm từng tham chiếu trong `analysis/thi-timeline/week3_case01_evidence_review.md`, `week3_findings_validation.csv`, `tests/test_case01_week3_evidence.py` so với tool output gốc. **Mọi số dòng, timestamp, AppId, VSN đều đúng.**

| Candidate | Kết luận | Ghi chú cho Thi |
|---|---|---|
| **C1** – share `pricing decision` → mở Excel | ✅ **Approve, kèm ghi chú** | (1) `SB0141` (NTUSER 20:24:33) là **twin** của `SB0133`, không phải bằng chứng thứ hai. (2) `SB0158` Last Interacted = `mru0_inference`. (3) Không có `EXCEL.EXE.pf` → "Excel đã chạy" chỉ dựa trên JL + LNK. (4) `JL0022` và `LNK0001` (cùng 20:26:53) là **một** hành động mở. |
| **C2** – `V:` alias / thư mục `final` | ✅ **Approve** | `SB0147`/`SB0148` cùng dòng L62 (cùng key, unverified) = một bằng chứng. Alias V: có giới hạn thời gian (`20:26:04Z–20:29:00Z`); `valid_to` lấy theo NIST nên ghi nguồn. |
| **C5** – mở thư xin nghỉ bằng Word | ✅ **Approve** | FilesLoaded của WINWORD đã kiểm **độc lập** (parser SCCA): có `.DOCX` + `~$…DOCX`. AppId Jump List `47bb2136fda3f1ed` chưa xác định ứng dụng nên chỉ dùng làm bổ trợ. `IEXPLORE.EXE` cũng nạp `.DOCX` → phản ví dụ, không đủ để kết luận "mở" chỉ từ FilesLoaded. |

Phúc đã **chạy test trên `dev`** trước khi approve (theo quy tắc kế hoạch). Phúc không merge vì có liên quan schema.

## 4. Checklist release

- [x] Hash ảnh đĩa khớp NIST (MD5 `A49D1254…`), 145/145 file evidence_work không đổi
- [x] Output tool gốc: 6/6 khớp SHA-256 đã công bố
- [x] Không đẩy raw evidence (hive, .pf, .lnk, Jump List, ảnh đĩa) lên repo. Chỉ có CSV output, hash và fixtures
- [x] Không có timestamp thời gian phân tích (2026) trong event
- [x] Không gắn nhãn synthetic thành CASE01 (`build_dataset_inventory.py` phân loại theo nội dung)
- [x] Không gán `verified` cho metadata. `verified` chỉ gồm 13 event đã kiểm ≥ 2 công cụ
- [x] UNC giữ `\\`. `D:\de` = unresolved. `V:` = inferred có khoảng thời gian
- [x] Phiên bản tool ghi trong `evidence_reference`: SBECmd 2026.10.2, LECmd 2026.10.3, JLECmd 2026.10.5, PECmd 2026.10.3, python-registry 1.3.1, olefile 0.47
- [x] Traceability 692/692; kiểm chứng chéo 631/631 + 6 key GUI
- [ ] **Thứ tự merge:** `nam-week2-v2` → `dev` trước, rồi đến `phuc-week3` (merge thử: không xung đột)
- [ ] Nam sửa `test_normalizer.py:68`
- [ ] Quyên áp dụng `week3_manifest_corrections.csv` (P0: EVT-001 sha256 rỗng, size hive, Prefetch/LNK/JL thiếu hash, SIM-* VERIFIED)
- [ ] Toàn bộ test xanh trên `dev` sau merge → mới merge `dev` → `main`

## 5. Known limitations

1. **`D:\de` lệch NIST:** ShellBags ghi `D:\de` lúc 19:54:35Z, trong khi NIST ghi đổi tên lúc 20:40Z. Chưa giải thích được (3 VSN quang khác nhau). Ghi là **unresolved**.
2. **Không có Prefetch EXCEL/POWERPNT:** việc mở `.xlsx`/`.pptx` chỉ dựa trên JL/LNK/ShellBags.
3. **Chưa có EVTX, `$MFT`, `$UsnJrnl`, Amcache/RecentFileCache, UserAssist:** không phát hiện được đổi tên, xóa, format, logon. Ba hành động NIST (đổi tên, xóa, dọn thùng rác) chưa có artifact trực tiếp.
4. **USBSTOR ↔ volume** liên kết bằng trùng thời điểm, không có ID tường minh. USBSTOR là cấp máy, không gán được cho user.
5. **ShellBags LastInteracted** chỉ chắc chắn với MRU 0. MRU ≠ 0 chỉ là lần ghi key cha.
6. **Timestamp MAC của shell item** là FAT 2 giây, Accessed chỉ có ngày → không dùng để xếp thứ tự trong cùng 2 giây.
7. **Độ lệch 2 hive** 0–33 giây (trung vị 4) → khi ghép twin phải dùng cửa sổ theo dữ liệu, không dùng hằng số.
8. **Plaso chưa chạy trên CASE01.** Các file `plaso_raw_output*` trong `results/` là của scenario synthetic Alice.
9. **`SourceAccessed` đã bị nhiễm** bởi lần đọc ngày 2026-10-28. Kích thước file `.dd` trong manifest chưa đo.

## 6. Issue bàn giao

| # | Việc | Người nhận | Mức |
|---|---|---|---|
| 1 | Merge `nam-week2-v2` vào `dev` trước PR `phuc-week3` | Nam / Quyên | P0 |
| 2 | Sửa `tests/test_normalizer.py:68` → `unverified` hoặc dùng `SB0133` | Nam | P0 |
| 3 | Áp dụng `week3_manifest_corrections.csv` | Quyên | P0 |
| 4 | Chỉ nạp `results/case01_shellbags_events.csv` + `case01_supporting_events.csv` (không nạp `shellbags_findings.csv`) | Nam | P1 |
| 5 | Trích xuất EVTX / `$MFT` / `$UsnJrnl` nếu cần chứng minh đổi tên, xóa | Phúc (nếu còn thời gian) | P2 |
| 6 | Giải quyết mâu thuẫn `D:\de` 19:54Z với NIST 20:40Z | Thi + Phúc | P2 |
| 7 | Đo kích thước `.dd` và hash lại MD5 (`Get-FileHash … -Algorithm MD5` → `A49D1254…`) cho manifest | Phúc | P2 |
