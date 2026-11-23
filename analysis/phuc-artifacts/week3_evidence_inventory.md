# Week 3 – Evidence Inventory & Artifact Mapping – CASE01

**Người thực hiện:** Phúc · **Kế hoạch:** ngày 15 (inventory, manifest) và ngày 17 (artifact bổ trợ)
**Quy ước:** giờ UTC; giờ máy nghi phạm = UTC − 4h (EDT). Ba mức kết luận: Observed · Inferred · NIST-confirmed.

---

## 1. Evidence gốc và tính toàn vẹn

| Đối tượng | Nguồn | Kiểm tra | Kết quả |
|---|---|---|---|
| Ảnh đĩa `cfreds_2015_data_leakage_pc.dd` | NIST CFReDS Data Leakage Case | MD5 so với NIST (leakage-answers.pdf §4.1) | ✅ `A49D1254C873808C58E6F1BCD60B5BDE`; SHA-256 `026C1436…98BE4E2` |
| 145 file trong `evidence_work/` (hive, Prefetch, LNK, Jump List, Recycle Bin) | Copy từ ổ mount read-only F: ngày 2026-10-28 | Hash lại ngày 2026-11-23, so với `hashes_evidence_work_20261028_102116.csv` | ✅ **145/145 khớp** – không thay đổi sau gần 4 tuần |
| 124 file thô (LNK, Prefetch, Jump List) chuyển sang môi trường parse độc lập | `evidence_work/` | Hash sau khi chuyển | ✅ 124/124 khớp `case01_source_inventory.csv` |

Danh sách từng file (đường dẫn, kích thước, SHA-256, mtime): **`case01_source_inventory.csv`**.

## 2. Inventory dataset trong repo

Tạo tự động: `python analysis/phuc-artifacts/scripts/build_dataset_inventory.py -o analysis/phuc-artifacts/week3_repo_dataset_inventory.csv`.
Script phân loại theo **nội dung** file (không theo tên). Hash tính sau khi chuẩn hóa xuống dòng về LF để không phụ thuộc cấu hình git.

| Dataset | Loại | Parser / tool | Bản ghi | ID bản ghi nguồn | Tái tạo |
|---|---|---|---|---|---|
| `tool_output/sbecmd/Deduplicated.csv` | CASE01 – output gốc | SBECmd 2026.10.2 (hive bản copy) | 109 | `Deduplicated.csv:L<n>` | chạy lại SBECmd (`scripts/day3_4_run_tools.ps1`) |
| `tool_output/lecmd/LECmd_Output_fromF.csv` | CASE01 – output gốc | LECmd 2026.10.3 (ổ F: read-only) | 15 | `LECmd_Output_fromF.csv:L<n>` | như trên |
| `tool_output/jlecmd/AutomaticDestinations_fromF.csv` | CASE01 – output gốc | JLECmd 2026.10.5 (ổ F:) | 31 | `AutomaticDestinations_fromF.csv:L<n>` | như trên |
| `tool_output/pecmd/PECmd_Output_fromF.csv` | CASE01 – output gốc | PECmd 2026.10.3 (ổ F:) | 95 | `PECmd_Output_fromF.csv:L<n>` | như trên |
| `tool_output/registry/registry_usb_network.csv` | CASE01 – output gốc | `registry_usb_check.py` (python-registry) | 26 | `registry_usb_network.csv:L<n>` | `scripts/registry_usb_check.py` |
| `shellbags_findings.csv` | CASE01 – dẫn xuất (v2) | `sbecmd_to_findings.py` + `apply_verification_policy.py` | 383 | `CASE01-SB####` | 2 script trên |
| `results/case01_shellbags_events.csv` | CASE01 – dẫn xuất (schema chung) | `to_team_schema.py` | 383 | `CASE01-SB####` | `to_team_schema.py` |
| `case01_supporting_events.csv` **(mới)** | CASE01 – dẫn xuất | `build_supporting_events.py` | 309 | `CASE01-LNK/JL/PF/REG####` | `build_supporting_events.py` |
| `results/case01_shellbags_timestamp_audit.csv`, `case01_candidates_review*.csv`, `case01_shellbags_groups.csv`, `case01_shellbags_path_context.csv`, `case01_review_v2/` | CASE01 – dẫn xuất (Thi) | `analysis/thi-timeline/*.py` | 91–452 | event ID của Phúc | script của Thi |
| `results/sample_timeline.*`, `correlation_findings.*`, `plaso_raw_output.csv` | **synthetic (Alice)** | prototype tuần 1 | 7–8 | `EVT-*` | – |

Kết quả chạy (2026-11-23): **29 file** – 23 `case01_real`, 5 `synthetic_alice`, 1 `mixed` (`docs/evidence_manifest.csv` chứa cả dòng `CASE01-*` lẫn `SIM-*`, là đúng thiết kế nhưng các dòng SIM phải mang nhãn NOT_VERIFIED – xem §3). Chi tiết: **`week3_repo_dataset_inventory.csv`**.

> ⚠️ Các file synthetic trong `results/` **không có cột `case_id`**. Không được nạp chung với CASE01. Plaso **chưa chạy trên CASE01** (`plaso_pipeline_guide.md` đã ghi rõ: `plaso_raw_output_real.*` là `filestat` của scenario Alice).

**Kiểm tra nhập trùng (kế hoạch ngày 15):** nạp cả `shellbags_findings.csv` và `results/case01_shellbags_events.csv` vào storage schema v2 vẫn ra **766 dòng cho 383 `event_id`** (fingerprint khác nhau). Pipeline hiện chỉ dùng `--shellbags results/case01_shellbags_events.csv` (`docs/plaso_pipeline_guide.md`), Thi cũng chỉ dùng file này. Vì vậy **không có nhập trùng trong luồng hiện tại**. `scripts/trace_evidence.py` báo lỗi nếu DB có `event_id` trùng.

## 3. Đề xuất sửa `docs/evidence_manifest.csv`

Manifest thuộc quyền Quyên và đang được sửa trên nhánh `nam-week2-v2`, nên Phúc **không sửa trực tiếp** (tránh xung đột). Toàn bộ đề xuất kèm căn cứ nằm trong **`week3_manifest_corrections.csv`**. Các lỗi P0:

| Mục | Sai | Đúng |
|---|---|---|
| `CASE01-EVT-001` sha256 | `e3b0c442…b855` = **hash của chuỗi rỗng** | tính lại sau merge |
| `CASE01-EVD-001` UsrClass.dat size | 1 572 864 | **786 432** |
| `CASE01-EVD-002` NTUSER.DAT size | 262 144 | **1 048 576** |
| `CASE01-EVD-003/004/005` (Prefetch, LNK, Jump List) | không có hash nhưng ghi `VERIFIED` | list-hash + hash từng file |
| `SIM-EVD-001…006` | ghi `VERIFIED`; cột sha256 chỉ có 32 ký tự (độ dài MD5) | `NOT_VERIFIED` / `SYNTHETIC` |

## 4. Chính sách `verified` (thay đổi so với tuần 2)

Quy tắc kế hoạch: **không gán VERIFIED khi chỉ có timestamp metadata**.

- Script `scripts/apply_verification_policy.py` hạ **17/30** event ShellBags từ `verified` về `unverified`:
  - 15 event `ShellItem_Folder*` (MAC của đối tượng lưu trong shell item)
  - 2 event `ShellBag_KeyLastWrite` có MRU ≠ 0 (`SB0150`, `SB0157`: lần ghi key cha)
- **Còn 13 event `verified`**: tất cả là First/Last Interacted hoặc KeyLastWrite MRU 0 của F001, F004, F005, đã kiểm bằng ShellBags Explorer **và** python-registry.
- Kết quả đối chiếu giá trị **không bị mất**: giữ trong `evidence_reference` ("verified: ShellBags Explorer …") và `extra_attributes.value_cross_checked_by`, kèm `verification_note`.
- Thêm `extra_attributes.semantic_basis` để tách **căn cứ** của `semantic_class`:

| semantic_basis | Số event | Ý nghĩa |
|---|---|---|
| `child_key_creation` | 70 | First Interacted = LastWrite key con (đã kiểm 3 công cụ) |
| `mru0_inference` | 82 | Last Interacted / KeyLastWrite ở MRU 0: **diễn giải**, không phải ground truth độc lập |
| `parent_key_write` | 63 | KeyLastWrite MRU ≠ 0: không gán được cho thư mục |
| `shell_item_metadata` | 168 | MAC của đối tượng |

**Ảnh hưởng tới nhóm:** `tests/test_normalizer.py::test_shellbags_normalizer` trên nhánh `nam-week2-v2` đang khẳng định `CASE01-SB0001` (event metadata) là `verified`. Đề xuất Nam đổi dòng 68 thành `assertEqual(ev0.validation_status, "unverified")`, hoặc kiểm một event hành động như `CASE01-SB0133`.

## 5. Mapping artifact bổ trợ (ngày 17)

File: **`case01_supporting_events.csv`** – 309 event, schema v2 (cột chính `timestamp_type`, `evidence_reference`, `validation_status`, `case_id`).

| Artifact | timestamp_type | semantic_class | Số event | Cột nguồn |
|---|---|---|---|---|
| LNK | `LNK_FileCreated` / `LNK_FileModified` | `user_interaction` (≈ lần mở đầu / cuối) | 15 / 15 | `SourceCreated` / `SourceModified` |
| LNK | `LNK_Target{Created,Modified,Accessed}` | `target_metadata` | 13 × 3 | `Target*` |
| Jump List | `JumpList_TargetModified` | `user_interaction` (DestList entry cập nhật) | 31 | `LastModified` |
| Prefetch | `Prefetch_LastRun` | `program_execution` | 95 | `LastRun` |
| Prefetch | `Prefetch_FileCreated` | `program_execution_approx` (≈ lần chạy đầu + ~10 s) | 95 | `SourceCreated` |
| Registry | `Generic` | `device_first_connection` / `registry_write_context` | 19 | `registry_usb_network.csv` |

Mỗi event có: `origin=raw_tool_output`, `source_line` (file + dòng), tool + phiên bản, `input=F: read-only mount`, `case_id=CASE01`, `validation_status=unverified`.
Prefetch giữ `files_loaded_user` (file trong profile `informant` mà chương trình đã nạp) để Thi dùng cho R04.

**Đã loại khỏi timeline:**

| Giá trị | Lý do |
|---|---|
| `SourceAccessed` của LNK / Jump List / Prefetch | Trên ổ mount, giá trị = **2026-10-28 03:51** (lúc tool đọc file). Là dấu vết của quá trình phân tích, không phải evidence |
| Toàn bộ output LNK/JL/Prefetch lượt `20261028_103708` | Chạy trên bản copy: Created/Accessed = thời điểm copy |
| `CreationTime` của Jump List | Do JLECmd suy ra từ ObjectID (droid), không phải hành động |
| MAC file đích nhúng trong Jump List | Trùng mã `JumpList_TargetModified` đã dùng cho DestList; tránh lẫn ngữ nghĩa |

**Không có / chưa có trong repo:**

| Artifact | Trạng thái | Ghi chú |
|---|---|---|
| Recycle Bin (`$I`/`$R`) | **unavailable** – thật sự trống | 3 thư mục SID chỉ có `desktop.ini`; RBCmd 0 file. NIST: thùng rác đã bị dọn (11:14 EDT 25/03) |
| EVTX | **chưa trích xuất** | Chưa kiểm tra trong ảnh đĩa (vị trí chuẩn `Windows\System32\winevt\Logs`), chưa copy/parse. Nếu cần: `EvtxECmd.exe -d F:\Windows\System32\winevt\Logs --csv <out>` trên ổ mount read-only |
| `$MFT`, `$UsnJrnl` | **chưa trích xuất** | Cần cho đổi tên/xóa/format (3 hành động NIST chưa bắt được) |
| Amcache / RecentFileCache.bcf, UserAssist | **chưa kiểm tra** | Win7 thường dùng RecentFileCache.bcf; Amcache.hve chỉ có khi đã cài bản cập nhật tương ứng |

LNK và Prefetch **có dữ liệu CASE01 thật** (không phải synthetic), nên không có rủi ro P0 về phạm vi.

## 6. Bàn giao

- **Nam:** nạp `results/case01_shellbags_events.csv` + `analysis/phuc-artifacts/case01_supporting_events.csv` (692 event, đã thử trên storage schema v2: 0 lỗi, idempotent, 692/692 truy ngược khớp). Không nạp `shellbags_findings.csv`.
- **Thi:** `semantic_class` + `semantic_basis`, `fs_path`, `volume_map_case01.csv` và helper `scripts/volume_map.py` (alias theo thời gian).
- **Quyên:** `week3_manifest_corrections.csv`.
