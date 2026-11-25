# Tuần 3 – Ngày 15: Schema ↔ UI contract

**Trạng thái:** ĐỀ XUẤT, chờ Nam / Thi / Phúc xác nhận (mục 6). Nền: `dev` tại `8053b34`.
**Mẫu:** [`ui_events.json`](examples/ui_events.json), [`ui_findings.json`](examples/ui_findings.json), lấy từ output CASE01 thật và được khóa bằng `tests/test_ui_contract.py`.

## 1. Nguồn dữ liệu và owner

| Dữ liệu | UI đọc từ | Owner |
|---|---|---|
| Event | SQLite, qua `TimelineStore.query()` → `ForensicEvent` | Nam |
| Finding | JSON, mảng `CorrelationFinding`; không có bảng findings trong SQLite | Thi (engine), Nam (pipeline ghi file) |
| Provenance trong `extra_attributes` | JSON trong event | Phúc |

Khóa event là `(case_id, event_id)`. Mọi `finding.event_ids` phải tìm thấy event cùng `case_id`; thiếu thì UI báo lỗi, không tự tạo event.

## 2. Tên trường được freeze

| Trường | Vị trí | Quy tắc UI |
|---|---|---|
| `event_id`, `case_id` | trực tiếp | Luôn hiện; thiếu `case_id` → "Unspecified" |
| `timestamp` | trực tiếp | ISO 8601 UTC, hiện kèm "UTC". Đề gọi là `timestamp_utc`; **không đổi tên** |
| `timestamp_type`, `timestamp_desc` | trực tiếp | Luôn đi cùng `timestamp`; null → "Not recorded" |
| `artifact_source` | trực tiếp | Đề gọi là `artifact_type`; cột SQLite `artifact_type` chỉ là bản sao |
| `source_file` | trực tiếp | Hive hoặc file nguồn |
| `target_path` | trực tiếp | Chuẩn hóa separator, không resolve alias. Cột SQLite `object_path` là bản sao |
| `evidence_reference` | trực tiếp | Hiện nguyên văn; thiếu → cảnh báo |
| `validation_status` | trực tiếp | Hiện nguyên giá trị; null → "Not recorded". **Nguồn duy nhất** của trạng thái |
| `confidence_level` | trực tiếp | Độ tin cậy, không phải trạng thái kiểm chứng |
| `raw_path` | `extra_attributes` | Literal trước chuẩn hóa; 12 event CASE01 không có |
| `fs_path`, `fs_path_basis` | `extra_attributes` | Chỉ ShellBags; `fs_path` rỗng nghĩa là mục ảo |
| `semantic_class`, `semantic_basis`, `caveat` | `extra_attributes` | Dùng cho nhãn ở mục 3 |
| `source_line` | `extra_attributes` | Record nguồn, ví dụ `Deduplicated.csv:L106` |
| `finding_id`, `event_ids`, `matched_rules`, `time_delta_seconds`, `confidence_score`, `explanation`, `investigation_note`, `evidence_references` | finding | Dùng `event_ids`; `event_a_id`/`event_b_id` giữ để tương thích |

**Path hiển thị:** *namespace gốc* = `shellbag_path` (ShellBags) hoặc `raw_full_path` (Prefetch, nếu có), còn lại `raw_path`; *path chuẩn hóa* = `fs_path` nếu event có khóa này, ngược lại `target_path`. Lưu ý `raw_path` của ShellBags CASE01 là path đã giải, không phải namespace BagMRU.

## 3. Nhãn bằng chứng của event (chỉ hiển thị, không ghi DB)

Kiểm theo thứ tự; dòng khớp đầu tiên được dùng:

| Điều kiện | Nhãn |
|---|---|
| `semantic_class` là `target_metadata` | Metadata only: không phải hành vi người dùng |
| `semantic_class` là `registry_write_unattributed` hoặc `registry_write_context` | Registry write: không gán hành vi |
| `semantic_class` là `program_execution_approx` | Approximate execution |
| `semantic_basis` là `mru0_inference` | Inferred interaction |
| `semantic_class` là `user_interaction` | Interaction evidence |
| `semantic_class` là `program_execution` | Program execution evidence |
| `semantic_class` là `device_first_connection` | Device connection evidence (cấp máy) |
| Khác hoặc thiếu | Not classified |

`semantic_basis` còn nhận `child_key_creation`, `shell_item_metadata`, `parent_key_write`. `fs_path_basis` nhận `unc`, `drive_letter`, `user_profile_inferred` (gắn nhãn path inferred) và `virtual` (không có path filesystem).

**Bẫy:** 17 event (ví dụ `CASE01-SB0031`) có chữ `verified:` trong `evidence_reference` nhưng `validation_status` là `unverified`. UI không được suy trạng thái từ chuỗi reference.

## 4. Trạng thái finding

| `finding.validation_status` | Nhãn UI |
|---|---|
| null hoặc `unverified` | Candidate |
| `verified` | Validated |
| `disputed` | Unresolved |
| `synthetic` | Synthetic |

Engine hiện để null cho toàn bộ 6.192 finding CASE01, nên tất cả là Candidate. Điểm HIGH, event `verified` hay việc xem trên UI **không** nâng trạng thái. UI chỉ đọc, không ghi trạng thái. Kết quả duyệt thủ công C1/C2/C5 của Thi nằm ở `week3_findings_validation.csv`, là nguồn riêng và không đè lên finding.

## 5. Cần thống nhất

| # | Vấn đề | Đề xuất | Owner |
|---|---|---|---|
| 1 | `TimelineStore` tạo file khi path chưa có và chạy migration khi mở | Ngày 16: đã thêm `TimelineStore(path, read_only=True)`, chờ Nam review | Nam |
| 2 | `query()` chưa có `offset`, tổng số dòng và lọc nhiều artifact | Ngày 16: đã thêm `offset`, `artifacts`, `count_matching()`, `distinct_values()`, chờ Nam review | Nam |
| 3 | Filter path chỉ tìm `target_path`, không tìm `fs_path` / `shellbag_path` | Giữ ở v1.0 hoặc mở rộng query | Nam, Phúc |
| 4 | Ai ghi `finding.validation_status` sau review | Thi ghi vào output; UI chỉ hiển thị | Thi |
| 5 | Nhãn và câu chữ mục 3 | Phúc/Thi duyệt | Phúc, Thi |

## 6. Xác nhận

Đổi tên hoặc nghĩa của trường ở mục 2 sau khi freeze phải báo cả nhóm và sửa mẫu cùng test.

- [ ] Nam: database / query (1, 2, 3)
- [ ] Thi: finding output (4, 5)
- [ ] Phúc: evidence fields (3, 5)
