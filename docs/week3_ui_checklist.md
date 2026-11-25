# Tuần 3 – Ngày 15: Kiểm kê UI

Kiểm kê ban đầu theo `src/app.py` tại `dev` `8053b34`; đã cập nhật đến Ngày 19. `[x]` đã có, `[ ]` còn thiếu.

## Ngày 16 – Timeline và filters
- [x] Bảng event; lọc ngày UTC, path, keyword, một artifact (AND)
- [x] P0: DB mặc định `results/case01_timeline.db` không có; path sai sẽ tạo file DB rỗng
- [x] P0: cột `timestamp_type`, `source_file` và `case_id` trong bảng
- [x] P1: lọc theo giờ, lọc `case_id` và `validation_status` (query đã hỗ trợ)
- [x] P1: phân trang và tổng số kết quả; hiện chỉ lấy N event đầu
- [x] P1: tách empty state: chưa có DB / DB rỗng / filter không khớp / lỗi đọc
- [x] P1: filter không khớp không được chặn tab Findings

## Ngày 17 – Evidence detail
- [x] timestamp và type, source, case, message, path, status, reference, extra JSON
- [x] P0: `event_id`, `timestamp_desc`, `source_line` hiện rõ trong chi tiết
- [x] P0: namespace gốc cạnh path chuẩn hóa; path dài không vỡ
- [x] P0: nhãn bằng chứng (contract mục 3) và `caveat`
- [x] P1: cảnh báo khi thiếu `evidence_reference`

## Ngày 18 – Findings
- [x] finding_id, confidence, rules, time delta, explanation, references
- [x] P0: findings mặc định là Alice; chặn trộn với CASE01
- [x] P0: nhãn Candidate / Validated / Unresolved lấy từ dữ liệu
- [x] P0: mở được event nguồn kể cả khi nằm ngoài filter timeline
- [x] P1: lọc rule, status; phân trang (6.192 finding); hiện path và `investigation_note`
- [x] P1: 3 candidate kiểm tra:
  - [x] C1: `CASE01-SB0133` + `CASE01-JL0022`
  - [x] C2: `CASE01-SB0147` + `CASE01-JL0020`
  - [x] C5: `CASE01-PF0173` + `CASE01-LNK0037`

## Ngày 19 – Export
- [x] CSV timeline (chỉ các dòng đã tải), HTML report
- [x] P0: CSV/JSON cho toàn bộ kết quả filter; CSV/JSON cho findings
- [x] P0: kiểm tra required fields và `event_ids`; báo lỗi khi thiếu evidence
- [x] P0: test roundtrip
- [x] P1: rà thông tin nhạy cảm trong `extra_attributes`; chặn CSV formula injection

## Ngày 20–21 – Smoke và freeze
- [x] P0: cache theo path, không làm mới khi DB/JSON thay đổi (Ngày 18: khóa cache theo mtime và kích thước)
- [ ] P0: smoke test CASE01 trong venv sạch; lệnh chạy trong README
- [ ] P1: test tự động cho UI (hiện chưa có)
- [ ] P1: changelog, known limits

## Ngoài kế hoạch Ngày 15–21, đề có yêu cầu
- [ ] Trang import evidence (metadata, hash): cần nhóm quyết định phạm vi
- [ ] Biểu đồ timeline
