# Tuần 3 – Ngày 19: Export CSV/JSON

Code: `src/ui_export.py`. Test: `tests/test_ui_export.py`.

## File xuất

| File | Nội dung |
|---|---|
| Timeline CSV / JSON | Mọi event khớp filter ở sidebar, không chỉ trang đang xem |
| Findings CSV | Finding khớp filter ở tab Correlation findings |
| Findings JSON | Như trên, kèm `source_events` để mọi `event_ids` tra được ngay trong file |
| HTML | Báo cáo cũ (`ReportGenerator`): 50 event đầu và finding hợp lệ đang chọn |

JSON có `export_version`, thời điểm xuất UTC, filter đã dùng, tên và SHA-256 của DB/JSON nguồn, `record_count` và `excluded_records`. Không ghi đường dẫn thư mục. CSV không có phần này, nên dùng JSON khi cần kiểm chứng.

## Kiểm tra trước khi xuất

- Event: bắt buộc `event_id`, `case_id`, `timestamp`, `timestamp_type`, `artifact_source`, `source_file`, `validation_status`, `evidence_reference`; `(case_id, event_id)` không trùng.
- Finding: có ID không trùng, case, rules, reference; mỗi event nguồn khớp đúng một record cùng case và hợp lệ; reference khớp event.
- Có lỗi thì chặn xuất và liệt kê. Chọn **Leave out invalid records** mới xuất phần còn lại; JSON ghi rõ record bị bỏ và lý do.
- Export không đổi `validation_status` và không ghi vào DB/JSON nguồn.

## Dữ liệu nhạy cảm

Chỉ xuất trường trong allowlist. Không xuất SID, tên máy, volume serial/label, danh sách file Prefetch nạp và các attribute khác. **Vẫn giữ** `username`, path, mô tả và evidence reference để truy vết; các trường này có thể chứa tên người hoặc serial thiết bị. Cần xem lại trước khi công khai.

## CSV

UTF-8 có BOM. Text bắt đầu bằng `=`, `+`, `-`, `@` hoặc `'` được thêm `'` ở đầu để Excel không chạy thành công thức; `read_csv()` bỏ dấu này. Ô rỗng là null, trừ `target_path` và `message`. Cột danh sách/object và số được ghi dạng JSON.

## Kết quả CASE01

692 event và 6.192 finding không có lỗi; roundtrip CSV/JSON khớp. Đã chuẩn bị export trên trình duyệt; nội dung file được kiểm qua code, chưa bấm tải từng file.
