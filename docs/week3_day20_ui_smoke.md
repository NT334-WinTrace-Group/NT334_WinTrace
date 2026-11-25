# Tuần 3 – Ngày 20: UI end-to-end và smoke test

Môi trường (2026-11-26): Windows 11, Python 3.12.6. Clone mới của nhánh `UI`, venv mới cài từ `requirements-lock.txt` (Streamlit 1.67.0, `pip check` sạch). Phần sửa Ngày 20 được chép vào clone đó trước lần chạy cuối.

## Kết quả

| Kiểm tra | Cách kiểm | Kết quả |
|---|---|---|
| Test suite trên venv sạch | `python -m pytest -q` | 246 passed, 14 subtests |
| Pipeline CASE01 theo README | CLI | 692 event, 6.192 candidate |
| Mở UI với đường dẫn mặc định | Trình duyệt, venv sạch | Đạt, không lỗi console |
| Lọc `CASE01-SB0133` | Trình duyệt + test | 1 event |
| Xem evidence | Test | Reference và `Deduplicated.csv:L106` hiện đủ |
| Chuẩn bị export | Trình duyệt + test | 1 event đã lọc, 6.192 finding |
| Nội dung CSV/JSON | Test roundtrip | Khớp |
| Bấm tải file và mở bằng Excel | **Chưa kiểm**, cần làm tay | – |
| 3 candidate C1, C2, C5 | Test | Mở được, truy ra đúng event nguồn |

## Trường hợp hỏng (`tests/test_ui_smoke.py`)

| Trường hợp | Hành vi |
|---|---|
| DB thiếu, rỗng, hỏng, thiếu cột | Thông báo rõ; không tạo hoặc sửa file |
| DB bị thay hoặc xóa khi đang mở | Đọc lại ngay; finding trỏ event cũ bị cảnh báo |
| Một dòng event hỏng | Nêu đúng event và dòng DB; các event khác vẫn dùng được |
| Export khi có dòng hỏng | Chặn, trừ khi chọn "Leave out invalid records"; JSON ghi dòng bị bỏ |
| Findings JSON rỗng hoặc sai cấu trúc | Cảnh báo; timeline vẫn chạy |
| Path 900+ ký tự | Hiển thị được |

## Lỗi P0 đã sửa

Trước Ngày 20, một dòng DB có kiểu dữ liệu sai (ví dụ `extra_attributes` NULL) làm sập toàn bộ UI; timestamp hoặc JSON hỏng làm mất cả tab findings.

## Chờ review

- [ ] Phúc: forensic check
- [ ] Thi: candidate semantics
- [ ] Nam: `MalformedEventError` và tham số `malformed` trong `src/storage.py`
