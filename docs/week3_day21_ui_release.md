# WinTrace UI v1.0 – Changelog, giới hạn và review

**Trạng thái:** ứng viên v1.0 trên nhánh `UI`, chờ review. Chưa merge vào `dev`, chưa tag release.

## Chạy

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-lock.txt
python -m pytest -q
```

Chạy lệnh pipeline CASE01 trong [README](../README.md), rồi:

```powershell
python -m streamlit run src\app.py
```

Mở http://localhost:8501.

## Changelog (so với `dev` `8053b34`)

| Ngày | Thay đổi |
|---|---|
| 15 | Schema ↔ UI contract, JSON mẫu có test, kiểm kê UI |
| 16 | Timeline UTC, filter tổ hợp, phân trang, empty states; DB mở read-only |
| 17 | Evidence detail, hai dạng path, nhãn bằng chứng, cảnh báo provenance |
| 18 | Findings view, truy event nguồn, trạng thái review từ dữ liệu |
| 19 | Export CSV/JSON có kiểm tra, allowlist trường, chặn công thức Excel |
| 20 | Cô lập event hỏng, smoke test, sửa lệnh chạy trong README |
| 21 | Pipeline từ chối ghi đè file input; cảnh báo status lạ; HTML report có Review Status và giờ UTC |

Module dùng chung bị sửa: `src/storage.py` (giữ thứ tự tham số `query()` của `dev`, tham số mới chỉ nhận theo tên; thêm API đọc; `query()` báo `MalformedEventError` với dòng hỏng), `src/pipeline.py` (chặn ghi đè), `src/report_generator.py`, `requirements.txt` (`streamlit>=1.50.0`). Không thêm bảng hay cột SQLite.

## Kết quả freeze

- Trạng thái event giữ nguyên từ DB đến bảng, chi tiết, CSV, JSON; mọi giá trị schema đều có nhãn review.
- Phiên UI đầy đủ không đổi byte nào của DB và findings JSON.
- DB cũ thiếu cột: UI từ chối và không sửa; mở bằng `TimelineStore` để migrate rồi dùng được.
- Pipeline không ghi đè CSV input, kể cả qua hard link.
- Chạy trên dữ liệu CASE01 tại commit `0f276d8`: 692 event, 6.192 candidate.

## Giới hạn đã biết

1. UI đọc output có sẵn; **không có trang import evidence** và không chạy Plaso. Plaso chưa chạy trên CASE01.
2. CASE01 chưa có EVTX, Recycle Bin, MFT nên không minh họa được xóa file.
3. 6.192 finding đều là Candidate; phần lớn không phải hành vi người dùng. Điểm HIGH không có nghĩa là đã kiểm chứng.
4. Kết quả duyệt C1/C2/C5 nằm ở CSV riêng, chưa được ghi vào finding.
5. Filter path chỉ tìm `target_path`; không quy đổi alias ổ đĩa (ví dụ `V:`). Keyword tiếng Việt có dấu phân biệt hoa thường.
6. Status hoặc confidence lạ trong DB bị `ForensicEvent` đổi thành `unverified` / `MEDIUM`; UI chỉ cảnh báo status.
7. HTML report gồm mọi event khớp filter và mọi finding đã chọn (PR 19 bỏ giới hạn 50 event), nên có thể rất lớn. CSV không có manifest.
8. Export giữ `username`, path, mô tả và reference; cần xem lại trước khi công khai.
9. Chưa có biểu đồ timeline. Chưa benchmark DB lớn; mọi finding và event được trích dẫn được nạp vào RAM.
10. UI nhãn tiếng Anh, caveat của artifact giữ tiếng Việt.

## Review

Phát hiện khi đối chiếu code, **không sửa trong nhánh UI**:

| Owner | Vấn đề |
|---|---|
| Thi | Cả 519 finding HIGH là R01+R02+R03, nhiều cặp dùng metadata/KeyLastWrite; 8 finding R04 chỉ MEDIUM |
| Thi | `correlate()` ghép mọi cặp event, O(n²): khoảng 18 giây với 692 event |

Các vấn đề về `CrossValidator`, `validation_report.md` và hash manifest đã được PR 19 xử lý.

Cần duyệt trước khi merge:

- [ ] Nam: `storage.py`, `pipeline.py`
- [ ] Thi: nhãn bằng chứng, câu chữ R01–R05, ý nghĩa candidate
- [ ] Phúc: provenance, giới hạn diễn giải
- [ ] Tải CSV/JSON bằng tay và mở bằng Excel
- [ ] Test xanh trên `dev` sau merge
