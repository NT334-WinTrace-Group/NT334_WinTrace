# WinTrace – Super Timeline Creation and Analysis

> **Môn học:** NT334 – Pháp chứng kỹ thuật số (Digital Forensics)  
> **Đồ án:** Phân tích và Xây dựng Super Timeline trên hệ điều hành Windows  

---

## Giới thiệu tổng quan
**WinTrace** là giải pháp phân tích pháp chứng kỹ thuật số tập trung vào việc tạo và phân tích **Super Timeline** từ nhiều nguồn bằng chứng độc lập trên Windows (Prefetch, ShellBags, LNK, Windows Event Logs EVTX, Recycle Bin).

Dự án áp dụng công cụ trích xuất công nghiệp **Plaso (`log2timeline` / `psort`)**, chuẩn hóa sự kiện theo **Event Schema** thống nhất, thực hiện **Cross-Validation** (đối chiếu chéo giữa các nguồn) và áp dụng **Correlation Rules (R01 - R05)** để tái dựng chuỗi hành vi của người dùng và hệ thống với độ tin cậy pháp chứng cao.

## Quickstart (Windows PowerShell)

Create and activate a virtual environment, install the pinned Python
dependencies, and run the tests:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-lock.txt
python -m pytest -q
```

`requirements.txt` contains the supported dependency ranges;
`requirements-lock.txt` pins the resolved Windows/Python 3.12 dependency set.
Plaso is an external forensic runtime and is not included in this Python lock.

Import the committed CASE01 parser outputs into one case-isolated SQLite
database and verify repeat-import idempotency:

```powershell
.\scripts\run_case01_day17.ps1
```

For a direct CLI run:

```powershell
python src\pipeline.py `
  --input analysis\phuc-artifacts\case01_supporting_events.csv `
  --shellbags results\case01_shellbags_events.csv `
  --case-id CASE01 `
  --source-label case01-supporting-tools `
  --output-dir results `
  --output normalized.json `
  --database timeline.db `
  --findings findings.json
```

The command writes to `results\CASE01\`, keeps the canonical ShellBags CSV as
the single ShellBags event source, and preserves parser/source labels. A
`filestat` row is not counted as Prefetch/EVTX/LNK parser activity.

This import exercises committed parser outputs; it does not run Plaso against
the CASE01 disk image. See [the Day 17 execution report](./docs/week3_day17_execution.md)
for the input checksums and runtime limitations, [the Day 18 data API
contract](./docs/week3_day18_data_api.md), [the Day 19 error contract](./docs/week3_day19_error_contract.md),
and [the Day 20-21 validation record](./docs/week3_day20_21_validation.md).
## Week 3 non-UI verification
See [the reproducible guide](docs/week3_non_ui_guide.md) for CASE01 validation, report export, SQLite benchmark, and test commands.
