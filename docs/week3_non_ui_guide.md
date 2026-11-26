# Week 3 non-UI verification

This guide covers Quyên's Week 3 validation, benchmark, report export, and validation report work. Streamlit changes and browser-based acceptance are intentionally excluded.

## Rebuild the CASE01 SQLite database

From the repository root:

```powershell
python -m src.pipeline `
  --input analysis/phuc-artifacts/case01_supporting_events.csv `
  --shellbags results/case01_shellbags_events.csv `
  --database results/case01_timeline.db `
  --case-id CASE01 `
  --output "$env:TEMP\case01_timeline.json" `
  --format json
```

This imports 383 ShellBags records and 309 supporting records. It rebuilds normalized derived data; it does not modify raw evidence.

## Export CSV, JSON, and HTML

```powershell
python scripts/export_case_report.py `
  --database results/case01_timeline.db `
  --case-id CASE01 `
  --output-dir results/reports
```

The export checks ensure the timeline has event IDs, timestamp types, and evidence references and that the JSON includes C1/C2/C5 with source references. Candidate findings are labeled unverified. Outputs are written locally under `results/reports/`.

## Run the SQLite benchmark

```powershell
python scripts/benchmark_timeline.py `
  --sizes 692,6920,27680 `
  --repeats 7 `
  --output docs/benchmark_results.json
```

Every benchmark row is generated and marked synthetic. Never use these rows as forensic findings or as CASE01 evidence. Method and measured results are in [benchmark_report.md](benchmark_report.md).

## Run checks

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install pytest
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m unittest tests.test_cross_validation -q
```

`pytest` is listed in `requirements.txt`; the isolated virtual environment avoids relying on a machine-wide Python install. Install the full `requirements.txt` when setting up the application itself. Streamlit and browser acceptance are outside this non-UI checklist.
