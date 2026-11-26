# Week 3 non-UI verification

This guide covers Quyên's Week 3 validation, benchmark, report export, and validation report work. Streamlit changes and browser-based acceptance are intentionally excluded.

## Rebuild the CASE01 SQLite database

From the repository root, create a fresh run directory and import the committed CASE01 parser outputs:

```powershell
$caseRun = Join-Path $env:TEMP ("wintrace-case01-" + [guid]::NewGuid().ToString("N"))
.\scripts\run_case01_day17.ps1 -OutputDirectory $caseRun
```

The script imports 383 ShellBags records and 309 supporting records, checks that a second import adds no duplicates, and writes the SQLite DB into `$caseRun`. It does not modify raw evidence or run Plaso against the disk image.

## Export CSV, JSON, and HTML

```powershell
python scripts/export_case_report.py `
  --database (Join-Path $caseRun "case01_timeline.db") `
  --case-id CASE01 `
  --output-dir results/reports
```

The export checks ensure the timeline has event IDs, timestamp types, and evidence references and that the JSON includes C1/C2/C5 with source references. Candidate findings are labeled unverified. Generated outputs are ignored by Git under `results/reports/`; the script recreates them when needed.

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
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe scripts\check_week3_inputs.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m unittest tests.test_cross_validation -q
```

Use Python 3.12 for the pinned `requirements-lock.txt`. If a platform-specific package cannot be installed from the lockfile, use `pip install -r requirements.txt` and record the Python/package versions. The isolated virtual environment avoids relying on machine-wide packages. Streamlit/browser acceptance is outside this non-UI checklist.
