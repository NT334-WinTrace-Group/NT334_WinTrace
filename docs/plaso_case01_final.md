# CASE01 – Plaso integration (final integration)

Bổ sung cho [Plaso Pipeline Guide](plaso_pipeline_guide.md). Các kết quả dưới đây thuộc lần chạy CASE01 ngày 27/11/2026, không phải scenario filestat Alice của tuần 1. Chứng cứ là thư mục artifacts đã thu thập, không phải full disk image.

## Reproduction

Chạy từ repository root trong PowerShell, dùng Python environment của WinTrace và Docker Desktop đang hoạt động. Thay đường dẫn theo máy; chỉ sử dụng bản sao evidence đã xác minh hash. Dùng thư mục output mới, nằm ngoài evidence; không ghi đè output cũ.

```powershell
$Python = "D:\doan\WinTrace-PR20-Review\.venv\Scripts\python.exe"
$Raw = "D:\doan\CASE01-Raw\case01\evidence_work"
$Out = "D:\doan\CASE01-Plaso-Reproduction"
$Plaso = "log2timeline/plaso@sha256:3de91dfa0dd6885bf76f8a0c14ba4ce48e174e2acab97157aa0bbabe5a2d108e"
New-Item -ItemType Directory -Path $Out -ErrorAction Stop
$Parsers = "prefetch,lnk,olecf/olecf_automatic_destinations,custom_destinations,winreg,recycle_bin"
$Fields = "datetime,timestamp_desc,source,source_long,message,parser,data_type,display_name,tag"
docker run --rm --network none --mount "type=bind,source=$Raw,target=/evidence,readonly" --mount "type=bind,source=$Out,target=/output" $Plaso log2timeline --storage-file /output/CASE01_artifacts.plaso --parsers $Parsers --status_view none /evidence
# Check $LASTEXITCODE is 0 before continuing.
docker run --rm --network none --mount "type=bind,source=$Out,target=/output,readonly" $Plaso pinfo /output/CASE01_artifacts.plaso
docker run --rm --network none --mount "type=bind,source=$Out,target=/output" $Plaso psort -o dynamic --fields $Fields -w /output/CASE01_plaso_full.csv /output/CASE01_artifacts.plaso
# Check $LASTEXITCODE again.
& $Python scripts/prepare_plaso_events.py $Out
& $Python -c "import csv; csv.field_size_limit(2**31-1); from src.pipeline import main; raise SystemExit(main())" --input "$Out\CASE01_plaso_valid.csv" --case-id CASE01 --source-label plaso-case01-artifacts --output-dir "$Out\wintrace" --output normalized.csv --format csv --database timeline.db --error-log errors.json
```

`DockerPlasoRunner` in `src/plaso_runner.py` also exposes Python methods for extraction, pinfo and export, with optional JSONL execution logs. It uses a pinned image, read-only input mounts and separate output directories. For `run_psort()`, use an output directory that does not contain the storage file. At the time of this record, the three tools were run via CLI; the Python `run_pinfo()` method and eight runner unit tests were confirmed. Python Docker Runner end-to-end smoke test passed on
CASE01 Prefetch artifacts, including log2timeline,
pinfo and psort. Canonical UI compatibility was also
confirmed across all five tabs.

The data quality script preserves the full CSV and its 1-based logical record numbers; it quarantines invalid timestamps instead of fabricating replacements. The new adapter recognizes prepared rows by their `source_record` field and preserves raw display names, timestamp descriptions and references. The adapter currently uses CASE01 file naming conventions. Do not use `--findings` on the full extended dataset: the pairwise engine has quadratic complexity. Do not merge duplicate evidence from different parsers as independent events without a provenance-aware reconciliation step.

## Observed results

| Check | Result |
|---|---:|
| Storage events | 213,148 |
| Event sources | 154 |
| Exported records | 212,792 |
| Storage/export count difference | 356 (cause not independently verified) |
| Valid records | 212,756 |
| Quarantined timestamps | 36 (19 UserAssist, 15 LNK, 2 TypedURLsTime) |
| SQLite integrity | ok |
| Unique event IDs and fingerprints | 212,756 each |
| CSV-to-SQLite traceability | 212,756 matches on nine checked fields; no mismatches |
| Validation status | all unverified |
| Registry events | 211,976 |
| Full regression suite before this documentation/script addition | 312 passed, 14 subtests passed |

### Cross-tool checks (UTC)

| Record | Timestamp | Artifact |
|---|---|---|
| 176742 | 2015-03-23 20:26:53.783794 | C1 Excel Jump List |
| 176758 | 2015-03-23 20:27:33.267068 | C2 PowerPoint Jump List |
| 212407 | 2015-03-25 15:24:48.193206 | C5 WINWORD Prefetch |
| 212459 | 2015-03-25 15:29:08.934806 | C5 DOCX Jump List |

These agree with the corresponding EZ Tools timestamps to the second; same underlying artifacts, not independent evidence of user actions. Prefetch run count 3 and hash CECBA770 agree; this dynamic export does not provide the direct FilesLoaded list required for C5 program-file association. The targeted correlation smoke test produced two MEDIUM candidates in each of two windows (4 and 13 input events; R01/R02 only), not a full-dataset benchmark.

## Dashboard

```powershell
& $Python -m streamlit run src/app.py
```

Set the sidebar SQLite path to `$Out\wintrace\CASE01\timeline.db` (substitute the actual absolute path). The extended dataset is a browsing-only mode: canonical findings, cross-validation, manual review and reporting are disabled. Filter JumpLists by `pricing_decision` to inspect `CASE01-PLASO-176742` and its source record. The canonical 692-event database remains separate. Tested page size 50: 4,256 pages, last page six events; measured first/second/last page approximately 0.416/0.438/5.325 seconds on the development machine. These are single observations, not a formal performance benchmark.

## Limitations

- One `UsrClass.dat` warning: unable to resolve Windows Registry file mapping. Plaso ShellBags coverage is incomplete; retain independent SBECmd results. This does not establish hive corruption.
- Three 1980 timestamps retained with review flag; not evidence of 1980 user activity. 36 invalid timestamps are quarantined, not erased.
- DestList entry modification is not target-file content modification, despite the existing schema label `JumpList_TargetModified`.
- Generic timestamps retain raw descriptions rather than falsely claiming a supported semantic type. No inferred user attribution from a target path.
- Registry key/value events dominate the dataset; number of events is not number of user actions.
- Extended database UI is for browsing; targeted correlation is separate. No conclusion about copying, exfiltration or intent from parser agreement alone.

Do not commit raw evidence, `.plaso`, large CSV, SQLite databases or sensitive logs to GitHub.
