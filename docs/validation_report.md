# Week 3 Validation Report — CASE01

**Owner:** Quyên — validation and reporting
**Scope:** Evidence manifest, H1–H4 validation, SQLite benchmark, and case report export
**Status:** Non-UI work is implemented and tested. CASE01 findings remain review candidates, not verified conclusions.

## 1. Evidence and dataset scope

The CASE01 timeline combines **383 ShellBags events** from `results/case01_shellbags_events.csv` and **309 supporting events** from `analysis/phuc-artifacts/case01_supporting_events.csv`, for **692 events**. Supporting events include LNK, JumpLists, Prefetch, and Registry records. These are derived outputs, not raw evidence, so the manifest marks the normalized timelines `REGENERABLE`.

The supplied inventory has a different size/hash for `case01_supporting_events.csv` than the current checkout. The manifest records the measured current file (**324,691 bytes**, SHA-256 **`342164f1a0e9799a8f57c86277ded9d8014e8b30028d58a119a878d7a90e207e`**) and retains the discrepancy in `source_note`.

The raw disk image and extracted artifact directories are absent from this checkout. Inventory hashes for multi-file groups are labeled as manifest digests, not single-file hashes. The disk image exact size and acquisition date remain blank because available repository sources do not establish them. Synthetic Alice fixture rows have no SHA-256 and are not marked `VERIFIED`.

## 2. H1–H4 validation

| Hypothesis | PASS requires | CASE01 result |
|---|---|---|
| H1 - folder navigation | A semantic user-interaction ShellBags event precedes a LNK/JumpList interaction to a descendant target path within 10 minutes; target metadata and reverse parent-child paths are excluded. Both source references are retained. | **PARTIAL**: 93 ordered pairs support the hypothesis; 24 reverse-order pairs are reported separately and do not count as support. |
| H2 - document execution | Prefetch directly references the same document path in `files_loaded_user` and is within 10 minutes of the LNK record. This is application/document association, not proof that a human opened the file. App name or extension compatibility alone is insufficient. | **PASS**: 1 direct-reference pair is inside the time window; 9 direct-reference pairs are outside it. The supported claim is limited to an application reference. |
| H3 - deletion lifecycle | Only a Recycle Bin event explicitly typed `RecycleBin_DeletionTime` or marked with deletion semantics is treated as deletion. Later same-path interaction is a temporal anomaly requiring review, not a confirmed contradiction because the file may have been recreated. | **NO_DATA**: CASE01 inventory lists three `desktop.ini` files and no `$I`/`$R` deletion records. |
| H4 - user attribution | Requires deletion semantics, same lifecycle ordering, matching non-empty SIDs, and shared stable file identity/lifecycle evidence. Path/time/SID alone remains review-required. | **NO_DATA**: no `$I` deletion records or file lifecycle identity are available. |

Overall status is **`PARTIAL`** (H1 PARTIAL, H2 PASS, H3/H4 NO_DATA). Mixed or unspecified case identifiers are rejected by `CrossValidator` when they could mix cases. Missing data never produces `VERIFIED`. The checks preserve event IDs and evidence references for supported pairs. H1/H2 use a 10-minute proximity window.

## 3. CASE01 review candidates

The repository records three source-backed candidates in `analysis/thi-timeline/week3_findings_validation.csv`:

| Candidate | Supported observation | Limit |
|---|---|---|
| C1 | ShellBags navigation precedes Excel JumpList/LNK records associated with a network-share document. | Does not establish copying or exfiltration; ShellBags twins are not independent sources. |
| C2 | Time-scoped `V:` mapping resolves to the secured-drive UNC share during the relevant interval. | Does not establish copying or exfiltration; a reused drive letter does not identify a unique device. |
| C5 | WINWORD Prefetch `FilesLoaded`, LNK, and JumpList contain matching resignation DOCX context. | Does not establish human intent or that a browser opened the document. |

C1/C2/C5 remain `unverified` and `review_pending_phuc`. Their observations, source references, caveats, and claims not established are retained in the candidate CSV and report export. A source reference is traceability information; it is not itself independent verification.

## 4. SQLite benchmark

The benchmark uses deterministic generated records marked `synthetic`, never CASE01 evidence. It measures insertion and median latency for case filter, artifact-plus-keyword query, and timeline retrieval at 692, 6,920, and 27,680 events. After integrating `dev`'s SQLite changes, the largest dataset inserted in **9.315 s**; the largest query median was **20.645 ms** for case filtering, **12.270 ms** for artifact plus keyword, and **2.471 ms** for timeline retrieval. The timestamp index was checked through `EXPLAIN QUERY PLAN`. See `benchmark_report.md` and `benchmark_results.json` for configuration and limitations.

## 5. Report export

`scripts/export_case_report.py` exported CSV, JSON, and HTML from the CASE01 SQLite database for all **692 events**. CSV includes event ID, case ID, timestamp/type, parser, source file, evidence reference, validation status, and `extra_attributes` JSON. HTML findings show case ID, event IDs, evidence references, confidence, and validation status. A direct CASE01 engine run produced **6,192 automated candidate findings**, exported separately from the **3 manual review candidates C1/C2/C5**. These are candidates, not verified conclusions.

## 6. Reproduction and checks

Rebuild the CASE01 SQLite database and export the reports:

```powershell
$caseRun = Join-Path $env:TEMP ("wintrace-case01-" + [guid]::NewGuid().ToString("N"))
.\scripts\run_case01_day17.ps1 -OutputDirectory $caseRun
python scripts/export_case_report.py --database (Join-Path $caseRun "case01_timeline.db") --case-id CASE01 --output-dir results/reports
python scripts/benchmark_timeline.py --sizes 692,6920,27680 --repeats 7 --output docs/benchmark_results.json
```

The merged `dev` + `quyen-week3` suite completed with **146 passed and 14 subtests passed** using `.venv\Scripts\python.exe -m pytest -q`. `compileall` and `git diff --check` passed. `check_week3_inputs.py` passed with **24 warnings** (missing raw/synthetic sources, optional Python packages, and native Plaso commands); the absent raw evidence aggregate digests were not rehashed or promoted to verified. CASE01 was re-imported as 692 unique events; repeat import inserted 0 additional rows. Setup and commands are in `week3_non_ui_guide.md`.

## 7. Limits

- The three review candidates do not prove copying, exfiltration, intent, or a specific person's action.
- Prefetch is machine-level evidence and does not identify an interactive user by itself.
- H3/H4 cannot be evaluated against deletion metadata because CASE01 inventory has no `$I`/`$R` files.
- `SOURCE_INVENTORY_RECORDED` means values were transcribed from the supplied inventory; absent raw files were not rehashed in this checkout.
