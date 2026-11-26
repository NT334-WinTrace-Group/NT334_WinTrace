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
| H1 — folder navigation | A typed or recognized ShellBags interaction precedes a LNK/JumpList interaction to a child path within 10 minutes; retain both source references. | **PARTIAL**: 150 ordered pairs support the hypothesis; 44 reverse-order pairs are reported separately and do not count as support. |
| H2 — document execution | Prefetch directly references the same document path in `files_loaded_user` and is within 10 minutes of the LNK event. App name or extension compatibility alone is insufficient. | **PASS**: 1 direct-reference pair is inside the time window; 9 direct-reference pairs are outside it. |
| H3 — deletion lifecycle | A Recycle Bin deletion timestamp follows a recognized same-path interaction. Later interaction is reported as a temporal contradiction. | **NO_DATA**: CASE01 inventory lists three `desktop.ini` files and no `$I`/`$R` deletion records. |
| H4 — user attribution | H3-compatible ordering and matching non-empty SIDs on both events. | **NO_DATA**: no `$I` deletion records are available. |

Overall status is **`PARTIAL`** (H1 PARTIAL, H2 PASS, H3/H4 NO_DATA). Missing data never produces `VERIFIED`. The checks preserve event IDs and evidence references for supported pairs. H1/H2 use a 10-minute proximity window.

## 3. CASE01 review candidates

The repository records three source-backed candidates in `analysis/thi-timeline/week3_findings_validation.csv`:

| Candidate | Supported observation | Limit |
|---|---|---|
| C1 | ShellBags navigation precedes Excel JumpList/LNK records associated with a network-share document. | Does not establish copying or exfiltration; ShellBags twins are not independent sources. |
| C2 | Time-scoped `V:` mapping resolves to the secured-drive UNC share during the relevant interval. | Does not establish copying or exfiltration; a reused drive letter does not identify a unique device. |
| C5 | WINWORD Prefetch `FilesLoaded`, LNK, and JumpList contain matching resignation DOCX context. | Does not establish human intent or that a browser opened the document. |

C1/C2/C5 remain `unverified` and `review_pending_phuc`. Their observations, source references, caveats, and claims not established are retained in the candidate CSV and report export. A source reference is traceability information; it is not itself independent verification.

## 4. SQLite benchmark

The benchmark uses deterministic generated records marked `synthetic`, never CASE01 evidence. It measures insertion and median latency for case filter, artifact-plus-keyword query, and timeline retrieval at 692, 6,920, and 27,680 events. On the recorded Windows/Python/SQLite environment, the largest query median was **33 ms**; inserting 27,680 rows took **21.4 seconds**. See `benchmark_report.md` and `benchmark_results.json` for measurements and limitations.

## 5. Report export

`scripts/export_case_report.py` exported CSV, JSON, and HTML from the CASE01 SQLite database for all **692 events**. CSV and HTML include event IDs, timestamp types, and evidence references. JSON contains the complete event records, C1/C2/C5 with source references, and H1–H4 validation output. All candidates are labeled as requiring review.

## 6. Reproduction and checks

Rebuild the SQLite database:

```powershell
python -m src.pipeline `
  --input analysis/phuc-artifacts/case01_supporting_events.csv `
  --shellbags results/case01_shellbags_events.csv `
  --database results/case01_timeline.db `
  --case-id CASE01 `
  --output "$env:TEMP\case01_timeline.json" `
  --format json
```

Export the case report and reproduce the benchmark:

```powershell
python scripts/export_case_report.py --database results/case01_timeline.db --case-id CASE01 --output-dir results/reports
python scripts/benchmark_timeline.py --sizes 692,6920,27680 --repeats 7 --output docs/benchmark_results.json
```

The full test suite completed with **119 passed** using `\.venv\Scripts\python.exe -m pytest -q` after removing the UI-only source-reference viewer test. `python -m compileall -q src scripts tests` and `git diff --check` also passed. Setup and commands are in `week3_non_ui_guide.md`.

## 7. Limits

- The three review candidates do not prove copying, exfiltration, intent, or a specific person's action.
- Prefetch is machine-level evidence and does not identify an interactive user by itself.
- H3/H4 cannot be evaluated against deletion metadata because CASE01 inventory has no `$I`/`$R` files.
- `SOURCE_INVENTORY_RECORDED` means values were transcribed from the supplied inventory; absent raw files were not rehashed in this checkout.
