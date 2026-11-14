# CASE01 – Correlation candidate first-pass review (generated)

> This document reviews candidate *pairs*. It is not validation of user actions or correlation precision.

## Data lineage and reproducibility

- Candidate input (repo-relative): `results/case01_candidates_review.csv`
- Candidate SHA-256: `1c3771648771593202484f00f435838940fed365dd132b72d9a9db1f1bb38131`
- Candidate input last committed revision: `65953a5d7db1ceb04f3956c8753be959a6743518`
- Source events (repo-relative): `results/case01_shellbags_events.csv`
- Events SHA-256: `afb9f3e90b84f83a4db0858d5fe7548bee0e5a4d528ed29550fc8661ae65ce58`
- Source events last committed revision: `b625ecd6d3ba065f04daa8ccdc6078b616f76c4c`
- Generator script (repo-relative): `analysis/thi-timeline/generate_case01_correlation_review.py`
- Generator script SHA-256: `0255f41ae55790b541112221e008499c738f3c5bb635eb61744833655f182dbb`
- Git HEAD at generation (not necessarily the report's commit): `e32de01ae119aa863c2a15773eda8cab01a0135b`
- Note: the report commit is created after generation; input revisions and SHA-256 hashes pin exact data and code.
- Generated UTC: `2026-11-14T16:30:24.193360+00:00`
- Regenerate (repo root): `python analysis/thi-timeline/generate_case01_correlation_review.py --review-csv results/case01_candidates_review.csv --events-csv results/case01_shellbags_events.csv --report analysis/thi-timeline/case01_correlation_review_week2_v2.md --enriched-csv results/case01_review_v2/case01_candidates_review_enriched.csv --overwrite`
- Validation: timestamps, descriptions, full path, delta_minutes, R01/R02 reconstructed from source CSV.
- This baseline refers to the pre-PR #9 source representation; do not validate against newer normalized paths silently.
- Candidate case inferred from `CASE01-SB...` identifiers; source-record numbers refer to logical CSV rows, not original forensic hive offsets.
- `+00:00` timestamps are parsed as timezone-aware UTC. Timezone of original evidence must be verified separately.

## Statistics calculated from candidate input

| Metric | Value |
|---|---:|
| First-pass review pairs | 452 |
| Distinct path strings | 70 |
| Pairs with equal timestamps | 275 |
| Both timestamps are ShellItem target metadata | 231 |
| At least one BagMRU timestamp | 221 |

## Prior baseline (not recalculated by this run)

The older 6,063-candidate prototype run is historical context only. Provide `--raw-findings path/to/full_findings.csv` to recompute its counts; do not present that historical count as a result of this run.

## Example pairs (source review CSV records)

| Pair | UTC times | Timestamp semantics | Source review record |
|---|---|---|---:|
| `CASE01-SB0002` / `CASE01-SB0003` | 2014-12-16T16:10:26+00:00 / 2014-12-16T16:10:26+00:00 | ShellItem Target Created / ShellItem Target Modified | 1 |
| `CASE01-SB0004` / `CASE01-SB0006` | 2015-02-05T18:06:32+00:00 / 2015-02-05T18:06:32+00:00 | ShellItem Target Modified / ShellItem Target Modified | 2 |
| `CASE01-SB0007` / `CASE01-SB0010` | 2015-02-15T21:51:38+00:00 / 2015-02-15T21:52:08+00:00 | ShellItem Target Modified / ShellItem Target Accessed | 3 |
| `CASE01-SB0007` / `CASE01-SB0013` | 2015-02-15T21:51:38+00:00 / 2015-02-15T21:52:10+00:00 | ShellItem Target Modified / ShellItem Target Created | 4 |
| `CASE01-SB0008` / `CASE01-SB0011` | 2015-02-15T21:51:38+00:00 / 2015-02-15T21:52:08+00:00 | ShellItem Target Modified / ShellItem Target Accessed | 5 |
| `CASE01-SB0008` / `CASE01-SB0014` | 2015-02-15T21:51:38+00:00 / 2015-02-15T21:52:10+00:00 | ShellItem Target Modified / ShellItem Target Created | 6 |
| `CASE01-SB0009` / `CASE01-SB0012` | 2015-02-15T21:51:38+00:00 / 2015-02-15T21:52:08+00:00 | ShellItem Target Modified / ShellItem Target Accessed | 7 |
| `CASE01-SB0009` / `CASE01-SB0015` | 2015-02-15T21:51:38+00:00 / 2015-02-15T21:52:10+00:00 | ShellItem Target Modified / ShellItem Target Created | 8 |
| `CASE01-SB0010` / `CASE01-SB0013` | 2015-02-15T21:52:08+00:00 / 2015-02-15T21:52:10+00:00 | ShellItem Target Accessed / ShellItem Target Created | 9 |
| `CASE01-SB0011` / `CASE01-SB0014` | 2015-02-15T21:52:08+00:00 / 2015-02-15T21:52:10+00:00 | ShellItem Target Accessed / ShellItem Target Created | 10 |
| `CASE01-SB0012` / `CASE01-SB0015` | 2015-02-15T21:52:08+00:00 / 2015-02-15T21:52:10+00:00 | ShellItem Target Accessed / ShellItem Target Created | 11 |
| `CASE01-SB0016` / `CASE01-SB0017` | 2015-03-22T14:37:23+00:00 / 2015-03-22T14:37:23+00:00 | BagMRU Last Interacted / BagMRU Key Last Write | 12 |

## Evidence and interpretive limits

- Candidate pairs with at least one missing direct evidence reference: **0** (no references invented).
- `ShellItem Target Created/Modified/Accessed` are metadata of objects stored in ShellBags, not a sequence of user actions.
- R01 + R02 alone do not prove that a user opened, copied or modified a file.
- Network-share/drive-letter aliases require independent mapping/volume verification.
- Original ShellBags event IDs are preserved; do not delete source events to reduce pair counts.
- `case01_candidates_review_enriched.csv` links pairs to logical source CSV records and any evidence reference present in input.
- Confirm with Phúc's original artifact evidence before calling a correlation `verified`.
