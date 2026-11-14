# CASE01 ShellBags – DFIR review (generated)

> **Object-context audit only.** Not validated user-activity findings.

## Reproducibility

- Input CSV (repo-relative): `results/case01_shellbags_events.csv`
- Input SHA-256: `afb9f3e90b84f83a4db0858d5fe7548bee0e5a4d528ed29550fc8661ae65ce58`
- Input last committed revision: `b625ecd6d3ba065f04daa8ccdc6078b616f76c4c`
- Generator script (repo-relative): `analysis/thi-timeline/analyze_case01_shellbags_week2.py`
- Generator script SHA-256: `304a14b591807c77c6dbf59a013d7fcee120169adc9ef24fdcf3d90e8572d9ed`
- Git HEAD at generation (not necessarily the report's commit): `e32de01ae119aa863c2a15773eda8cab01a0135b`
- Note: the Git commit containing this report is created **after** generation; source revision and SHA-256 hashes are reproducibility anchors.
- Generated UTC: `2026-11-14T16:30:16.063098+00:00`
- Suggested command (from repo root): `python analysis/thi-timeline/analyze_case01_shellbags_week2.py --input results/case01_shellbags_events.csv --output-dir results/case01_review_v2 --report analysis/thi-timeline/case01_shellbags_dfir_review_v2.md --overwrite`
- Input supports pre-schema-v2 fields. `case_id=CASE01` is inferred from valid event IDs when absent.
- `source_csv_record` is a *logical CSV record number*, not evidence hive offset or physical line number.

## Timestamp categories (calculated from current input)

| Category | Events |
|---|---:|
| TARGET_METADATA | 168 |
| REGISTRY_UPDATE | 104 |
| INFERRED_INTERACTION | 111 |
| OTHER_OR_UNKNOWN | 0 |

- Total events: **383**
- Distinct path-text groups: **91**
- Warnings: **0** (non-fatal; examples below)

## Prominent path groups

| Path | Events |
|---|---:|
| `Desktop\Computers and Devices\10.11.11.128\10.11.11.128\secured_drive\Secret Project Data\pricing decision` | 12 |
| `Desktop\Computers and Devices\10.11.11.128\10.11.11.128\secured_drive\Past Projects` | 11 |
| `Desktop\This PC\D:\de` | 11 |
| `Desktop\Computers and Devices\10.11.11.128\10.11.11.128\secured_drive\Common Data` | 10 |
| `Desktop\Computers and Devices\10.11.11.128\10.11.11.128\secured_drive\Secret Project Data\design` | 10 |
| `Desktop\Computers and Devices\10.11.11.128\10.11.11.128\secured_drive\Secret Project Data\final` | 10 |
| `Desktop\Computers and Devices\10.11.11.128\10.11.11.128\secured_drive\Secret Project Data\progress` | 10 |
| `Desktop\Computers and Devices\10.11.11.128\10.11.11.128\secured_drive\Secret Project Data\proposal` | 10 |
| `Desktop\Computers and Devices\10.11.11.128\10.11.11.128\secured_drive\Secret Project Data\technical review` | 10 |
| `Desktop\Computers and Devices\10.11.11.128\10.11.11.128\secured_drive\Secret Project Data` | 9 |

## Analysis limits

- ShellItem target MAC timestamps are object metadata, not direct folder-opening times.
- BagMRU inferred interactions and key LastWrite require source-hive / MRU context.
- Path grouping compares strings only; does not equate mapped drives with UNC shares.
- Do not merge two distinct timestamp semantics into one activity event.
- Historical prototype 6,063/452 counts are NOT recomputed by this script. Use the separate candidate-review report.
- Provenance missing in the source CSV remains missing; never invent an evidence reference.

## Non-fatal warnings (first 15)

- None

## Next steps

- Compare selected event IDs/CSV record numbers with Phúc's source evidence notes.
- Keep object context separate from independently supported activity candidates.
- Coordinate engine changes with Quyên rather than editing shared files concurrently.
