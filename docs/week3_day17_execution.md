# Week 3 Day 17 - CASE01 pipeline run

## Result and scope

The downstream CASE01 import was run twice from committed parser outputs:
309 supporting events from LECmd, JLECmd, PECmd, and python-registry, plus
383 ShellBags events. The first run inserted 692 rows; the repeat inserted
zero. This is a reproducible normalized SQLite import, not a fresh
`log2timeline.py` / `psort.py` extraction.

The Plaso extraction stage remains blocked in this checkout:

- The manifest names a 40 GiB image at
  `evidence/case01/cfreds_2015_data_leakage_pc.dd`, but that file and the
  CASE01 hive / Prefetch / LNK / Jump List source directories are absent.
- Native `log2timeline.py` and `psort.py` are unavailable. WSL has Python
  3.12.3 but neither Plaso command; Docker Client 29.0.1 cannot connect to
  the Docker Desktop Linux engine.
- `results/plaso_raw_output.csv` is the small Alice synthetic scenario and is
  not used as CASE01 evidence. Its eight rows include several synthetic
  parser labels; they are not evidence that Plaso ran on CASE01.

Do not report the Plaso/psort stage as complete until Phuc provides the
CASE01 source files and a working Plaso runtime. The available CASE01
supporting output is still useful for exercising the normalized importer,
with each row retaining an event ID and `evidence_reference`.

## Reproduction

Run from the repository root in PowerShell:

```powershell
.\scripts\run_case01_day17.ps1
```

The script creates a fresh run directory under `%TEMP%`, writes separate
stdout/stderr logs for both imports, records input hashes and Python/tool
availability, and queries the resulting SQLite database. To choose a
specific empty output directory:

```powershell
.\scripts\run_case01_day17.ps1 -OutputDirectory "$env:TEMP\case01-day17-run"
```

The underlying pipeline invocation is:

```powershell
python src\pipeline.py `
  --input analysis\phuc-artifacts\case01_supporting_events.csv `
  --shellbags results\case01_shellbags_events.csv `
  --output "$env:TEMP\case01_normalized.json" `
  --database "$env:TEMP\case01_timeline.db" `
  --error-log "$env:TEMP\case01_errors.json" `
  --case-id CASE01 `
  --source-label case01-supporting-tools
```

Use the same database path for the second invocation to verify idempotency.
`--source-label case01-supporting-tools` avoids labelling LECmd/JLECmd/PECmd/
Registry records as Plaso output. ShellBags keeps its own `shellbags` label.

## Recorded run

Environment: Windows, Python 3.12.6. `PlasoRunner` was not invoked because
there is no CASE01 raw source or available Plaso runtime.

Input SHA-256:

| Input | SHA-256 |
|---|---|
| `analysis/phuc-artifacts/case01_supporting_events.csv` | `342164f1a0e9799a8f57c86277ded9d8014e8b30028d58a119a878d7a90e207e` |
| `results/case01_shellbags_events.csv` | `14f50ebe794b3cd51142bd1319a2767dd208d63a973bbc17da51cfb564f850a8` |

The supporting-event builder was rerun from committed `tool_output` files:
309 rows (`LNK` 69, `JumpLists` 31, `Prefetch` 190, `Registry` 19), with
15 `SourceAccessed` values excluded. Its output SHA-256 matched the committed
supporting CSV above.
The normalized output labels these rows `case01-supporting-tools` and the
ShellBags rows `shellbags`; parser counts are `lecmd` 69, `jlecmd` 31,
`pecmd` 190, `python-registry` 19, and `sbecmd` 383. No Plaso `filestat`
event is counted as CASE01 parser activity.

Parser/tool versions recorded in the source metadata:

| Parser/tool | Version | Events |
|---|---:|---:|
| SBECmd | 2026.10.2 | 383 ShellBags |
| LECmd | 2026.10.3 | 69 LNK |
| JLECmd | 2026.10.5 | 31 Jump Lists |
| PECmd | 2026.10.3 | 190 Prefetch |
| python-registry | 1.3.1 | 19 Registry |

Pipeline stdout summary, run 1:

```text
Imported 383 ShellBags events.
Successfully normalized 692 forensic events.
SQLite timeline: 692 new events, 692 total events
ShellBags: 383; Prefetch: 190; LNK: 69; JumpLists: 31; Registry: 19
Pipeline completed successfully; exit code 0.
```

Repeat run:

```text
Successfully normalized 692 forensic events.
SQLite timeline: 0 new events, 692 total events
Pipeline completed successfully; exit code 0.
```

Neither run produced a normalization error log or stderr output.

## SQLite query counts

The run script queries the database with:

```sql
SELECT artifact_source, COUNT(*)
FROM events
GROUP BY artifact_source
ORDER BY artifact_source;

SELECT case_id, COUNT(*)
FROM events
GROUP BY case_id;

SELECT COUNT(*) AS total,
       COUNT(DISTINCT event_id) AS unique_event_ids,
       SUM(CASE WHEN evidence_reference IS NOT NULL
                 AND evidence_reference <> '' THEN 1 ELSE 0 END) AS with_evidence_reference
FROM events;
```

Observed result: 692 total rows, 692 unique event IDs, 692 `CASE01` rows,
and 692 rows with an `evidence_reference` (zero missing references). Artifact
counts match the table above. The repeated import left the row count at 692.

## Integrity caveat

The current manifest entry for `results/case01_shellbags_events.csv` is stale:
it records 212,716 bytes and the empty-file SHA-256, while the actual input
used here is 575,015 bytes with the SHA-256 recorded above. The preflight
checker also reports missing raw CASE01 sources and mismatches for synthetic
fixtures. These manifest entries were not silently rewritten; the artifact
owners should confirm corrected integrity metadata.
