# Week 3 Day 19 - Input and execution errors

## Pipeline contract

- Missing input files, malformed timestamps/JSON, unsupported explicit
  artifact names, empty event sets, and duplicate ShellBags event sources fail
  the pipeline. Invalid records are not partially written to the normalized
  output, database, or findings file.
- If `--error-log` is provided, rejected CSV rows and their record numbers are
  written there before the pipeline exits nonzero. `--output-dir` creates a
  case-specific `<root>/<case-id>` directory and defaults the error log to
  `errors.json`.
- `--output-dir` requires a safe `--case-id`; all requested output files are
  placed under that case directory. Distinct filenames are required.
- A `filestat` row is retained as `Generic` parser metadata; it cannot claim
  that a Prefetch, EVTX, or LNK artifact parser succeeded. Unknown explicit
  artifact names are rejected.
- `PlasoRunner` raises `PlasoCommandError` for a missing executable or
  nonzero command exit. When a log path is supplied, pass and fail records are
  written as JSON Lines with command, return code, stdout/stderr, and UTC
  start/end times.

## Examples

Run the import with outputs isolated by case:

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

This writes outputs below `results\CASE01\`. For a bad record, include
`--error-log errors.json`; the process exits with code 1 and does not create
the normalized output, database, or findings output.

The Python regression tests exercise malformed timestamps/JSON, a missing
source, unsupported artifacts, duplicate ShellBags inputs, case isolation,
and Plaso command failures. They do not claim that Plaso has been run on the
CASE01 disk image; that image and a working Plaso runtime are still required.
