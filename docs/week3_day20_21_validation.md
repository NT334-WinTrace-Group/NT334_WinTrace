# Week 3 Days 20-21 - Integration and release checks

## Available CASE01 integration input

The integration test uses the committed CASE01 parser outputs, not the
synthetic Alice timeline:

| Input | Events |
|---|---:|
| Supporting parser output (LECmd, JLECmd, PECmd, Registry) | 309 |
| Canonical ShellBags events | 383 |
| Total | 692 |

`tests/test_week3_integration.py` normalizes these sources into a temporary
SQLite database, imports them twice, and asserts 692 rows after both imports,
unique event IDs, UTC timestamps, evidence references, correct filters, and
use of the timestamp index. `scripts/run_case01_day17.ps1` additionally runs
the full pipeline CLI twice and captures stdout/stderr, checksums, and query
counts in a fresh temporary directory.

Recorded CLI run: exit code 0; first import inserted 692/692 rows; the repeat
inserted 0 and left 692 total. The SQLite query reported 692 unique IDs, all
under `CASE01`, and 692 evidence references.

Recorded fail-fast run with one malformed timestamp: exit code 1, stderr began
`[ERROR] Rejected 1 malformed input record(s)`, and `errors.json` identified
CSV record 1. The normalized JSON, SQLite database, and findings output were
not created.

## Commands

```powershell
python -m pytest -q
.\scripts\run_case01_day17.ps1
git diff --check
```

## Clean-machine status and release checklist

- Runtime validated here: Windows, Python 3.12.6. Full suite:
  `121 passed, 14 subtests passed`.
- A pinned dependency set is in `requirements-lock.txt`, generated from
  `requirements.txt` with Python 3.12. The manifest's former
  `python-registry>=1.4.0` requirement could not resolve from the package
  index (latest available was 1.3.1); the supported lower bound is now 1.3.1.
- A fresh Windows/Python 3.12 virtual environment installed
  `requirements-lock.txt` and passed the full suite:
  `121 passed, 14 subtests passed`.
- Plaso is a separate runtime; the native
  Windows environment and available WSL/Docker setup in this workspace did
  not provide working `log2timeline.py` / `psort.py`.
- The CASE01 raw image and original hive/Prefetch/LNK/Jump List inputs are not
  present in this checkout. Consequently, no clean-machine Plaso extraction
  of CASE01 or release tag is claimed.
- Before release, obtain the evidence-owner-approved input manifest hashes,
  verify the Plaso runtime/version, rerun the extraction and import, check the
  query counts and evidence references, and obtain cross-review approval.
