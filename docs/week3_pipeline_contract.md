# WinTrace Week 3 Pipeline Contract — Day 15

## Purpose and status

This contract defines the inputs allowed into the CASE01 pipeline, the event
identity/provenance requirements, and a repeatable local environment/manifest
check. It is based on integrated `dev` commit `d303420` and the files present
in the workspace on 2026-11-25. It does not certify access to the original
CASE01 disk image or a fresh Plaso extraction.

## Integration snapshot

- `origin/dev`: `d303420` — PR #10 and PR #13 are integrated.
- `origin/week2`: `e560b48` — PR #12 is integrated there; `dev` is 16 commits
  ahead of `week2` at this snapshot. Week 3 work should target `dev`.
- PR #10 was merged into `dev` on 2026-11-24. PR #12 was merged into `week2`
  on 2026-11-23; its changes are included in the integrated branch history.

## CASE01 input contract

| Input | Role | Pipeline rule |
|---|---|---|
| `results/case01_shellbags_events.csv` | Canonical normalized CASE01 ShellBags input (`CASE01-EVT-001`) | Import once as the sole ShellBags event source. Its 383 `event_id` values are the primary event keys. |
| `analysis/phuc-artifacts/tool_output/sbecmd/Deduplicated.csv` | SBECmd tool output and provenance source (`CASE01-OUT-001`) | Use to verify source rows/references; do not import alongside the normalized CSV. Doing so can duplicate the same ShellBags evidence. |
| `evidence/case01/` image, hives and auxiliary artifact directories | Original/parser inputs listed in the manifest | Only claim a real parser run for files that are present, hashed, and tied to a recorded tool run. Missing files are not replaced with scenario fixtures. |
| `results/plaso_raw_output.csv` and `results/plaso_raw_output_real.*` | Alice scenario test data | Synthetic/test-only. Never combine with CASE01 or describe as CASE01 evidence. |

`shellbags_findings.csv`, if used for cross-checking, is not a second import
source. Preserve its provenance as a review/reference source only.

### Event identity and schema v2

- Logical identity is `(case_id, event_id)`. `event_id` is unique among the
  current 383 ShellBags rows; the case namespace prevents IDs from different
  datasets being conflated.
- Normalized events must expose `case_id`, `timestamp_type`,
  `evidence_reference`, and `validation_status` as direct schema fields.
- The current source CSV has direct Schema v2 fields and retains detailed
  parser/provenance metadata in `extra_attributes`.
- Path normalization changes separators in `target_path` only; adapters preserve
  the exact input literal in `extra_attributes.raw_path`. Do not rewrite the
  CASE01 source CSV to apply normalization.
- All current rows carry direct `case_id="CASE01"`. If an older input lacks it,
  the adapter may explicitly infer CASE01 from the `CASE01-` event ID prefix;
  it must not infer a case from a filename or timestamp.
- Timestamps entering storage are ISO-8601 UTC. Keep the original timestamp
  meaning in `timestamp_type`; do not reinterpret ShellItem target metadata as
  user interaction.
- Importing the same normalized source again must not increase the row count.

### Sample input and expected normalized output

Input CSV row shape from the current source:

```csv
event_id,timestamp,timestamp_desc,timestamp_type,artifact_source,source_file,target_path,evidence_reference,validation_status,case_id,extra_attributes
CASE01-SB0001,2014-12-16T16:10:26+00:00,ShellItem Target Modified Time,ShellItem_FolderModified,ShellBags,UsrClass.dat,E:\Secret Project Data\design\winter_whether_advisory.zip,Deduplicated.csv:L59 | hive=UsrClass.dat | BagPath=BagMRU\1\0\1\4 | Slot=0 | MRU=0 | ShellType=File | verified: ShellBags Explorer v2026.10.1 (CASE01-F004),unverified,CASE01,"{""semantic_class"":""target_metadata"",""timestamp_precision"":""fat_2s""}"
```

Expected normalized identity/provenance fields:

```json
{
  "event_id": "CASE01-SB0001",
  "case_id": "CASE01",
  "timestamp": "2014-12-16T16:10:26+00:00",
  "timestamp_desc": "ShellItem Target Modified Time",
  "timestamp_type": "ShellItem_FolderModified",
  "target_path": "E:\\Secret Project Data\\design\\winter_whether_advisory.zip",
  "extra_attributes": {
    "raw_path": "E:\\Secret Project Data\\design\\winter_whether_advisory.zip"
  },
  "artifact_source": "ShellBags",
  "evidence_reference": "Deduplicated.csv:L59 | hive=UsrClass.dat | BagPath=BagMRU\\1\\0\\1\\4 | Slot=0 | MRU=0 | ShellType=File | verified: ShellBags Explorer v2026.10.1 (CASE01-F004)",
  "validation_status": "unverified"
}
```

The row is an example of imported source data, not a claim that target
metadata proves user activity or a newly verified finding.

## Environment and manifest check

From the repository root, run:

```powershell
python scripts\check_week3_inputs.py
```

The command reports Python/dependency/executable availability, validates
manifest IDs and source paths, verifies file size/SHA-256 where recorded, and
checks the canonical ShellBags CSV for schema, timestamp, JSON metadata,
`event_id` uniqueness and CASE01 identity. It exits `1` when it finds errors;
warnings identify missing external evidence or tools that need separate setup.
It is a local integrity check, not a substitute for acquisition records or
Plaso execution logs.

On this checkout, the command exits `1` because it finds a stale normalized
ShellBags size/hash and six synthetic fixture rows whose manifest size/hash do
not match the checked-out placeholder files. It also reports missing external
CASE01 image/hive/auxiliary inputs as warnings. This is an expected actionable
failure until the evidence owners reconcile those inputs and manifest entries.

### Environment snapshot

`requirements.txt` currently declares minimum versions, not a lockfile. On the
workspace used for this check:

| Component | Observed |
|---|---|
| Python | 3.12.6 |
| pytest | 9.2.0 |
| pandas | 2.2.3 |
| numpy | 2.1.3 |
| pydantic | 2.11.4 |
| python-dateutil | 2.9.0.post0 |
| streamlit | 1.57.0 |
| python-registry, liblnk-python, evtx | Not installed in this Python environment |
| `log2timeline.py`, `psort.py` | Not found on native PATH |
| Docker, WSL executables | Found; engine/runtime readiness and Plaso image version still require a separate check |

These are observed versions, not pinned project requirements. Do not treat
Docker/WSL executable presence as proof that Plaso can currently run.

## Current P0/P1 issue list

### P0 — Must resolve before treating the manifest as verified

1. **Normalized ShellBags manifest size/hash is stale.** The manifest records
   `212716` bytes and SHA-256
   `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
   for `results/case01_shellbags_events.csv`. At integrated `dev` commit
   `d303420`, the workspace file is `575015` bytes with SHA-256
   `14f50ebe794b3cd51142bd1319a2767dd208d63a973bbc17da51cfb564f850a8`.
   The manifest hash is the empty-file digest. Phuc/Quyen must confirm the
   authoritative version before updating the manifest.
2. **The six Alice scenario manifest hashes/sizes do not match the files in
   this checkout.** Those files are marked `synthetic`, but their manifest rows
   currently say `VERIFIED`; the checker reports a size and/or SHA-256 mismatch
   for each. Treat the files as synthetic fixtures, not intact forensic
   evidence, and reconcile their manifest metadata before using integrity
   status in a report.

### P1 — Required for reproducible real-evidence pipeline

1. **Original image and registry hives are absent from this checkout.** The
   manifest paths `evidence/case01/cfreds_2015_data_leakage_pc.dd`,
   `evidence/case01/hives/UsrClass.dat`, and
   `evidence/case01/hives/NTUSER.DAT` were not found. The manifest also lists
   Prefetch/LNK/Jump Lists sources that must be checked before claiming
   multi-artifact CASE01 extraction.
2. **No dependency lockfile exists.** `requirements.txt` uses minimum-version
   ranges; a clean, identical environment is not yet pinned.
3. **Native Plaso commands and Python forensic parser packages are absent.**
   Docker/WSL executables exist, but Plaso image/runtime and parser tool
   versions must be verified separately before a reproducible extraction run.
4. **Keep the normalized CSV schema current.** The current file has direct
   Schema v2 fields and 383 unique event IDs. Do not regress to input where
   provenance is available only in `extra_attributes`.

## Ownership and handoff

- **Phuc:** confirm canonical ShellBags source, authoritative manifest hashes,
  and availability/provenance of CASE01 raw and auxiliary inputs.
- **Quyen:** approve schema-v2 field contract and any manifest/schema change.
- **Nam:** maintain the environment/input check and preserve one-source,
  idempotent pipeline import.
- **Thi:** consume this contract for correlation input and verify case
  isolation.
