# Week 3 Day 18 - SQLite data API

## Contract

This work keeps Quyên's Schema v2 columns unchanged. `TimelineStore` remains
the stable Python adapter; its `query()` returns `ForensicEvent` objects with
the direct provenance fields (`case_id`, `timestamp_type`,
`evidence_reference`, and `validation_status`) and `extra_attributes`
preserved.

- New and migrated timestamps are stored as timezone-aware UTC ISO 8601 strings
  with `+00:00`. Existing timestamp precision is not rounded.
- Query bounds are inclusive. A naive `datetime` bound is interpreted as UTC;
  an aware bound is converted to UTC. A reversed range raises `ValueError`.
- `artifact`, `case_id`, and `validation_status` comparisons are
  case-insensitive.
- `path` searches within `target_path`. `keyword` searches `target_path`,
  `source_file`, `message`, `event_id`, and `evidence_reference`. SQL wildcard
  characters supplied by the user are treated literally.
- Existing schema migrations remain additive: missing v2 columns and indexes
  are created without dropping or renaming data. Known pre-UTC fingerprint
  formats are migrated transactionally; an unknown fingerprint or collision
  aborts initialization rather than silently rewriting a record.

## Example

```python
from datetime import datetime, timezone
from src.storage import TimelineStore

with TimelineStore("results/CASE01/timeline.db") as store:
    events = store.query(
        start=datetime(2015, 3, 23, tzinfo=timezone.utc),
        end=datetime(2015, 3, 24, tzinfo=timezone.utc),
        artifact="shellbags",
        path=r"\\10.11.11.128\secured_drive",
        keyword="CASE01-SB0133",
        case_id="CASE01",
        validation_status="verified",
        limit=500,
    )
```

The Streamlit viewer uses this same adapter for UTC date, path, keyword, and
artifact filters. No new database table or Schema v2 field is introduced.

## Verification

`tests/test_storage.py` covers UTC conversion, indexed time queries, wildcard
escaping, provenance round trips, legacy database migrations, and duplicate
imports. `tests/test_week3_integration.py` repeats an import of the committed
CASE01 parser outputs and checks the query results and evidence references.
