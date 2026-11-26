# Week 3 SQLite benchmark

## Method

`scripts/benchmark_timeline.py` creates deterministic synthetic `ForensicEvent` rows marked `validation_status=synthetic`; it does not read or alter CASE01 evidence. The benchmark measures SQLite insertion and three query patterns through `TimelineStore`: case-filtered results, artifact plus keyword filtering, and chronological timeline retrieval. Query values are medians of seven repetitions. The test sizes are 692, 6,920, and 27,680 events, so 692 approximates the current CASE01 event count while larger sizes show scaling.

## Environment

- Python 3.12.10
- SQLite 3.49.1
- Windows 11, Intel64 Family 6 Model 154 Stepping 3

## Measured results

| Synthetic events | Insert time (s) | SQLite size (bytes) | Case filter median (s) | Artifact + keyword median (s) | Timeline median (s) |
|---:|---:|---:|---:|---:|---:|
| 692 | 0.207232 | 622,592 | 0.002587 | 0.002764 | 0.002215 |
| 6,920 | 2.015709 | 5,726,208 | 0.006119 | 0.006458 | 0.002335 |
| 27,680 | 9.314989 | 22,732,800 | 0.020645 | 0.012270 | 0.002471 |

The machine-readable measurements are in `benchmark_results.json`. Re-run from the repo root with:

```powershell
python scripts/benchmark_timeline.py --sizes 692,6920,27680 --repeats 7 --output docs/benchmark_results.json
```

## Interpretation and limits

This rerun uses the merged SQLite schema and direct UTC ISO timestamp comparisons; the largest-case timeline median was 2.471 ms. `EXPLAIN QUERY PLAN` for the time-range query uses `idx_events_timestamp`. It does not establish a universal performance guarantee: results depend on the machine, Python/SQLite versions, filesystem, and synthetic field distribution. No comparison with a prior implementation or other database was performed, so this report does not claim a speedup.
