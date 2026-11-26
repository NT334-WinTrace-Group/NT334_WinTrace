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
| 692 | 0.205046 | 512,000 | 0.002437 | 0.002283 | 0.002427 |
| 6,920 | 1.716492 | 4,825,088 | 0.005949 | 0.005457 | 0.004309 |
| 27,680 | 21.422707 | 19,189,760 | 0.029848 | 0.033068 | 0.021980 |

The machine-readable measurements are in `benchmark_results.json`. Re-run from the repo root with:

```powershell
python scripts/benchmark_timeline.py --sizes 692,6920,27680 --repeats 7 --output docs/benchmark_results.json
```

## Interpretation and limits

On this run, query medians at 27,680 synthetic rows stayed below 34 ms. Insert time increased more sharply at the largest size, reaching about 21.4 seconds. This points to ingestion as the next performance area to profile if the project grows beyond the current dataset size. It does not establish a universal performance guarantee: results depend on the machine, Python/SQLite versions, filesystem, and synthetic field distribution. No comparison with a prior implementation or other database was performed, so this report does not claim a speedup.
