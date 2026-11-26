"""Measure SQLite ingest and query latency on clearly synthetic timeline rows."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import platform
import sqlite3
import sys
import statistics
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.schema import ForensicEvent
from src.storage import TimelineStore


def build_synthetic_events(count: int) -> list[ForensicEvent]:
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    events = []
    artifacts = ("ShellBags", "LNK", "Prefetch", "JumpLists")
    for index in range(count):
        artifact = artifacts[index % len(artifacts)]
        minute = index % 1440
        events.append(ForensicEvent(
            event_id=f"BENCH-{index:07d}",
            timestamp=(start + timedelta(days=index // 1440, minutes=minute)).isoformat(),
            timestamp_desc=f"Synthetic {artifact} benchmark event",
            timestamp_type=f"Benchmark_{artifact}",
            artifact_source=artifact,
            source_file=f"benchmark/{artifact.lower()}/{index // 1000:04d}.csv",
            target_path=rf"C:\Benchmark\case-{index % 50:02d}\document-{index % 500:03d}.docx",
            message=f"Synthetic benchmark activity record {index}",
            evidence_reference=f"benchmark-fixture.csv:L{index + 2}",
            validation_status="synthetic",
            case_id=f"BENCH{index % 4:02d}",
            extra_attributes={"benchmark_fixture": True},
        ))
    return events


def measure_size(count: int, repeats: int) -> dict:
    events = build_synthetic_events(count)
    with tempfile.TemporaryDirectory(prefix="wintrace-benchmark-") as temp:
        database = Path(temp) / "benchmark.sqlite"
        with TimelineStore(str(database)) as store:
            start = time.perf_counter()
            inserted = store.insert_events(events)
            insert_seconds = time.perf_counter() - start

            samples: dict[str, list[float]] = {
                "case_filter": [], "artifact_and_keyword": [], "full_timeline": [],
            }
            for _ in range(repeats):
                start = time.perf_counter()
                result = store.query(case_id="BENCH01", limit=100)
                samples["case_filter"].append(time.perf_counter() - start)
                assert result

                start = time.perf_counter()
                result = store.query(artifact="Prefetch", keyword="document-", limit=100)
                samples["artifact_and_keyword"].append(time.perf_counter() - start)
                assert result

                start = time.perf_counter()
                result = store.query(limit=100)
                samples["full_timeline"].append(time.perf_counter() - start)
                assert len(result) == min(count, 100)

            return {
                "events_requested": count,
                "events_inserted": inserted,
                "database_bytes": database.stat().st_size,
                "insert_seconds": round(insert_seconds, 6),
                "queries_median_seconds": {
                    name: round(statistics.median(values), 6)
                    for name, values in samples.items()
                },
            }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", default="692,6920,27680", help="Comma-separated row counts")
    parser.add_argument("--repeats", type=int, default=7)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    sizes = [int(value.strip()) for value in args.sizes.split(",") if value.strip()]
    if not sizes or any(size < 1 for size in sizes):
        parser.error("--sizes must contain positive integers")
    if args.repeats < 1:
        parser.error("--repeats must be positive")

    result = {
        "benchmark": "WinTrace SQLite ingest and query",
        "fixture": "Deterministic synthetic rows only; not CASE01 evidence",
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "sqlite": sqlite3.sqlite_version,
            "processor": platform.processor() or "not reported by OS",
        },
        "repeats_per_query": args.repeats,
        "measurements": [measure_size(size, args.repeats) for size in sizes],
    }
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
