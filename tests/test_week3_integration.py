from datetime import datetime, timezone
from pathlib import Path

from src.normalizer import PlasoNormalizer, ShellBagsNormalizer
from src.storage import TimelineStore


ROOT = Path(__file__).resolve().parents[1]


def test_case01_import_is_idempotent_and_queryable(tmp_path):
    supporting, supporting_errors = PlasoNormalizer.normalize_file_with_report(
        str(ROOT / "analysis" / "phuc-artifacts" / "case01_supporting_events.csv"),
        "case01-supporting-tools",
        case_id="CASE01",
    )
    shellbags, shellbags_errors = ShellBagsNormalizer.normalize_file_with_report(
        str(ROOT / "results" / "case01_shellbags_events.csv")
    )
    events = supporting + shellbags
    database = tmp_path / "CASE01" / "timeline.db"

    assert supporting_errors == []
    assert shellbags_errors == []
    assert len(supporting) == 309
    assert len(shellbags) == 383

    with TimelineStore(str(database)) as store:
        assert store.insert_events(events) == 692
        assert store.insert_events(events) == 0
        assert store.count() == 692
        results = store.query(
            start=datetime(2015, 3, 23, tzinfo=timezone.utc),
            end=datetime(2015, 3, 24, tzinfo=timezone.utc),
            artifact="shellbags",
            keyword="CASE01-SB0133",
            case_id="case01",
        )
        plan = store.connection.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM events WHERE timestamp >= ? AND timestamp <= ?",
            ("2015-03-23T00:00:00+00:00", "2015-03-24T00:00:00+00:00"),
        ).fetchall()

    assert len(results) == 1
    assert results[0].event_id == "CASE01-SB0133"
    assert results[0].timestamp.endswith("+00:00")
    assert results[0].evidence_reference
    assert any("idx_events_timestamp" in row["detail"] for row in plan)
