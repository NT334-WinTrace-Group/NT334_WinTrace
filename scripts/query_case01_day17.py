"""Print event, case, artifact, and evidence-reference counts from a timeline DB."""

import json
import sqlite3
import sys


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: query_case01_day17.py DATABASE")

    with sqlite3.connect(sys.argv[1]) as connection:
        total = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        unique_ids = connection.execute(
            "SELECT COUNT(DISTINCT event_id) FROM events"
        ).fetchone()[0]
        case_counts = connection.execute(
            "SELECT case_id, COUNT(*) FROM events GROUP BY case_id ORDER BY case_id"
        ).fetchall()
        artifact_counts = connection.execute(
            "SELECT artifact_source, COUNT(*) FROM events "
            "GROUP BY artifact_source ORDER BY artifact_source"
        ).fetchall()
        with_references = connection.execute(
            "SELECT COUNT(*) FROM events "
            "WHERE evidence_reference IS NOT NULL AND evidence_reference <> ''"
        ).fetchone()[0]

    print(json.dumps({
        "total_events": total,
        "unique_event_ids": unique_ids,
        "case_counts": case_counts,
        "artifact_counts": artifact_counts,
        "events_with_evidence_reference": with_references,
        "events_missing_evidence_reference": total - with_references,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
