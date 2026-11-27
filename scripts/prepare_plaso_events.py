"""Split CASE01 psort CSV into valid and quarantined timestamp records."""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from contextlib import ExitStack
from pathlib import Path
import sys

# Support direct invocation from any working directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.schema import parse_iso_utc

FIELDS = {"datetime", "timestamp_desc", "source", "source_long", "message", "parser", "data_type", "display_name", "tag"}


def prepare(root: Path) -> dict:
    csv.field_size_limit(2**31 - 1)
    source = root / "CASE01_plaso_full.csv"
    valid = root / "CASE01_plaso_valid.csv"
    quarantine = root / "CASE01_plaso_quarantine.csv"
    for path in (valid, quarantine):
        if path.exists():
            raise FileExistsError(f"Refusing to overwrite {path}")
    accepted = rejected = 0
    types = Counter()
    created = []
    try:
        with ExitStack() as stack:
            f = stack.enter_context(source.open(encoding="utf-8-sig", newline=""))
            reader = csv.DictReader(f)
            header = reader.fieldnames or []
            if not FIELDS.issubset(header) or len(header) != len(set(header)) or {"source_record", "rejection_reason"}.intersection(header):
                raise ValueError("Unexpected psort CSV header")
            fields = header + ["source_record"]
            good = stack.enter_context(valid.open("x", encoding="utf-8", newline=""))
            created.append(valid)
            bad = stack.enter_context(quarantine.open("x", encoding="utf-8", newline=""))
            created.append(quarantine)
            good_writer = csv.DictWriter(good, fieldnames=fields)
            bad_writer = csv.DictWriter(bad, fieldnames=fields + ["rejection_reason"])
            good_writer.writeheader()
            bad_writer.writeheader()
            for index, row in enumerate(reader, start=1):
                if None in row or any(v is None for v in row.values()):
                    raise ValueError(f"Malformed CSV record {index}")
                row["source_record"] = index
                try:
                    parse_iso_utc(row["datetime"])
                except (ValueError, OverflowError) as exc:
                    row["rejection_reason"] = str(exc)
                    bad_writer.writerow(row)
                    rejected += 1
                    types[row["data_type"]] += 1
                else:
                    good_writer.writerow(row)
                    accepted += 1
    except BaseException:
        # Remove only outputs created by this invocation on failure.
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return {"total_input": accepted + rejected, "valid_records": accepted,
            "quarantined_records": rejected, "quarantined_data_types": dict(types)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="Directory containing CASE01_plaso_full.csv")
    args = parser.parse_args()
    print(json.dumps(prepare(args.directory), indent=2))


if __name__ == "__main__":
    main()
