import csv

import pytest

from scripts.prepare_plaso_events import FIELDS, prepare


def write_source(root, timestamps):
    source = root / "CASE01_plaso_full.csv"
    with source.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=sorted(FIELDS))
        writer.writeheader()
        for ts in timestamps:
            row = dict.fromkeys(FIELDS, "")
            row.update(datetime=ts, data_type="windows:lnk:link")
            writer.writerow(row)
    return source


def test_prepare_preserves_record_numbers_and_source(tmp_path):
    source = write_source(tmp_path, ["1980-01-01T04:00:00+00:00", "0000-00-00T00:00:00.000000+00:00", "2015-03-25T15:29:08.934806+00:00"])
    original = source.read_bytes()
    result = prepare(tmp_path)
    assert result["total_input"] == 3
    assert result["valid_records"] == 2
    assert result["quarantined_records"] == 1
    with (tmp_path / "CASE01_plaso_valid.csv").open(encoding="utf-8", newline="") as f:
        assert [r["source_record"] for r in csv.DictReader(f)] == ["1", "3"]
    with (tmp_path / "CASE01_plaso_quarantine.csv").open(encoding="utf-8", newline="") as f:
        row = next(csv.DictReader(f))
        assert row["source_record"] == "2"
        assert row["rejection_reason"]
    assert source.read_bytes() == original


def test_prepare_refuses_overwrite(tmp_path):
    write_source(tmp_path, ["2015-03-25T15:29:08+00:00"])
    output = tmp_path / "CASE01_plaso_valid.csv"
    output.write_text("keep", encoding="utf-8")
    with pytest.raises(FileExistsError):
        prepare(tmp_path)
    assert output.read_text(encoding="utf-8") == "keep"
    assert not (tmp_path / "CASE01_plaso_quarantine.csv").exists()
