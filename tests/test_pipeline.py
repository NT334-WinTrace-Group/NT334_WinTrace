import csv
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from src.pipeline import run_pipeline


def test_pipeline_keeps_supporting_tool_source_label():
    row = {
        "event_id": "CASE01-LNK0001",
        "timestamp": "2015-03-25T15:24:48+00:00",
        "timestamp_desc": "LNK File Modified",
        "timestamp_type": "LNK_FileModified",
        "artifact_source": "LNK",
        "source_file": "report.docx.lnk",
        "target_path": r"C:\Users\informant\Desktop\report.docx",
        "message": "Supporting LNK event",
        "parser": "lecmd",
        "case_id": "CASE01",
        "extra_attributes": "{}",
    }

    with TemporaryDirectory() as temp_dir:
        input_path = Path(temp_dir) / "supporting.csv"
        output_path = Path(temp_dir) / "normalized.json"
        with input_path.open("w", encoding="utf-8", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=row.keys())
            writer.writeheader()
            writer.writerow(row)

        run_pipeline(
            input_file=str(input_path),
            output_file=str(output_path),
            case_id="CASE01",
            source_label="case01-supporting-tools",
        )

        [event] = json.loads(output_path.read_text(encoding="utf-8"))

    assert event["parser"] == "lecmd"
    assert event["extra_attributes"]["source_label"] == "case01-supporting-tools"
