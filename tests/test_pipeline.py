import csv
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from src.pipeline import run_pipeline


def test_pipeline_normalizes_missing_case_ids_without_merging_named_case():
    rows = [
        {
            "event_id": "EVT-001",
            "timestamp": "2026-10-25T02:10:00+00:00",
            "timestamp_desc": "LNK Target Accessed",
            "artifact_source": "LNK",
            "source_file": "report.docx.lnk",
            "target_path": r"C:\Cases\shared\report.docx",
            "message": "Shortcut target",
            "case_id": "",
        },
        {
            "event_id": "EVT-002",
            "timestamp": "2026-10-25T02:11:00+00:00",
            "timestamp_desc": "File Deletion Time",
            "artifact_source": "RecycleBin",
            "source_file": "$I-report.docx",
            "target_path": r"C:\Cases\shared\report.docx",
            "message": "Recycle Bin item",
            "case_id": "  ",
        },
        {
            "event_id": "EVT-003",
            "timestamp": "2026-10-25T02:12:00+00:00",
            "timestamp_desc": "LNK Target Accessed",
            "artifact_source": "LNK",
            "source_file": "other-case.lnk",
            "target_path": r"C:\Cases\shared\report.docx",
            "message": "Named case shortcut",
            "case_id": "Unspecified",
        },
    ]

    with TemporaryDirectory() as temp_dir:
        input_path = Path(temp_dir) / "events.csv"
        output_path = Path(temp_dir) / "events.json"
        findings_path = Path(temp_dir) / "findings.json"
        with input_path.open("w", encoding="utf-8", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)

        run_pipeline(
            input_file=str(input_path),
            output_file=str(output_path),
            findings_file=str(findings_path),
        )

        events = json.loads(output_path.read_text(encoding="utf-8"))
        findings = json.loads(findings_path.read_text(encoding="utf-8"))

    assert [event["case_id"] for event in events] == [None, None, "Unspecified"]
    assert len(findings) == 1
    assert findings[0]["event_ids"] == ["EVT-001", "EVT-002"]
    assert findings[0]["case_id"] is None
