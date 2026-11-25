import csv
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from src.pipeline import PipelineInputError, main, run_pipeline
from src.storage import TimelineStore


def _write_rows(path, rows):
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def _supporting_row():
    return {
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


def test_pipeline_keeps_supporting_tool_source_label():
    with TemporaryDirectory() as temp_dir:
        input_path = Path(temp_dir) / "supporting.csv"
        output_path = Path(temp_dir) / "normalized.json"
        _write_rows(input_path, [_supporting_row()])

        run_pipeline(
            input_file=str(input_path),
            output_file=str(output_path),
            case_id="CASE01",
            source_label="case01-supporting-tools",
        )

        [event] = json.loads(output_path.read_text(encoding="utf-8"))

    assert event["parser"] == "lecmd"
    assert event["extra_attributes"]["source_label"] == "case01-supporting-tools"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("timestamp", "not-a-timestamp", "Invalid timestamp"),
        ("extra_attributes", "{malformed", "Invalid extra_attributes JSON"),
    ],
)
def test_pipeline_fails_before_outputs_when_any_record_is_invalid(
    tmp_path, field, value, message
):
    row = _supporting_row()
    row[field] = value
    input_path = tmp_path / "input.csv"
    output_path = tmp_path / "normalized.json"
    database_path = tmp_path / "timeline.db"
    findings_path = tmp_path / "findings.json"
    error_path = tmp_path / "errors.json"
    _write_rows(input_path, [_supporting_row(), row])

    with pytest.raises(PipelineInputError, match=message):
        run_pipeline(
            input_file=str(input_path),
            output_file=str(output_path),
            database_file=str(database_path),
            findings_file=str(findings_path),
            error_log=str(error_path),
        )

    assert json.loads(error_path.read_text(encoding="utf-8"))[0]["record"] == 2
    assert not output_path.exists()
    assert not database_path.exists()
    assert not findings_path.exists()


def test_pipeline_cli_returns_nonzero_for_missing_source(tmp_path, monkeypatch, capsys):
    missing_input = tmp_path / "missing.csv"
    monkeypatch.setattr(
        sys,
        "argv",
        ["pipeline", "--input", str(missing_input), "--output", str(tmp_path / "out.json")],
    )

    assert main() == 1
    assert "[ERROR] Input file not found" in capsys.readouterr().err


def test_pipeline_places_all_outputs_under_case_directory_and_is_idempotent(tmp_path):
    input_path = tmp_path / "supporting.csv"
    _write_rows(input_path, [_supporting_row()])
    output_root = tmp_path / "output"
    def run_import():
        return run_pipeline(
            input_file=str(input_path),
            output_file="normalized.json",
            database_file="timeline.db",
            findings_file="findings.json",
            case_id="CASE01",
            case_output_dir=str(output_root),
        )

    run_import()
    run_import()

    case_dir = output_root / "CASE01"
    assert (case_dir / "normalized.json").is_file()
    assert (case_dir / "findings.json").is_file()
    with TimelineStore(str(case_dir / "timeline.db")) as store:
        assert store.count() == 1


def test_pipeline_refuses_two_shellbags_event_inputs(tmp_path):
    row = _supporting_row()
    row["artifact_source"] = "ShellBags"
    row["timestamp_type"] = "ShellBag_LastInteracted"
    row["parser"] = "sbecmd"
    source = tmp_path / "shellbags.csv"
    _write_rows(source, [row])

    with pytest.raises(PipelineInputError, match="one canonical ShellBags"):
        run_pipeline(
            input_file=str(source),
            shellbags_file=str(source),
            output_file=str(tmp_path / "output.json"),
        )
    assert not (tmp_path / "output.json").exists()


def test_pipeline_rejects_unsupported_artifact_filter_before_outputs(tmp_path):
    input_path = tmp_path / "supporting.csv"
    output_path = tmp_path / "normalized.json"
    _write_rows(input_path, [_supporting_row()])

    with pytest.raises(PipelineInputError, match="Unsupported artifact filter"):
        run_pipeline(
            input_file=str(input_path),
            output_file=str(output_path),
            filter_artifact="ImaginaryArtifact",
        )

    assert not output_path.exists()
