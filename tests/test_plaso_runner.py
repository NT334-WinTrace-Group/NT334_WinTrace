import json

import pytest

from src.plaso_runner import PlasoCommandError, PlasoRunner


def test_runner_writes_execution_log(tmp_path):
    log_path = tmp_path / "run.jsonl"
    runner = PlasoRunner(executable="python", psort_executable="python")
    result = runner._run(["python", "-c", "print('ok')"], str(log_path))

    assert result.returncode == 0
    record = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    assert record["returncode"] == 0
    assert "ok" in record["stdout"]


def test_runner_surfaces_command_failure(tmp_path):
    runner = PlasoRunner(executable="python")
    log_path = tmp_path / "run.jsonl"
    with pytest.raises(PlasoCommandError, match="exited with code"):
        runner._run(["python", "-c", "raise SystemExit(3)"], str(log_path))
    record = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    assert record["returncode"] == 3


def test_runner_logs_when_tool_cannot_be_started(tmp_path):
    log_path = tmp_path / "run.jsonl"
    runner = PlasoRunner(executable="wintrace-missing-plaso-command")

    with pytest.raises(PlasoCommandError, match="Unable to start"):
        runner._run([runner.executable], str(log_path))

    record = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    assert record["returncode"] is None
    assert record["stderr"]
