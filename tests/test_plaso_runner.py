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

from src.plaso_runner import DockerPlasoRunner


TEST_IMAGE = "log2timeline/plaso@sha256:" + "a" * 64


def test_docker_runner_build_command(tmp_path):
    runner = DockerPlasoRunner(TEST_IMAGE)

    command = runner._docker_command(
        [
            (tmp_path, "/evidence", True),
        ],
        "pinfo",
        ["/evidence/case.plaso"],
    )

    assert command[:3] == ["docker", "run", "--rm"]
    assert "--network" in command
    assert "none" in command
    assert TEST_IMAGE in command
    assert any(
        "target=/evidence,readonly" in arg
        for arg in command
    )
    assert command[-2:] == [
        "pinfo", "/evidence/case.plaso"
    ]


def test_docker_runner_rejects_unpinned_image():
    with pytest.raises(ValueError):
        DockerPlasoRunner("log2timeline/plaso:latest")


def test_docker_runner_rejects_existing_storage(tmp_path):
    runner = DockerPlasoRunner(TEST_IMAGE)

    evidence = tmp_path / "evidence"
    evidence.mkdir()

    storage = tmp_path / "existing.plaso"
    storage.touch()

    with pytest.raises(FileExistsError):
        runner.run_log2timeline(evidence, storage)


def test_docker_runner_protects_evidence(tmp_path):
    runner = DockerPlasoRunner(TEST_IMAGE)

    evidence = tmp_path / "evidence"
    evidence.mkdir()

    with pytest.raises(ValueError):
        runner.run_log2timeline(
            evidence,
            evidence / "output.plaso"
        )


def test_docker_runner_pinfo_readonly(tmp_path, monkeypatch):
    runner = DockerPlasoRunner(TEST_IMAGE)

    storage = tmp_path / "case.plaso"
    storage.touch()

    monkeypatch.setattr(
        runner,
        "_run",
        lambda command, log_path=None: command,
    )

    command = runner.run_pinfo(storage)

    assert "pinfo" in command
    assert any(
        "target=/input/case.plaso,readonly" in arg
        for arg in command
    )
def test_docker_runner_rejects_log_inside_evidence(tmp_path):
    runner = DockerPlasoRunner(TEST_IMAGE)

    evidence = tmp_path / "evidence"
    evidence.mkdir()

    storage = tmp_path / "output" / "case.plaso"

    with pytest.raises(ValueError):
        runner.run_log2timeline(
            source=evidence,
            storage_file=storage,
            log_path=evidence / "execution.jsonl",
        )


def test_docker_runner_rejects_log_over_storage(tmp_path):
    runner = DockerPlasoRunner(TEST_IMAGE)

    storage = tmp_path / "case.plaso"
    storage.write_bytes(b"original evidence")

    with pytest.raises(ValueError):
        runner.run_pinfo(
            storage_file=storage,
            log_path=storage,
        )

    assert storage.read_bytes() == b"original evidence"