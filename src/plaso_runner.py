"""Run Plaso commands reproducibly and persist execution diagnostics."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
from typing import Dict, List, Optional, Sequence


class PlasoCommandError(RuntimeError):
    """Raised when a Plaso command cannot be started or exits unsuccessfully."""


@dataclass(frozen=True)
class PlasoRunResult:
    command: List[str]
    returncode: Optional[int]
    stdout: str
    stderr: str
    started_at: str
    finished_at: str


class PlasoRunner:
    """Small subprocess wrapper for log2timeline, pinfo, and psort."""

    def __init__(self, executable: str = "log2timeline.py", psort_executable: str = "psort.py"):
        self.executable = executable
        self.psort_executable = psort_executable

    def _run(
        self,
        command: Sequence[str],
        log_path: Optional[str] = None,
        cwd: Optional[str] = None,
    ) -> PlasoRunResult:
        started = datetime.now(timezone.utc)
        try:
            completed = subprocess.run(
                list(command),
                cwd=cwd,
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:
            finished = datetime.now(timezone.utc)
            self._write_log(
                PlasoRunResult(
                    command=list(command),
                    returncode=None,
                    stdout="",
                    stderr=str(exc),
                    started_at=started.isoformat(),
                    finished_at=finished.isoformat(),
                ),
                log_path,
            )
            raise PlasoCommandError(
                f"Unable to start Plaso command {list(command)!r}: {exc}"
            ) from exc
        finished = datetime.now(timezone.utc)
        result = PlasoRunResult(
            command=list(command),
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
        )
        self._write_log(result, log_path)
        if result.returncode != 0:
            raise PlasoCommandError(
                f"Plaso command exited with code {result.returncode}: "
                f"{completed.stderr.strip() or completed.stdout.strip()}"
            )
        return result

    @staticmethod
    def _write_log(result: PlasoRunResult, log_path: Optional[str]) -> None:
        if not log_path:
            return
        path = Path(log_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "command": result.command,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "started_at": result.started_at,
                "finished_at": result.finished_at,
            }, ensure_ascii=False) + "\n")

    def run_log2timeline(
        self,
        source: str,
        storage_file: str,
        parsers: Optional[str] = None,
        log_path: Optional[str] = None,
        extra_args: Optional[Sequence[str]] = None,
    ) -> PlasoRunResult:
        Path(storage_file).parent.mkdir(parents=True, exist_ok=True)
        command = [
            self.executable,
            "--status_view", "none",
            "--storage_file", storage_file,
        ]
        if parsers:
            command.extend(["--parsers", parsers])
        if extra_args:
            command.extend(extra_args)
        command.append(source)
        return self._run(command, log_path)

    def run_psort(
        self,
        storage_file: str,
        output_file: str,
        output_format: str = "dynamic",
        log_path: Optional[str] = None,
        extra_args: Optional[Sequence[str]] = None,
    ) -> PlasoRunResult:
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        command = [
            self.psort_executable,
            "-o", output_format,
            "-w", output_file,
        ]
        if extra_args:
            command.extend(extra_args)
        command.append(storage_file)
        return self._run(command, log_path)

class DockerPlasoRunner(PlasoRunner):
    """Execute Plaso tools using an isolated Docker container."""

    def __init__(self, image: str, docker_executable: str = "docker"):
        super().__init__()

        if "@sha256:" not in image:
            raise ValueError("Use a pinned Plaso image digest")

        self.image = image
        self.docker_executable = docker_executable

    @staticmethod
    def _protect_log_path(log_path, protected_path):
        if log_path is None:
            return

        log = Path(log_path).resolve()
        protected = Path(protected_path).resolve()

        if log == protected or log.is_relative_to(protected):
            raise ValueError(
                "Execution log must be outside protected evidence"
            )
    def _docker_command(self, mounts, tool, args):
        command = [
            self.docker_executable,
            "run",
            "--rm",
            "--network", "none",
        ]

        for host_path, container_path, readonly in mounts:
            host = Path(host_path).resolve()

            if "," in str(host):
                raise ValueError("Unsupported comma in mount path")

            mount = (
                f"type=bind,source={host},"
                f"target={container_path}"
            )

            if readonly:
                mount += ",readonly"

            command.extend(["--mount", mount])

        command.extend([self.image, tool])
        command.extend(args)

        return command

    def run_log2timeline(
        self, source, storage_file, parsers=None,
        log_path=None, extra_args=None,
    ):
        source = Path(source).resolve()
        storage = Path(storage_file).resolve()

        self._protect_log_path(log_path, source)
        self._protect_log_path(log_path, storage)

        if not source.is_dir():
            raise FileNotFoundError(source)

        if storage.exists():
            raise FileExistsError(storage)

        if storage.is_relative_to(source):
            raise ValueError("Output must be outside evidence directory")

        if source.is_relative_to(storage.parent):
            raise ValueError("Output mount must not contain evidence")

        storage.parent.mkdir(parents=True, exist_ok=True)

        mounts = [
            (source, "/evidence", True),
            (storage.parent, "/output", False),
        ]

        args = [
            "--status_view", "none",
            "--storage-file", f"/output/{storage.name}",
        ]

        if parsers:
            args.extend(["--parsers", parsers])

        if extra_args:
            args.extend(extra_args)

        args.append("/evidence")

        command = self._docker_command(
            mounts, "log2timeline", args
        )

        return self._run(command, log_path)

    def run_pinfo(
        self, storage_file, log_path=None, verbose=False
    ):
        storage = Path(storage_file).resolve()

        self._protect_log_path(log_path, storage)

        if not storage.is_file():
            raise FileNotFoundError(storage)

        mounts = [
            (storage, "/input/case.plaso", True),
        ]

        args = ["-v"] if verbose else []
        args.append("/input/case.plaso")

        command = self._docker_command(
            mounts, "pinfo", args
        )

        return self._run(command, log_path)

    def run_psort(
        self, storage_file, output_file,
        output_format="dynamic",
        log_path=None, extra_args=None,
    ):

        storage = Path(storage_file).resolve()
        output = Path(output_file).resolve()

        self._protect_log_path(log_path, storage)
        self._protect_log_path(log_path, output)
        if not storage.is_file():
            raise FileNotFoundError(storage)

        if output.exists():
            raise FileExistsError(output)

        if storage.is_relative_to(output.parent):
            raise ValueError(
                "Output mount must not contain the Plaso storage"
            )

        output.parent.mkdir(parents=True, exist_ok=True)

        mounts = [
            (storage, "/input/case.plaso", True),
            (output.parent, "/output", False),
        ]

        args = [
            "-o", output_format,
            "-w", f"/output/{output.name}",
        ]

        if extra_args:
            args.extend(extra_args)

        args.append("/input/case.plaso")

        command = self._docker_command(
            mounts, "psort", args
        )

        return self._run(command, log_path)
