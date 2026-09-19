from __future__ import annotations

import asyncio
import shutil
from abc import ABC
from dataclasses import dataclass, field


@dataclass
class ToolStatus:
    name: str
    available: bool
    path: str | None = None
    version: str | None = None
    error: str | None = None


@dataclass
class ToolRunResult:
    tool: str
    command: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    parsed: dict = field(default_factory=dict)
    error: str | None = None


class ExternalTool(ABC):
    name: str = "tool"
    binary: str = "tool"
    version_args: tuple[str, ...] = ("--version",)

    def status(self) -> ToolStatus:
        path = shutil.which(self.binary)
        if not path:
            return ToolStatus(name=self.name, available=False, error="not found in PATH")
        return ToolStatus(name=self.name, available=True, path=path)

    async def version(self) -> str | None:
        s = self.status()
        if not s.available:
            return None
        try:
            proc = await asyncio.create_subprocess_exec(
                self.binary,
                *self.version_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            return stdout.decode("utf-8", errors="replace").strip().splitlines()[0]
        except Exception:
            return None

    async def run(
        self, args: list[str], *, timeout: float = 300.0, stdin: str | None = None
    ) -> ToolRunResult:
        """Run the binary safely (no shell)."""
        if not self.status().available:
            return ToolRunResult(
                tool=self.name,
                command=[self.binary, *args],
                returncode=-1,
                error=f"{self.binary} not available",
            )
        cmd = [self.binary, *args]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if stdin else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(stdin.encode() if stdin else None), timeout=timeout
                )
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                return ToolRunResult(
                    tool=self.name, command=cmd, returncode=-1, error="timeout"
                )
            return ToolRunResult(
                tool=self.name,
                command=cmd,
                returncode=proc.returncode or 0,
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
            )
        except Exception as exc:  # noqa: BLE001
            return ToolRunResult(
                tool=self.name,
                command=cmd,
                returncode=-1,
                error=f"{type(exc).__name__}: {exc}",
            )
