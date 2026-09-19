from __future__ import annotations

from spiderforge.integrations.base import ExternalTool, ToolRunResult


class NucleiTool(ExternalTool):
    name = "nuclei"
    binary = "nuclei"
    version_args = ("-version",)

    async def scan(
        self,
        target: str,
        *,
        severity: str = "medium,high,critical",
        templates: list[str] | None = None,
        rate_limit: int = 50,
        timeout: float = 600.0,
    ) -> ToolRunResult:
        """Run nuclei against a target. Only reports severities >= medium by default."""
        args = [
            "-target", target,
            "-severity", severity,
            "-jsonl",
            "-silent",
            "-no-color",
            "-rate-limit", str(rate_limit),
        ]
        if templates:
            for t in templates:
                args += ["-t", t]
        result = await self.run(args, timeout=timeout)
        result.parsed = self._parse_jsonl(result.stdout)
        return result

    @staticmethod
    def _parse_jsonl(output: str) -> dict:
        import json

        findings: list[dict] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return {"findings": findings, "count": len(findings)}
