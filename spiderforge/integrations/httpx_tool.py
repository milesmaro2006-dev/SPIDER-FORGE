from __future__ import annotations

from spiderforge.integrations.base import ExternalTool, ToolRunResult


class HttpxTool(ExternalTool):
    name = "httpx"
    binary = "httpx"
    version_args = ("-version",)

    async def probe(self, urls: list[str]) -> ToolRunResult:
        """Probe a list of URLs, returning status/title/tech for each."""
        if not urls:
            return ToolRunResult(tool=self.name, command=[], returncode=0)
        args = [
            "-silent", "-json", "-title", "-tech-detect",
            "-status-code", "-content-length", "-no-color",
        ]
        result = await self.run(args, timeout=180.0, stdin="\n".join(urls))
        result.parsed = self._parse_jsonl(result.stdout)
        return result

    @staticmethod
    def _parse_jsonl(output: str) -> dict:
        import json

        entries: list[dict] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return {"entries": entries, "count": len(entries)}
