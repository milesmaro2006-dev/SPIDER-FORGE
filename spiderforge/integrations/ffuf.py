from __future__ import annotations

from pathlib import Path

from spiderforge.integrations.base import ExternalTool, ToolRunResult


class FfufTool(ExternalTool):
    name = "ffuf"
    binary = "ffuf"
    version_args = ("-V",)

    async def fuzz_paths(
        self,
        base_url: str,
        *,
        wordlist: Path,
        filter_codes: str = "404",
        rate: int = 100,
        timeout: float = 600.0,
    ) -> ToolRunResult:
        """Directory/path fuzzing. Requires a wordlist file."""
        if not wordlist.exists():
            return ToolRunResult(
                tool=self.name, command=[], returncode=-1, error=f"wordlist not found: {wordlist}"
            )
        url = base_url.rstrip("/") + "/FUZZ"
        args = [
            "-u", url,
            "-w", str(wordlist),
            "-fc", filter_codes,
            "-rate", str(rate),
            "-json",
            "-silent",
            "-noninteractive",
        ]
        result = await self.run(args, timeout=timeout)
        result.parsed = self._parse_jsonl(result.stdout)
        return result

    @staticmethod
    def _parse_jsonl(output: str) -> dict:
        import json

        hits: list[dict] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                hits.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return {"hits": hits, "count": len(hits)}
