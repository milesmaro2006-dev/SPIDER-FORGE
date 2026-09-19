from __future__ import annotations

from spiderforge.integrations.base import ExternalTool, ToolRunResult


class NmapTool(ExternalTool):
    name = "nmap"
    binary = "nmap"
    version_args = ("--version",)

    async def scan_top_ports(self, host: str, *, top: int = 100) -> ToolRunResult:
        """Scan the top N TCP ports. Safe default: no service scripts, no OS detection."""
        args = ["-Pn", "-T4", "--top-ports", str(top), "-oG", "-", host]
        result = await self.run(args, timeout=180.0)
        result.parsed = self._parse_greppable(result.stdout)
        return result

    @staticmethod
    def _parse_greppable(output: str) -> dict:
        open_ports: list[int] = []
        for line in output.splitlines():
            if not line.startswith("Host:") or "Ports:" not in line:
                continue
            _, _, ports = line.partition("Ports:")
            for entry in ports.split(","):
                parts = entry.strip().split("/")
                if len(parts) >= 2 and parts[1] == "open":
                    try:
                        open_ports.append(int(parts[0]))
                    except ValueError:
                        continue
        return {"open_ports": sorted(set(open_ports))}
