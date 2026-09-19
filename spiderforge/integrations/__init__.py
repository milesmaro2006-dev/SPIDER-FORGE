from spiderforge.integrations.ffuf import FfufTool
from spiderforge.integrations.httpx_tool import HttpxTool
from spiderforge.integrations.nmap import NmapTool
from spiderforge.integrations.nuclei import NucleiTool

TOOLS = {
    "nmap": NmapTool(),
    "httpx": HttpxTool(),
    "nuclei": NucleiTool(),
    "ffuf": FfufTool(),
}

__all__ = ["TOOLS", "NmapTool", "HttpxTool", "NucleiTool", "FfufTool"]
