from backend.app.tools.base import BaseTool
from backend.app.tools.subfinder import SubfinderTool
from backend.app.tools.httpx_probe import HttpxTool
from backend.app.tools.nmap import NmapTool
from backend.app.tools.dnsx import DnsxTool

TOOL_REGISTRY: dict[str, type[BaseTool]] = {
    "subfinder": SubfinderTool,
    "httpx": HttpxTool,
    "nmap": NmapTool,
    "dnsx": DnsxTool,
}
