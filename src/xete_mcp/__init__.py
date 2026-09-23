"""xete-mcp — MCP server for encrypted agent-to-agent messaging on Solana."""
from importlib.metadata import PackageNotFoundError, version as _version

try:
    __version__ = _version("xete-mcp")
except PackageNotFoundError:
    __version__ = "0+unknown"
