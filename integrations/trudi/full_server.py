"""Task-facing TRUDI MCP server for Hunter full-mode investigations.

This module does not reimplement any forensic tool.  It imports TRUDI's
official server and applies FastMCP's visibility transform so the primary
analyst only sees tools that the current Hunter deployment has qualified.
"""

from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TRUDI_ROOT = PROJECT_ROOT / "third_party" / "trudi"
if str(TRUDI_ROOT) not in sys.path:
    sys.path.insert(0, str(TRUDI_ROOT))
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from server import mcp  # noqa: E402
from full_tools import MINIMAL_FULL_TOOLS  # noqa: E402

mcp.enable(names=set(MINIMAL_FULL_TOOLS), components={"tool"}, only=True)


if __name__ == "__main__":
    mcp.run(transport="stdio")
