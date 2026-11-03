from __future__ import annotations

from typing import Any

from mcp.server.mcpserver.exceptions import ToolError

from ..client import AetherClient
from .utils import local_file

PRIVATE = {"is_private": "true", "is_private_report": "true"}
MAX_FILE_BYTES = 100 * 1024 * 1024


# Upload the file as a private scan; Aether answers with its flow_id.
async def scan_file(client: AetherClient, path: str) -> dict[str, Any]:
    file = local_file(path)
    if file.stat().st_size > MAX_FILE_BYTES:
        raise ToolError(f"File too large (max 100 MB): {path}.")
    data = await client.request("POST", "/api/scan/file", data=PRIVATE, files={"file": (file.name, file.read_bytes())},
                                timeout=120)  # uploads can be slow
    return {"flow_id": data.get("flow_id")}  # the rest (queue priority) is of no use to the LLM


# Submit the URL as a private scan; Aether answers with its flow_id.
async def scan_url(client: AetherClient, url: str) -> dict[str, Any]:
    data = await client.request("POST", "/api/scan/url", data={"url": url, **PRIVATE})
    return {"flow_id": data.get("flow_id")}  # the rest (queue priority) is of no use to the LLM
