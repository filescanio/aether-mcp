from __future__ import annotations

import os
import re
from typing import Any

import httpx
from mcp.server.mcpserver.exceptions import ToolError

# The only endpoints this server may call
ALLOWED_PATHS = [
    r"/api/scan/(file|url)",
    r"/api/scan/[0-9a-f]{24}/report",
    r"/api/reputation/(hash|ip|domain|url)",
    r"/api/reports/(advanced-search|threat-attribution-options)",
    r"/api/reports/[0-9a-f-]{36}/[0-9a-f]{64}",
    r"/api/system/(config|mitre|signal-groups|yara)",
    r"/api/similarity-search/similarity",
    r"/api/threatintel/get-prevalence",
]
# Fields about Aether users (e.g. uploader email) that must never reach the LLM
USER_FIELDS = {"uploader", "userId"}
# Hint added to search errors, so the LLM knows how to recover
SEARCH_HINT = " Narrow the search: add date_from and date_to, or more filters."


# HTTP client for Aether: API key, endpoint allowlist, short errors.
class AetherClient:
    # Set up the HTTP session; the API key is read per request so the server starts without it.
    def __init__(self) -> None:
        self.base_url = os.environ.get("AETHER_BASE_URL", "https://www.filescan.io").rstrip("/")
        self._http = httpx.AsyncClient(base_url=self.base_url)

    # Send one request to an allowlisted endpoint and return its JSON (or text); failures become tool errors.
    async def request(self, method: str, path: str, params: dict[str, Any] | None = None, data: dict[str, Any] | None = None,
                      files: dict[str, Any] | None = None, json: Any = None, timeout: float = 60) -> Any:
        api_key = os.environ.get("AETHER_API_KEY")
        if not api_key:
            raise ToolError("AETHER_API_KEY is not set.")
        if not self.base_url.startswith("https://"):
            raise ToolError("AETHER_BASE_URL must start with https://.")
        if not any(re.fullmatch(p, path, re.IGNORECASE) for p in ALLOWED_PATHS):
            raise ToolError(f"Endpoint not allowed: {path}")
        params = {k: v for k, v in (params or {}).items() if v is not None}
        hint = SEARCH_HINT if path == "/api/reports/advanced-search" else ""  # how to recover from a slow search
        try:
            resp = await self._http.request(method, path, params=params, data=data, files=files, json=json,
                                            headers={"X-Api-Key": api_key}, timeout=timeout)
        except httpx.TimeoutException:
            raise ToolError("Aether timed out." + hint) from None
        except httpx.HTTPError as exc:
            raise ToolError(f"Could not reach Aether ({type(exc).__name__}).") from None
        if resp.status_code >= 400:
            raise ToolError(f"Aether returned HTTP {resp.status_code}: {resp.text[:300].replace(api_key, '***')}"
                            f"{hint if resp.status_code >= 500 else ''}")
        return _drop_user_fields(resp.json()) if "json" in resp.headers.get("content-type", "") else resp.text


# Remove USER_FIELDS at any depth of a JSON response.
def _drop_user_fields(data: Any) -> Any:
    if isinstance(data, dict):
        return {k: _drop_user_fields(v) for k, v in data.items() if k not in USER_FIELDS}
    if isinstance(data, list):
        return [_drop_user_fields(v) for v in data]
    return data
