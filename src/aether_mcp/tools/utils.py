from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp.server.mcpserver.exceptions import ToolError

MAX_CHARS = 1000
MAX_ITEMS = 100


# A local file to read; hidden files and folders (.ssh, .aws, .env, ...) are refused: they often hold secrets.
def local_file(path: str) -> Path:
    file = Path(path).expanduser().resolve()
    if any(part.startswith(".") for part in file.parts):
        raise ToolError(f"Hidden files and folders are not allowed: {path}.")
    if not file.is_file():
        raise ToolError(f"No file at {path}.")
    return file


# Cut long strings and lists at any depth: reports hold text written by malware authors.
def bounded(data: Any, max_chars: int = MAX_CHARS, max_items: int = MAX_ITEMS) -> Any:
    if isinstance(data, str):
        return data[:max_chars] + "..." if len(data) > max_chars else data
    if isinstance(data, list):
        more = [f"... {len(data) - max_items} more"] if len(data) > max_items else []
        return [bounded(v, max_chars, max_items) for v in data[:max_items]] + more
    if isinstance(data, dict):
        return {k: bounded(v, max_chars, max_items) for k, v in data.items()}
    return data
