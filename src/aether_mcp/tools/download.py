from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any, BinaryIO

from mcp.server.mcpserver.exceptions import ToolError

from ..client import AetherClient

ZIP_PASSWORD = "infected"  # the usual password for malware archives
DOWNLOAD_TIMEOUT = 300  # big samples can be slow
MAX_DOWNLOAD_BYTES = 500 * 1024 * 1024
NOT_PROTECTED = "Aether did not return a password-protected ZIP; nothing was saved."


# Save a sample as Aether serves it, a password-protected ZIP, to AETHER_DOWNLOAD_DIR; the LLM only gets its path.
# It is streamed to disk, never held in memory.
async def download_file(client: AetherClient, sha256: str) -> dict[str, Any]:
    folder = _download_dir(client)
    target = folder / f"{sha256.lower()}.zip"  # never the original name: it is part of the lure (invoice.pdf.exe)
    if target.exists():
        raise ToolError(f"Already downloaded: {target}.")
    writer = _ZipWriter(target)
    try:
        await client.request("GET", f"/api/files/{sha256.lower()}", params={"type": "raw", "password": ZIP_PASSWORD},
                             timeout=DOWNLOAD_TIMEOUT, sink=writer.write)
        writer.close()
        if writer.file is None or not _is_encrypted_zip(target):
            raise ToolError(NOT_PROTECTED)
    except BaseException as exc:
        writer.discard()  # never leave a partial or unprotected file behind
        if isinstance(exc, FileExistsError):
            raise ToolError(f"Already downloaded: {target}.") from None
        if isinstance(exc, OSError):
            raise ToolError(f"Could not save to {target}: {exc.strerror}.") from None
        raise
    return {"path": str(target), "password": ZIP_PASSWORD, "size": writer.size}


# The folder the user chose for downloads; refused when downloads are off or the folder is not set up.
def _download_dir(client: AetherClient) -> Path:
    if not client.allow_downloads:
        raise ToolError("Downloads are off. The user can turn them on with AETHER_ALLOW_DOWNLOADS=true.")
    if not client.download_dir:
        raise ToolError("AETHER_DOWNLOAD_DIR is not set. The user must set it to the folder for downloaded samples.")
    folder = Path(client.download_dir).expanduser()
    if not folder.is_absolute():  # a relative path would depend on where the MCP client starts the server
        raise ToolError(f"AETHER_DOWNLOAD_DIR must be an absolute path: {client.download_dir}.")
    folder = folder.resolve()
    if any(part.startswith(".") for part in folder.parts):
        raise ToolError(f"AETHER_DOWNLOAD_DIR can't be a hidden folder: {client.download_dir}.")
    if not folder.is_dir():
        raise ToolError(f"AETHER_DOWNLOAD_DIR is not an existing folder: {client.download_dir}.")
    return folder


# Writes the download to `target` chunk by chunk. Nothing is written until the first ZIP entry header shows an
# encrypted entry, so a sample served in the clear never touches the disk; the size is capped.
class _ZipWriter:
    def __init__(self, target: Path) -> None:
        self.target = target
        self.file: BinaryIO | None = None
        self.head = b""
        self.size = 0

    def write(self, chunk: bytes) -> None:
        self.size += len(chunk)
        if self.size > MAX_DOWNLOAD_BYTES:
            raise ToolError(f"File too large to download (max {MAX_DOWNLOAD_BYTES // (1024 * 1024)} MB).")
        if self.file is None:
            self.head += chunk
            if len(self.head) < 8:  # local file header: signature (4), version (2), flags (2)
                return
            if not (self.head.startswith(b"PK\x03\x04") and self.head[6] & 0x1):
                raise ToolError(NOT_PROTECTED)
            self.file = self.target.open("xb")  # x: never overwrite a file
            chunk, self.head = self.head, b""
        self.file.write(chunk)

    def close(self) -> None:
        if self.file is not None:
            self.file.close()

    # Close and delete what was written; only a file this writer created.
    def discard(self) -> None:
        if self.file is not None:
            self.file.close()
            self.target.unlink(missing_ok=True)


# True if the ZIP at `path` has entries and every one is encrypted.
def _is_encrypted_zip(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
    except zipfile.BadZipFile:
        return False
    return bool(entries) and all(e.flag_bits & 0x1 for e in entries)
