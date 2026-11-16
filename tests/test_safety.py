import io
import os
import subprocess
import sys
import zipfile

import httpx
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from aether_mcp import server
from aether_mcp.client import AetherClient
from aether_mcp.tools import download, scan
from aether_mcp.tools.utils import MAX_CHARS, MAX_ITEMS, bounded, local_file

pytestmark = pytest.mark.anyio

SHA256 = "a" * 64


# Only allowlisted endpoints are called.
async def test_endpoint_not_allowed(fake_aether):
    client = fake_aether({})
    with pytest.raises(ToolError, match="Endpoint not allowed"):
        await client.request("GET", "/api/users/me")
    assert client.sent == []


# The API key is masked in Aether's error text.
async def test_key_masked_in_errors(fake_aether):
    client = fake_aether({"detail": "invalid key test-key"}, status=401)
    with pytest.raises(ToolError, match=r"\*\*\*") as error:
        await client.request("GET", "/api/system/config")
    assert "test-key" not in str(error.value)


# Slow or failing searches tell the LLM how to recover: narrow the search.
async def test_search_error_hint(fake_aether):
    def timeout(request):
        raise httpx.ReadTimeout("slow", request=request)
    with pytest.raises(ToolError, match="add date_from and date_to"):
        await fake_aether({"detail": "boom"}, status=504).request("GET", "/api/reports/advanced-search")
    client = fake_aether({})
    client._http = httpx.AsyncClient(base_url=client.base_url, transport=httpx.MockTransport(timeout))
    with pytest.raises(ToolError, match="timed out. Narrow the search"):
        await client.request("GET", "/api/reports/advanced-search")


# Fields about Aether users never reach the LLM.
async def test_user_fields_dropped(fake_aether):
    client = fake_aether({"items": [{"id": 1, "uploader": {"email": "user@example.com"}, "userId": 7}]})
    assert await client.request("GET", "/api/system/config") == {"items": [{"id": 1}]}


async def test_missing_api_key(monkeypatch):
    monkeypatch.delenv("AETHER_API_KEY", raising=False)
    with pytest.raises(ToolError, match="AETHER_API_KEY is not set"):
        await AetherClient().request("GET", "/api/system/config")


# The API key is never sent over plain HTTP.
async def test_http_base_url_refused(fake_aether, monkeypatch):
    monkeypatch.setenv("AETHER_BASE_URL", "http://www.filescan.io")
    client = fake_aether({})
    with pytest.raises(ToolError, match="https://"):
        await client.request("GET", "/api/system/config")
    assert client.sent == []


# Scans are public unless AETHER_PRIVATE_SCANS is set.
async def test_scan_url_is_public_by_default(fake_aether, monkeypatch):
    monkeypatch.delenv("AETHER_PRIVATE_SCANS", raising=False)
    client = fake_aether({"flow_id": "f" * 24, "priority": 1})
    assert await scan.scan_url(client, "https://example.com") == {"flow_id": "f" * 24}
    assert b"is_private=false" in client.sent[0].read()
    assert b"is_private_report=false" in client.sent[0].read()


async def test_scan_file_is_public_by_default(fake_aether, monkeypatch, tmp_path):
    monkeypatch.delenv("AETHER_PRIVATE_SCANS", raising=False)
    file = tmp_path / "sample.txt"
    file.write_text("hello")
    client = fake_aether({"flow_id": "f" * 24})
    assert await scan.scan_file(client, str(file)) == {"flow_id": "f" * 24}
    assert b'name="is_private"\r\n\r\nfalse' in client.sent[0].read()
    assert b'name="is_private_report"\r\n\r\nfalse' in client.sent[0].read()


@pytest.mark.parametrize("value", ["true", "1", "yes", "TRUE"])
async def test_scan_url_private_setting(fake_aether, monkeypatch, value):
    monkeypatch.setenv("AETHER_PRIVATE_SCANS", value)
    client = fake_aether({"flow_id": "f" * 24})
    await scan.scan_url(client, "https://example.com")
    assert b"is_private=true" in client.sent[0].read()
    assert b"is_private_report=true" in client.sent[0].read()


async def test_scan_file_private_setting(fake_aether, monkeypatch, tmp_path):
    monkeypatch.setenv("AETHER_PRIVATE_SCANS", "true")
    file = tmp_path / "sample.txt"
    file.write_text("hello")
    client = fake_aether({"flow_id": "f" * 24})
    await scan.scan_file(client, str(file))
    assert b'name="is_private"\r\n\r\ntrue' in client.sent[0].read()
    assert b'name="is_private_report"\r\n\r\ntrue' in client.sent[0].read()


# Off values (Claude Desktop sends "false" for an unchecked box) keep scans public.
@pytest.mark.parametrize("value", ["false", "0", "", "no"])
async def test_scan_private_setting_off(fake_aether, monkeypatch, value):
    monkeypatch.setenv("AETHER_PRIVATE_SCANS", value)
    client = fake_aether({"flow_id": "f" * 24})
    await scan.scan_url(client, "https://example.com")
    assert b"is_private=false" in client.sent[0].read()


# The scan tool descriptions tell the LLM whether scans are public or private.
def test_scan_descriptions_match_setting():
    expected = "private scan" if server.client.private_scans else "public scan"
    assert expected in server.SCAN_FILE_WHAT
    assert expected in server.SCAN_URL_WHAT


async def test_scan_file_too_large(fake_aether, tmp_path):
    file = tmp_path / "big.bin"
    with file.open("wb") as f:
        f.truncate(scan.MAX_FILE_BYTES + 1)
    client = fake_aether({})
    with pytest.raises(ToolError, match="too large"):
        await scan.scan_file(client, str(file))
    assert client.sent == []


# Hidden files and folders are refused, also through a symlink.
def test_hidden_paths_refused(tmp_path):
    secret = tmp_path / ".ssh" / "id_rsa"
    secret.parent.mkdir()
    secret.write_text("key")
    link = tmp_path / "link.txt"
    link.symlink_to(secret)
    for path in [secret, link, tmp_path / ".env"]:
        with pytest.raises(ToolError, match="Hidden"):
            local_file(str(path))


def test_missing_file(tmp_path):
    with pytest.raises(ToolError, match="No file"):
        local_file(str(tmp_path / "missing.txt"))


def test_bounded():
    data = {"text": "x" * (MAX_CHARS + 1), "list": list(range(MAX_ITEMS + 2)), "nested": [{"n": 1}]}
    assert bounded(data) == {"text": "x" * MAX_CHARS + "...", "list": list(range(MAX_ITEMS)) + ["... 2 more"],
                             "nested": [{"n": 1}]}


# Malformed IDs, hashes and dates are refused before any call to Aether.
@pytest.mark.parametrize("tool, args", [
    ("lookup_hash", {"sha256s": ["abc"]}),
    ("get_scan_result", {"flow_id": "../x"}),
    ("get_iocs", {"report_id": "../../x", "sha256": SHA256}),
    ("search", {"date_from": "yesterday"}),
])
async def test_bad_input_refused(tool, args):
    with pytest.raises(ToolError, match="should match pattern"):
        await server.mcp.call_tool(tool, args)


# ---------- download ----------

# A ZIP with one entry per flag; stdlib can't write encrypted ZIPs, so the "encrypted" bit is set in the headers.
def _zip(*encrypted: bool) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        for i in range(len(encrypted)):
            z.writestr(f"sample{i}", b"MZ" * 100)
    data = bytearray(buffer.getvalue())
    for signature, offset in [(b"PK\x03\x04", 6), (b"PK\x01\x02", 8)]:  # local and central headers
        at = -1
        for flag in encrypted:
            at = data.index(signature, at + 1)
            data[at + offset] |= flag
    return bytes(data)


# An AetherClient that downloads `content`, with downloads set up to save in `folder`.
@pytest.fixture
def fake_download(fake_aether, monkeypatch, tmp_path):
    def make(content, allow="true", folder=None, chunk=None):
        monkeypatch.setenv("AETHER_ALLOW_DOWNLOADS", allow)
        monkeypatch.setenv("AETHER_DOWNLOAD_DIR", str(tmp_path if folder is None else folder))
        client = fake_aether({})

        async def chunks():  # the body as a stream, in `chunk`-byte pieces
            for i in range(0, len(content), chunk or len(content) or 1):
                yield content[i:i + (chunk or len(content) or 1)]

        def handler(request):
            client.sent.append(request)
            return httpx.Response(200, content=chunks(), headers={"content-type": "application/octet-stream"})
        client._http = httpx.AsyncClient(base_url=client.base_url, transport=httpx.MockTransport(handler))
        return client
    return make


# The sample is saved as Aether's password-protected ZIP, named by hash; the LLM gets its path, never its content.
# It is streamed to disk: tiny chunks split even the ZIP header.
@pytest.mark.parametrize("chunk", [None, 3])
async def test_download_saves_encrypted_zip(fake_download, tmp_path, chunk):
    content = _zip(True)
    client = fake_download(content, chunk=chunk)
    result = await download.download_file(client, SHA256)
    target = tmp_path / f"{SHA256}.zip"
    assert result == {"path": str(target), "password": "infected", "size": len(content)}
    assert target.read_bytes() == content
    assert client.sent[0].url.path == f"/api/files/{SHA256}"
    assert dict(client.sent[0].url.params) == {"type": "raw", "password": "infected"}


# Downloads are off by default: nothing is called or saved.
@pytest.mark.parametrize("allow", ["", "false", "0"])
async def test_download_off_by_default(fake_download, tmp_path, allow):
    client = fake_download(_zip(True), allow=allow)
    with pytest.raises(ToolError, match="Downloads are off"):
        await download.download_file(client, SHA256)
    assert client.sent == [] and list(tmp_path.iterdir()) == []


# Downloads need AETHER_DOWNLOAD_DIR: an existing, non-hidden folder.
@pytest.mark.parametrize("folder, error", [("", "not set"), ("missing", "not an existing folder"),
                                           (".hidden", "hidden folder"), ("relative", "absolute path")])
async def test_download_dir_required(fake_download, tmp_path, monkeypatch, folder, error):
    (tmp_path / ".hidden").mkdir()
    (tmp_path / "relative").mkdir()
    monkeypatch.chdir(tmp_path)  # "relative" exists in the working directory, but is still refused
    path = {"": "", "relative": "relative"}.get(folder, str(tmp_path / folder))
    client = fake_download(_zip(True), folder=path)
    with pytest.raises(ToolError, match=error):
        await download.download_file(client, SHA256)
    assert client.sent == []


# Anything but an encrypted ZIP is never left on disk: a plain ZIP, the raw file, an empty or tiny body, or a ZIP
# whose first entry is encrypted but a later one is not (caught at the end, then deleted).
@pytest.mark.parametrize("content", [_zip(False), b"MZ\x90\x00 raw sample", b"", b"PK", _zip(True, False)])
async def test_download_refuses_unprotected_file(fake_download, tmp_path, content):
    client = fake_download(content)
    with pytest.raises(ToolError, match="password-protected ZIP"):
        await download.download_file(client, SHA256)
    assert list(tmp_path.iterdir()) == []


# Downloads are capped, and the part already written is deleted.
async def test_download_too_large(fake_download, tmp_path, monkeypatch):
    monkeypatch.setattr(download, "MAX_DOWNLOAD_BYTES", 100)
    client = fake_download(_zip(True), chunk=40)
    with pytest.raises(ToolError, match="too large"):
        await download.download_file(client, SHA256)
    assert list(tmp_path.iterdir()) == []


# An existing file is never overwritten.
async def test_download_never_overwrites(fake_download, tmp_path):
    (tmp_path / f"{SHA256}.zip").write_bytes(b"keep")
    client = fake_download(_zip(True))
    with pytest.raises(ToolError, match="Already downloaded"):
        await download.download_file(client, SHA256)
    assert client.sent == [] and (tmp_path / f"{SHA256}.zip").read_bytes() == b"keep"


# The download tool is only listed when the user turned downloads on.
@pytest.mark.parametrize("allow, listed", [("", False), ("true", True)])
def test_download_tool_listed_only_when_on(allow, listed):
    code = "from aether_mcp import server; print(hasattr(server, 'download_file'))"
    env = {**os.environ, "AETHER_ALLOW_DOWNLOADS": allow}
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True).stdout
    assert out.strip() == str(listed)
