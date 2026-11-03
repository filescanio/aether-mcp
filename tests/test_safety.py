import httpx
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from aether_mcp import server
from aether_mcp.client import AetherClient
from aether_mcp.tools import scan
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


# Scans are always private.
async def test_scan_url_is_private(fake_aether):
    client = fake_aether({"flow_id": "f" * 24, "priority": 1})
    assert await scan.scan_url(client, "https://example.com") == {"flow_id": "f" * 24}
    assert b"is_private=true" in client.sent[0].read()
    assert b"is_private_report=true" in client.sent[0].read()


async def test_scan_file_is_private(fake_aether, tmp_path):
    file = tmp_path / "sample.txt"
    file.write_text("hello")
    client = fake_aether({"flow_id": "f" * 24})
    assert await scan.scan_file(client, str(file)) == {"flow_id": "f" * 24}
    assert b'name="is_private"\r\n\r\ntrue' in client.sent[0].read()
    assert b'name="is_private_report"\r\n\r\ntrue' in client.sent[0].read()


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
