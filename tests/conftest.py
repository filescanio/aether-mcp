import httpx
import pytest

from aether_mcp.client import AetherClient


# Run async tests on asyncio.
@pytest.fixture
def anyio_backend():
    return "asyncio"


# An AetherClient that answers every request with `json` instead of calling Aether; requests sent are in client.sent.
@pytest.fixture
def fake_aether(monkeypatch):
    monkeypatch.setenv("AETHER_API_KEY", "test-key")
    monkeypatch.delenv("AETHER_BASE_URL", raising=False)

    def make(json, status=200):
        client = AetherClient()
        client.sent = []

        def handler(request):
            client.sent.append(request)
            return httpx.Response(status, json=json)

        client._http = httpx.AsyncClient(base_url=client.base_url, transport=httpx.MockTransport(handler))
        return client
    return make
