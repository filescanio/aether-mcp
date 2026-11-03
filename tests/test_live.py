import os

import pytest

from aether_mcp.client import AetherClient
from aether_mcp.tools import lookup, report, search

# Real Aether calls, read-only; run with AETHER_API_KEY set. Checks response shapes, not values (they change).
pytestmark = [pytest.mark.anyio, pytest.mark.skipif(not os.environ.get("AETHER_API_KEY"), reason="AETHER_API_KEY not set")]

SAMPLE = "90ac4de574d5525513587d66cfe793d8b8999834bf5654cc1976b6b85ddde7ef"  # MetaStealer, with a malware config


# The newest sandbox report of SAMPLE.
async def newest_report(client):
    reports = (await lookup.lookup_hash(client, [SAMPLE]))["results"][0]["sandbox_reports"]
    assert reports
    return reports[0]


async def test_lookup_hash():
    result = (await lookup.lookup_hash(AetherClient(), [SAMPLE]))["results"][0]
    assert result["verdict"] == "malicious"
    assert result["sandbox_reports"][0].keys() == {"report_id", "flow_id", "date", "verdict"}


async def test_resolve_family():
    families = (await search.resolve_family(AetherClient()))["families"]
    assert families and all(isinstance(f, str) for f in families)


async def test_pivot_ioc():
    result = await search.pivot_ioc(AetherClient(), sha256=SAMPLE)
    assert result["count"] >= 1
    assert result["items"][0]["file"]["sha256"] == SAMPLE


async def test_get_scan_result():
    client = AetherClient()
    result = await report.get_scan_result(client, (await newest_report(client))["flow_id"], wait_seconds=0)
    assert result["finished"] and result["verdict"] == "malicious" and result["has_config"]
    assert result["file"]["sha256"] == SAMPLE


async def test_get_iocs():
    client = AetherClient()
    assert await report.get_iocs(client, (await newest_report(client))["report_id"], SAMPLE)


async def test_get_malware_config():
    client = AetherClient()
    assert (await report.get_malware_config(client, [((await newest_report(client))["report_id"], SAMPLE)]))["results"][0]["configs"]


async def test_get_mitre_techniques():
    client = AetherClient()
    assert (await report.get_mitre_techniques(client, (await newest_report(client))["report_id"], SAMPLE))["tactics"]


async def test_search_by_yara_rule():
    assert (await search.search(AetherClient(), yara_rule="win_remcos"))["count"] >= 1


async def test_get_threat_attribution():
    client = AetherClient()
    files = (await report.get_threat_attribution(client, (await newest_report(client))["report_id"], SAMPLE))["files"]
    assert files[0]["attributions"][0]["family"] == "metastealer"


async def test_get_extracted_files():
    client = AetherClient()
    assert (await report.get_extracted_files(client, (await newest_report(client))["report_id"], SAMPLE))["files"]


async def test_get_yara_rule():
    assert (await search.get_yara_rule(AetherClient(), "win_remcos"))["rules"][0]["content"].startswith("rule win_remcos")
