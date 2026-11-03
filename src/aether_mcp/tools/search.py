from __future__ import annotations

import hashlib
from typing import Any

from ..client import AetherClient
from .report import unique_tags
from .utils import bounded

PAGE_SIZE = 5  # a few reports per page: `count` gives the total, `page` gives more
YARA_RULE_CHARS = 5000  # YARA rules are longer than the default cut


# The malware family names Aether attributes.
async def resolve_family(client: AetherClient) -> dict[str, Any]:
    data = await client.request("GET", "/api/reports/threat-attribution-options", params={"limit": 100})
    return {"families": data.get("tags")}


# The supported file types and file type groups (the rest of Aether's system config is not for the LLM).
async def resolve_file_type(client: AetherClient) -> dict[str, Any]:
    config = await client.request("GET", "/api/system/config")
    return {"supportedTypes": config.get("supportedTypes"), "fileGeneralTypes": config.get("fileGeneralTypes")}


# The MITRE ATT&CK technique IDs and names Aether maps to, matching the query (descriptions dropped: ~600 KB).
async def resolve_technique(client: AetherClient, query: list[str] | None = None) -> dict[str, str]:
    data = await client.request("GET", "/api/system/mitre")
    return _matching({tid: t["name"] for tactic in data.values() for tid, t in tactic["techniques"].items()}, query)


# Aether's signal group IDs (sandbox indicators) with their title, matching the query.
async def resolve_signal_group(client: AetherClient, query: list[str] | None = None) -> dict[str, str]:
    data = await client.request("GET", "/api/system/signal-groups")
    return _matching({g["id"]: g["description"] for section in data for g in section["groups"]}, query)


# The source of the YARA rule with this exact name (any case); empty if Aether has none.
async def get_yara_rule(client: AetherClient, name: str) -> dict[str, Any]:
    data = await client.request("GET", "/api/system/yara", params={"name": name})
    return bounded({"rules": [{"name": r.get("name"), "content": r.get("content")} for r in data or []]}, YARA_RULE_CHARS)


# Search Aether reports with the advanced-search filters, 5 files per page (newest report of each).
async def search(client: AetherClient, **filters: Any) -> dict[str, Any]:
    data = await client.request("GET", "/api/reports/advanced-search", params={**filters, "page_size": PAGE_SIZE, "unique_files": "true"})
    return bounded(_slim_search(data))


# The Aether reports that contain an IP, domain, URL, email or file SHA-256, 5 files per page (newest report of each).
async def pivot_ioc(client: AetherClient, **iocs: Any) -> dict[str, Any]:
    data = await client.request("GET", "/api/reports/advanced-search", params={**iocs, "page_size": PAGE_SIZE, "unique_files": "true"})
    return bounded(_slim_search(data))


# Samples with similar code (MetaDefender Cloud similarity search).
async def find_similar(client: AetherClient, sha256: str, min_similarity: int) -> dict[str, Any]:
    data = await client.request("GET", "/api/similarity-search/similarity",
                                params={"hash": sha256, "min_similarity": min_similarity})
    return bounded(_slim_find_similar(data))


# How many recent Aether reports each IOC appears in, by report verdict.
async def get_ioc_prevalence(client: AetherClient, **iocs: list[str] | None) -> dict[str, Any]:
    iocs = {k: v for k, v in iocs.items() if v}
    data = await client.request("POST", "/api/threatintel/get-prevalence", json=iocs)
    return _slim_ioc_prevalence(data, iocs.get("url") or [])


# ---------- helpers ----------

# Entries whose ID or text contains any of the keywords (case-insensitive); all if none given.
def _matching(entries: dict[str, str], keywords: list[str] | None) -> dict[str, str]:
    words = [w.lower() for w in keywords or [] if w.strip()]
    return {k: v for k, v in entries.items() if not words or any(w in f"{k} {v}".lower() for w in words)}


# Report count and per file (newest report only, rescans dropped): IDs, file, verdict, date and unique tags.
def _slim_search(data: dict[str, Any]) -> dict[str, Any]:
    newest: dict[str | None, dict[str, Any]] = {}
    for i in data.get("items") or []:  # newest first, so the first report of each file is kept
        newest.setdefault((i.get("file") or {}).get("sha256"), i)
    items = [{"report_id": item.get("id"), "flow_id": (item.get("scan_init") or {}).get("id"),
              "file": {"name": (item.get("file") or {}).get("name"), "sha256": (item.get("file") or {}).get("sha256"),
                       "type": (item.get("file") or {}).get("short_type")},
              "verdict": item.get("verdict"), "date": (item.get("date") or "")[:10],
              "tags": unique_tags(item.get("tags"))}
             for item in newest.values()]
    return {"count": data.get("count"), "items": items}


# Only the per-verdict counts (Aether also lists every report); URLs keyed back from Aether's MD5 to the URL.
def _slim_ioc_prevalence(data: dict[str, Any], urls: list[str]) -> dict[str, Any]:
    url_by_md5 = {hashlib.md5(u.encode()).hexdigest(): u for u in urls}
    return {kind: {url_by_md5.get(value, value): entry.get("counts") for value, entry in values.items()}
            for kind, values in data.items()}


# The most similar and the most recent similar files, once each, most similar first: SHA-256, similarity %, verdict,
# first seen and tags (to spot a wrong match); the per-dimension scores and file details are dropped.
def _slim_find_similar(data: dict[str, Any]) -> dict[str, Any]:
    files = {x.get("sha256"): x for x in (data.get("most_similar") or []) + (data.get("most_recent") or [])}.values()
    return {"similar": [{"sha256": x.get("sha256"), "similarity": round((x.get("overall_similarity") or 0) * 100),
                         "verdict": (x.get("details") or {}).get("verdict"),
                         "first_seen": ((x.get("details") or {}).get("start_date") or "")[:10],
                         "tags": (x.get("details") or {}).get("tags")}
                        for x in sorted(files, key=lambda x: -(x.get("overall_similarity") or 0))]}
