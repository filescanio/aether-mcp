from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from ..client import AetherClient
from .utils import local_file

LATEST_REPORTS = 3


# Aether's reputation for file SHA-256s.
async def lookup_hash(client: AetherClient, sha256s: list[str]) -> dict[str, Any]:
    return await _lookup_many(client, "hash", sha256s)


# Hash a local file (SHA-256) and look that hash up; the file is never uploaded. The hash is returned too.
async def lookup_file(client: AetherClient, path: str) -> dict[str, Any]:
    file = local_file(path)
    digest = hashlib.sha256()
    with file.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):  # in chunks: the file can be large
            digest.update(chunk)
    sha256 = digest.hexdigest()
    return {"sha256": sha256, **_slim_lookup(await client.request("GET", "/api/reputation/hash", params={"sha256": sha256}))}


# Aether's reputation for IP addresses.
async def lookup_ip(client: AetherClient, ips: list[str]) -> dict[str, Any]:
    return await _lookup_many(client, "ip", ips)


# Aether's reputation for domains.
async def lookup_domain(client: AetherClient, domains: list[str]) -> dict[str, Any]:
    return await _lookup_many(client, "domain", domains)


# Aether's reputation for URLs.
async def lookup_url(client: AetherClient, urls: list[str]) -> dict[str, Any]:
    return await _lookup_many(client, "url", urls)


# ---------- helpers ----------

# Aether's reputation for many values of one type (hash, ip, domain or url) in one call, as {"results": [...]}.
async def _lookup_many(client: AetherClient, kind: str, values: list[str]) -> dict[str, Any]:
    data = await client.request("POST", f"/api/reputation/{kind}", json=values)
    return {"results": [{"value": d.get("sha256") or d.get("ioc_value"), **_slim_lookup(d)} for d in data or []]}


# Verdict, MD Cloud detections (total only for hashes: AV engines) and recent sandbox reports.
def _slim_lookup(data: dict[str, Any]) -> dict[str, Any]:
    md = data.get("mdcloud") or {}
    mdcloud = {"detected": md.get("detected_av_engines", md.get("detected")), "total": md.get("total_av_engines"),
               "scan_date": (md.get("scan_time") or "")[:10] or None}
    return {"verdict": data.get("overall_verdict"),
            "mdcloud": {k: v for k, v in mdcloud.items() if v is not None} if md else None,
            "sandbox_reports": _sandbox_reports(data)}


# The newest LATEST_REPORTS (Aether's list is capped at ~500, sorted by date text, and can be stale for URLs).
def _sandbox_reports(data: dict[str, Any]) -> list[dict[str, Any]]:
    reports = sorted(data.get("filescan_reports") or [], key=lambda r: _date(r.get("report_date")), reverse=True)
    return [{"report_id": r.get("report_id"), "flow_id": r.get("flow_id"), "date": _date(r.get("report_date"))[:10],
             "verdict": r.get("verdict")} for r in reports[:LATEST_REPORTS]]


# Aether's "MM/DD/YYYY, HH:MM:SS" as a sortable ISO string ("" if missing or malformed).
def _date(value: str | None) -> str:
    try:
        return datetime.strptime(value or "", "%m/%d/%Y, %H:%M:%S").isoformat()
    except ValueError:
        return ""
