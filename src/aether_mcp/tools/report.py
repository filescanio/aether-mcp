from __future__ import annotations

import asyncio
import base64
import json
import time
from typing import Any

from mcp.server.mcpserver import Image
from mcp.server.mcpserver.exceptions import ToolError

from ..client import AetherClient
from .utils import bounded

REPORT_FILTERS = ["overallState", "finalVerdict", "allTags", "f:submitName", "f:mediaType", "f:digests"]
PENDING_STATES = {"in_queue", "in_progress"}
POLL_SECONDS = 5
EVIDENCE_PER_GROUP = 3
EVIDENCE_CHARS = 300
VERDICTS = ["NO_THREAT", "SUSPICIOUS", "LIKELY_MALICIOUS", "MALICIOUS"]  # lowest to highest
# IOC type of each IOC field of a file; the report's iocs leave out those found in extracted files.
IOC_FIELDS = {"extractedUrls": "url", "extractedDomains": "domain", "extractedIPs": "ip", "extractedEmails": "email",
              "extractedHashesMD5": "md5", "extractedHashesSHA1": "sha1", "extractedHashesSHA256": "sha256",
              "extractedHashesSHA512": "sha512", "extractedUUIDs": "uuid", "extractedRegistryPathways": "registry_path",
              "extractedRevisionSaveIDs": "revision_save_id", "extractedBTCWallets": "btc_wallet",
              "extractedETHWallets": "eth_wallet", "extractedXMRWallets": "xmr_wallet", "extractedUNCPaths": "unc_path",
              "extractedUncategorizedResources": "uncategorized"}
# IOCs are listed best origin first.
# Rank 0: malware config, 1: emulated (any *_EMULATION) or decoded from the sample, 3: content of websites it
# touched; others: 2.
IOC_ORIGIN_RANK = {"MALWARE_CONFIG": 0,
                   "IMAGE_QR_CODE": 1, "DOTNET_DECOMPILATION": 1, "PCODE_PARSE": 1, "INSTALLER_EXTRACTION": 1, "EMAIL_BODY": 1,
                   "EXTRACTED_FILE": 3, "URL_REDIRECT": 3, "URL_RENDER": 3, "EXTERNAL_PARSER": 3}
# Name and hash of the input file, the files extracted from it (whole: Aether returns each nested filter as separate
# items, so their name and data can't be joined) and the files it downloaded; add the field to read, e.g. "f:emulationData".
FILE_FILTERS = ["f:submitName", "f:digests", "f:extractedFiles", "fd:fileDownloadResults"]
# Event fields left out: script and payload contents, and noise
EMULATION_EVENT_DROPPED = {"Data", "Code", "HeadOfDecryptedData", "Alias", "Comments", "Tid", "ModuleBase"}
EMULATION_EVENT_CHARS = 300
EMULATION_EVENT_ITEMS = 10
# Only these match verdicts are kept: most matches are generic (anti-debug, compilers, crypto constants)
YARA_VERDICTS = {"LIKELY_MALICIOUS", "MALICIOUS"}


# Scan result, polling until finished or wait_seconds pass; only {"finished": false} while it still runs.
async def get_scan_result(client: AetherClient, flow_id: str, wait_seconds: int,
                          signal_groups: bool = False) -> dict[str, Any]:
    deadline = time.monotonic() + wait_seconds
    while not (finished := _finished(await _scan_report(client, flow_id, ["overallState"]))):
        if time.monotonic() >= deadline:
            return {"finished": False}
        await asyncio.sleep(min(POLL_SECONDS, deadline - time.monotonic()))
    filters = REPORT_FILTERS + (["allSignalGroups"] if signal_groups else [])
    return bounded(_slim_scan_result(await _scan_report(client, flow_id, filters)))


# IOCs of a report, including those found in extracted files; only the given types, if any.
async def get_iocs(client: AetherClient, report_id: str, sha256: str, types: list[str] | None = None) -> dict[str, Any]:
    return bounded(_slim_iocs(await _report(client, report_id, sha256, ["iocs", "f:extractedFiles"]), types))


# Malware configs of several reports (report_id, sha256), fetched in parallel.
async def get_malware_config(client: AetherClient, reports: list[tuple[str, str]]) -> dict[str, Any]:
    return bounded({"results": await asyncio.gather(*(_malware_config(client, *r) for r in reports))})


# MITRE ATT&CK techniques of a report (Aether maps them per signal group).
async def get_mitre_techniques(client: AetherClient, report_id: str, sha256: str) -> dict[str, Any]:
    return _slim_mitre_techniques(await _report(client, report_id, sha256, ["finalVerdict", "allSignalGroups"]))


# Emulation events of every emulated file in a report.
async def get_emulation(client: AetherClient, report_id: str, sha256: str) -> dict[str, Any]:
    return bounded(_slim_emulation(await _report(client, report_id, sha256, FILE_FILTERS + ["f:emulationData"])))


# Files extracted from a report's file (unpacked, or dropped during emulation); only interesting ones if asked.
async def get_extracted_files(client: AetherClient, report_id: str, sha256: str,
                              only_interesting: bool = True) -> dict[str, Any]:
    return bounded(_slim_extracted_files(await _report(client, report_id, sha256, ["f:extractedFiles"]), only_interesting))


# Likely malicious and malicious YARA matches of any file of a report.
async def get_yara_matches(client: AetherClient, report_id: str, sha256: str) -> dict[str, Any]:
    return bounded(_slim_yara_matches(await _report(client, report_id, sha256, FILE_FILTERS + ["f:yaraMatches"])))


# Malware families Aether attributed to any file of a report, with the evidence for each.
async def get_threat_attribution(client: AetherClient, report_id: str, sha256: str) -> dict[str, Any]:
    return bounded(_slim_threat_attribution(await _report(client, report_id, sha256, FILE_FILTERS + ["f:threatAttribution"])))


# How Aether's browser rendered the URLs of a report, and a screenshot (PNG) of each render.
async def get_url_render(client: AetherClient, report_id: str, sha256: str) -> list[Any]:
    renders = [r for resource in ((await _report(client, report_id, sha256, ["ur:renderResults"])).get("resources") or {}).values()
               for r in resource.get("renderResults") or []]
    return [bounded(_slim_url_render(renders))] + [Image(data=base64.b64decode(r["base64"]), format="png")
                                                   for r in renders if r.get("base64")]


# ---------- helpers ----------

# Malware configs of one report, or its error (so the other reports still return).
async def _malware_config(client: AetherClient, report_id: str, sha256: str) -> dict[str, Any]:
    try:
        report = await _report(client, report_id, sha256, ["f:extendedData.malwareConfig"])
    except ToolError as error:
        return {"report_id": report_id, "sha256": sha256, "error": str(error)}
    return {"report_id": report_id, "sha256": sha256, **_slim_malware_config(report)}


# A scan's report by flow_id, as {report_id: report}; empty until queued.
async def _scan_report(client: AetherClient, flow_id: str, filters: list[str]) -> dict[str, Any]:
    data = await client.request("GET", f"/api/scan/{flow_id}/report", params={"filter": filters})
    return dict(list((data.get("reports") or {}).items())[:1])


# A report by report_id and file SHA-256.
async def _report(client: AetherClient, report_id: str, sha256: str, filters: list[str]) -> dict[str, Any]:
    data = await client.request("GET", f"/api/reports/{report_id}/{sha256}", params={"filter": filters})
    return next(iter((data.get("reports") or {}).values()), {})


# Whether the scan's report exists and is no longer queued or running.
def _finished(report: dict[str, Any]) -> bool:
    return any(r.get("overallState") not in PENDING_STATES for r in report.values())


# Report ID, verdict, file, has_config, unique tags and, if asked, signal groups.
def _slim_scan_result(report: dict[str, Any]) -> dict[str, Any]:
    report_id, data = next(iter(report.items()), (None, {}))
    verdict = (data.get("finalVerdict") or {}).get("verdict")
    file = next(iter((data.get("resources") or {}).values()), {})
    tags = unique_tags(data.get("allTags"))
    result = {"finished": True, "report_id": report_id, "verdict": (verdict or "").lower() or None,
              "file": {"name": file.get("submitName"), "type": (file.get("mediaType") or {}).get("string"),
                       "sha256": (file.get("digests") or {}).get("SHA-256")},
              "has_config": any(t.get("source") == "MWCFG" for t in data.get("allTags") or []),  # MWCFG tags are suppressed
              "tags": tags}
    if "allSignalGroups" in data:
        result["signal_groups"] = _slim_signal_groups(data["allSignalGroups"], verdict)
    return result


# Signal group verdicts worth keeping: the final verdict and one below, never NO_THREAT.
def _kept_verdicts(final_verdict: str | None) -> list[str]:
    final = VERDICTS.index(final_verdict) if final_verdict in VERDICTS else 0
    return VERDICTS[max(1, final - 1):]


# Kept groups, merged by ID, with a few short evidence strings.
def _slim_signal_groups(groups: list[dict[str, Any]], final_verdict: str | None) -> list[dict[str, Any]]:
    kept = _kept_verdicts(final_verdict)
    merged: dict[str, dict[str, Any]] = {}
    for g in groups:
        verdict = (g.get("verdict") or {}).get("verdict")
        if verdict not in kept:
            continue
        m = merged.setdefault(g.get("identifier"), {"id": g.get("identifier"), "title": g.get("description"),
                                                     "verdict": verdict, "evidence": []})
        m["verdict"] = max(m["verdict"], verdict, key=VERDICTS.index)
        m["evidence"] += [(s.get("signalReadable") or "")[:EVIDENCE_CHARS] for s in g.get("signals") or []]
    for m in merged.values():
        m["verdict"] = m["verdict"].lower()  # lowercase like the lookup and search tools
        m["evidence"] = list(dict.fromkeys(m["evidence"]))[:EVIDENCE_PER_GROUP]
    return list(merged.values())


# {type: [{value, source}]}, best origin first (IOC_ORIGIN_RANK); no verdicts (mostly UNKNOWN).
def _slim_iocs(report: dict[str, Any], types: list[str] | None) -> dict[str, Any]:
    found = [(kind, i.get("data"), o.get("type"))
             for kind, items in (report.get("iocs") or {}).items() for i in items for o in i.get("origins") or [{}]]
    found += [(kind, ref.get("data"), (group.get("origin") or {}).get("type"))
              for resource in (report.get("resources") or {}).values() for f in resource.get("extractedFiles") or []
              for field, kind in IOC_FIELDS.items() for group in f.get(field) or [] for ref in group.get("references") or []]
    iocs: dict[str, dict[str, dict[str, None]]] = {}
    for kind, value, source in found:
        if not types or kind in types:
            iocs.setdefault(kind, {}).setdefault(value, {})[source] = None
    return {kind: [{"value": value, "source": ", ".join(filter(None, sources))} for value, sources in sorted(
                values.items(), key=lambda v: min(IOC_ORIGIN_RANK.get(s, 1 if str(s).endswith("_EMULATION") else 2) for s in v[1]))]
            for kind, values in iocs.items()}


# {"configs": [...]} without string dumps or payload bytes; empty if none.
def _slim_malware_config(report: dict[str, Any]) -> dict[str, Any]:
    file = next(iter((report.get("resources") or {}).values()), {})
    configs = [{k: v for k, v in (c.get("data") or {}).items() if k not in {"decrypted_strings", "retrieved_strings"}}
               for c in (file.get("extendedData") or {}).get("malwareConfig") or []]
    for config in configs:
        if "payloads" in config:
            config["payloads"] = [{k: v for k, v in p.items() if k != "value"} for p in config["payloads"]]
    return {"configs": configs}


# Tactics > techniques from the kept signal groups, each with the groups that found it.
def _slim_mitre_techniques(report: dict[str, Any]) -> dict[str, Any]:
    kept = _kept_verdicts((report.get("finalVerdict") or {}).get("verdict"))
    tactics: dict[str, dict[str, dict[str, Any]]] = {}
    for g in report.get("allSignalGroups") or []:
        if (g.get("verdict") or {}).get("verdict") not in kept:
            continue
        for t in g.get("allMitreTechniques") or []:
            tactic = tactics.setdefault((t.get("relatedTactic") or {}).get("name"), {})
            e = tactic.setdefault(t.get("ID"), {"id": t.get("ID"), "name": t.get("name"), "signal_groups": []})
            if g.get("identifier") not in e["signal_groups"]:
                e["signal_groups"].append(g.get("identifier"))
    return {"tactics": {name: list(techniques.values()) for name, techniques in tactics.items()}}


# {"files": [{name, sha256, origin, events}]}, only files with emulation events.
def _slim_emulation(report: dict[str, Any]) -> dict[str, Any]:
    return {"files": [{**_file(origin, f), "events": _slim_events(f["emulationData"])}
                      for origin, f in _files(report) if f.get("emulationData")]}


# {"files": [{name, sha256, origin, matches: [{rule, description, author, verdict, tags}]}]}, only YARA_VERDICTS
# matches and files with some.
def _slim_yara_matches(report: dict[str, Any]) -> dict[str, Any]:
    files = [(origin, f, [m for m in f.get("yaraMatches") or [] if (m.get("verdict") or {}).get("verdict") in YARA_VERDICTS])
             for origin, f in _files(report)]
    return {"files": [{**_file(origin, f), "matches": [
        {"rule": m.get("ruleName"), "description": (m.get("metaData") or {}).get("description"),
         "author": (m.get("metaData") or {}).get("author"), "verdict": m["verdict"]["verdict"].lower(),
         "tags": list(dict.fromkeys((t.get("tag") or {}).get("name") for t in m.get("tags") or []))}
        for m in matches]} for origin, f, matches in files if matches]}


# {"files": [{name, sha256, origin, attributions: [{family, type, score, description, evidences}]}]}, only attributed
# files; evidences without the repeated family name and OSINT source data.
def _slim_threat_attribution(report: dict[str, Any]) -> dict[str, Any]:
    return {"files": [{**_file(origin, f), "attributions": [
        {"family": a.get("threatName"), "type": a.get("threatType"), "score": a.get("aggregatedScore"),
         "description": a.get("description"),
         "evidences": [{k: v for k, v in e.items() if k not in ("threatName", "source")} for e in a.get("evidences") or []]}
        for a in f["threatAttribution"]["attributions"]]}
        for origin, f in _files(report) if (f.get("threatAttribution") or {}).get("attributions")]}


# {"renders": [{url, final_url, ip, server, redirects: [{from, status, to}], brand (only if detected)}]}; redirects are
# those of pages (not of scripts or images); the request log, links and Aether's phishing scores are dropped.
def _slim_url_render(renders: list[dict[str, Any]]) -> dict[str, Any]:
    slim = []
    for r in renders:
        data = r.get("urlRenderData") or {}
        result = data.get("result") or {}
        page = result.get("page") or {}
        pages = [q["request"] for q in (result.get("data") or {}).get("requests") or []
                 if (q.get("request") or {}).get("type") == "Document"]
        brand = (result.get("phishDetection") or {}).get("brand")
        slim.append({"url": data.get("url"), "final_url": page.get("url"), "ip": page.get("ip"), "server": page.get("server"),
                     "redirects": [{"from": p["redirectResponse"].get("url"), "status": p["redirectResponse"].get("status"),
                                    "to": (p.get("request") or {}).get("url")} for p in pages if p.get("redirectResponse")],
                     **({"brand": brand} if brand else {})})
    return {"renders": slim}


# Every file of a report as (origin, file): the input file, files extracted from it and files it downloaded.
def _files(report: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return [(origin, f) for resource in (report.get("resources") or {}).values()
            for origin, items in [("input", [resource]), ("extracted", resource.get("extractedFiles") or []),
                                  ("downloaded", resource.get("fileDownloadResults") or [])] for f in items]


# A file as {name, sha256, origin}.
def _file(origin: str, f: dict[str, Any]) -> dict[str, Any]:
    return {"name": f.get("submitName"), "sha256": (f.get("digests") or {}).get("SHA-256"), "origin": origin}


# Events as {action, ...details}, without repeats.
def _slim_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for e in events:
        event = {"action": e.get("action"), **_event_details(e.get("additionalInformation") or {})}
        unique.setdefault(json.dumps(event, sort_keys=True), event)
    return list(unique.values())


# Event details without EMULATION_EVENT_DROPPED, long call arguments (payloads) or HTTP response bodies;
# HTTP request bodies decoded from base64.
def _event_details(info: dict[str, Any]) -> dict[str, Any]:
    info = {k: v for k, v in info.items() if k not in EMULATION_EVENT_DROPPED}
    if isinstance(info.get("Arguments"), list):
        info["Arguments"] = [f"<{len(a)} chars>" if isinstance(a, str) and len(a) > EMULATION_EVENT_CHARS else a
                             for a in info["Arguments"]]
    if isinstance(info.get("Request"), dict) and "Body" in info["Request"]:
        info["Request"] = {**info["Request"], "Body": _decoded(info["Request"]["Body"])}
    if isinstance(info.get("Response"), dict):
        info["Response"] = {k: v for k, v in info["Response"].items() if k != "Body"}
    return bounded(info, EMULATION_EVENT_CHARS, EMULATION_EVENT_ITEMS)


# {"files": [{name, sha256, type, origin, parent, interesting, tags}]}; if only_interesting, also how many were left out.
def _slim_extracted_files(report: dict[str, Any], only_interesting: bool) -> dict[str, Any]:
    files = [{"name": f.get("submitName"), "sha256": (f.get("digests") or {}).get("SHA-256"),
              "type": (f.get("mediaType") or {}).get("string"), "origin": (f.get("origin") or {}).get("type"),
              "parent": (f.get("origin") or {}).get("identifier"), "interesting": bool(f.get("interesting")),
              "tags": unique_tags(f.get("allTags"))}
             for resource in (report.get("resources") or {}).values() for f in resource.get("extractedFiles") or []]
    if not only_interesting:
        return {"files": files}
    kept = [f for f in files if f["interesting"]]
    return {"files": kept, "not_interesting": len(files) - len(kept)}


# Base64 text decoded, or as it is if it is not base64 of UTF-8 text.
def _decoded(text: Any) -> Any:
    try:
        return base64.b64decode(text, validate=True).decode()
    except (TypeError, ValueError):
        return text


# Aether tags as unique {name, source}, without those Aether suppresses (also used by search and pivot_ioc).
def unique_tags(tags: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    pairs = dict.fromkeys(((t.get("tag") or {}).get("name"), t.get("source")) for t in tags or [] if not t.get("suppressed"))
    return [{"name": name, "source": source} for name, source in pairs]
