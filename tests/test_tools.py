import hashlib
import json

import pytest

from aether_mcp.tools import lookup, report, search

pytestmark = pytest.mark.anyio

SHA256 = "a" * 64
FLOW_ID = "f" * 24
REPORT_ID = "1234abcd-1234-1234-1234-1234567890ab"


# ---------- lookup ----------

# All values in one bulk call; the 3 newest sandbox reports each.
async def test_lookup_ip(fake_aether):
    reports = [{"report_id": f"r{day}", "flow_id": f"f{day}", "report_date": f"10/0{day}/2026, 10:00:00",
                "verdict": "malicious"} for day in (1, 3, 2, 4)]
    client = fake_aether([{"ioc_value": "203.0.113.5", "overall_verdict": "malicious",
                           "mdcloud": {"detected": 2, "scan_time": "2026-10-05T10:00:00"}, "filescan_reports": reports},
                          {"ioc_value": "198.51.100.7", "overall_verdict": "unknown"}])
    assert await lookup.lookup_ip(client, ["203.0.113.5", "198.51.100.7"]) == {"results": [
        {"value": "203.0.113.5", "verdict": "malicious", "mdcloud": {"detected": 2, "scan_date": "2026-10-05"},
         "sandbox_reports": [{"report_id": f"r{day}", "flow_id": f"f{day}", "date": f"2026-10-0{day}",
                              "verdict": "malicious"} for day in (4, 3, 2)]},
        {"value": "198.51.100.7", "verdict": "unknown", "mdcloud": None, "sandbox_reports": []}]}
    assert json.loads(client.sent[0].read()) == ["203.0.113.5", "198.51.100.7"]


async def test_lookup_file(fake_aether, tmp_path):
    file = tmp_path / "sample.txt"
    file.write_text("hello")
    client = fake_aether({"overall_verdict": "benign"})
    sha256 = hashlib.sha256(b"hello").hexdigest()
    assert await lookup.lookup_file(client, str(file)) == {"sha256": sha256, "verdict": "benign", "mdcloud": None,
                                                           "sandbox_reports": []}
    assert client.sent[0].url.params["sha256"] == sha256


# ---------- search ----------

async def test_resolve_family(fake_aether):
    assert await search.resolve_family(fake_aether({"tags": ["AsyncRAT"]})) == {"families": ["AsyncRAT"]}


async def test_resolve_file_type(fake_aether):
    client = fake_aether({"supportedTypes": ["pe"], "fileGeneralTypes": ["executable"], "other": "not for the LLM"})
    assert await search.resolve_file_type(client) == {"supportedTypes": ["pe"], "fileGeneralTypes": ["executable"]}


async def test_resolve_technique(fake_aether):
    client = fake_aether({"TA0005": {"techniques": {"T1055": {"name": "Process Injection", "description": "..."},
                                                    "T1027": {"name": "Obfuscated Files", "description": "..."}}}})
    assert await search.resolve_technique(client, ["inject"]) == {"T1055": "Process Injection"}


async def test_resolve_signal_group(fake_aether):
    client = fake_aether([{"groups": [{"id": "K1", "description": "Keylogger"}, {"id": "N1", "description": "Network"}]}])
    assert await search.resolve_signal_group(client, ["keylog"]) == {"K1": "Keylogger"}


async def test_get_yara_rule(fake_aether):
    client = fake_aether([{"name": "win_asyncrat_j1", "author": "a", "strength": 0.1, "content": "rule win_asyncrat_j1 {}"}])
    assert await search.get_yara_rule(client, "WIN_ASYNCRAT_J1") == {
        "rules": [{"name": "win_asyncrat_j1", "content": "rule win_asyncrat_j1 {}"}]}
    assert client.sent[0].url.params["name"] == "WIN_ASYNCRAT_J1"


# Rescans of a file are listed once (newest first); tags are unique, without suppressed ones.
async def test_search(fake_aether):
    def item(report_id, sha256):
        return {"id": report_id, "scan_init": {"id": FLOW_ID}, "file": {"name": "a.exe", "sha256": sha256, "short_type": "pe"},
                "verdict": "malicious", "date": "2026-10-02T10:00:00",
                "tags": [{"tag": {"name": "rat"}, "source": "MWCFG"}] * 2 + [{"tag": {"name": "x"}, "source": "SIGNAL", "suppressed": True}]}
    client = fake_aether({"count": 3, "items": [item("r2", SHA256), item("r1", SHA256), item("r3", "b" * 64)]})
    result = await search.search(client, verdict="malicious")
    assert result["count"] == 3
    assert [i["report_id"] for i in result["items"]] == ["r2", "r3"]
    assert result["items"][0] == {"report_id": "r2", "flow_id": FLOW_ID, "file": {"name": "a.exe", "sha256": SHA256, "type": "pe"},
                                  "verdict": "malicious", "date": "2026-10-02", "tags": [{"name": "rat", "source": "MWCFG"}]}
    assert client.sent[0].url.params["page_size"] == "5"
    assert client.sent[0].url.params["unique_files"] == "true"


# The most similar and the most recent files, once each, most similar first.
async def test_find_similar(fake_aether):
    def similar(sha256, score):
        return {"sha256": sha256, "overall_similarity": score, "details": {
            "verdict": "malicious", "start_date": "2026-01-02T10:00:00", "tags": ["rat"]}}
    client = fake_aether({"most_similar": [similar(SHA256, 0.973)], "most_recent": [similar("b" * 64, 0.991), similar(SHA256, 0.973)]})
    assert await search.find_similar(client, SHA256, 95) == {"similar": [
        {"sha256": sha256, "similarity": score, "verdict": "malicious", "first_seen": "2026-01-02", "tags": ["rat"]}
        for sha256, score in [("b" * 64, 99), (SHA256, 97)]]}


# Aether keys URLs by their MD5; they come back as URLs.
async def test_get_ioc_prevalence(fake_aether):
    url = "https://example.com"
    client = fake_aether({"url": {hashlib.md5(url.encode()).hexdigest(): {"counts": {"malicious": 2}, "reports": ["..."]}}})
    assert await search.get_ioc_prevalence(client, ip=None, domain=None, url=[url], email=None) == {
        "url": {url: {"malicious": 2}}}
    assert client.sent[0].read() == b'{"url":["https://example.com"]}'


# ---------- report ----------

async def test_get_scan_result_running(fake_aether):
    client = fake_aether({"reports": {"r1": {"overallState": "in_progress"}}})
    assert await report.get_scan_result(client, FLOW_ID, wait_seconds=0) == {"finished": False}


async def test_get_scan_result(fake_aether):
    client = fake_aether({"reports": {"r1": {
        "overallState": "finished", "finalVerdict": {"verdict": "MALICIOUS"},
        "resources": {"x": {"submitName": "a.exe", "mediaType": {"string": "pe"}, "digests": {"SHA-256": SHA256}}},
        "allTags": [{"tag": {"name": "agenttesla"}, "source": "MWCFG", "suppressed": True},
                    {"tag": {"name": "agenttesla"}, "source": "THREAT_ATTRIBUTION"}]}}})
    assert await report.get_scan_result(client, FLOW_ID, wait_seconds=0) == {
        "finished": True, "report_id": "r1", "verdict": "malicious",
        "file": {"name": "a.exe", "type": "pe", "sha256": SHA256},
        "has_config": True, "tags": [{"name": "agenttesla", "source": "THREAT_ATTRIBUTION"}]}


# The report's IOCs plus those found in extracted files, merged by value; only the asked types.
async def test_get_iocs(fake_aether):
    def found(value, source):
        return [{"origin": {"type": source}, "references": [{"data": value}]}]
    client = fake_aether({"reports": {REPORT_ID: {
        "iocs": {"ip": [{"data": "203.0.113.5", "origins": [{"type": "INPUT_FILE"}, {"type": "INPUT_FILE"}]}]},
        "resources": {"file": {"extractedFiles": [{"extractedIPs": found("203.0.113.5", "JAVASCRIPT_EMULATION"),
                                                   "extractedUrls": found("https://example.com/a", "EXTRACTED_FILE")}]}}}}})
    assert await report.get_iocs(client, REPORT_ID, SHA256) == {
        "ip": [{"value": "203.0.113.5", "source": "INPUT_FILE, JAVASCRIPT_EMULATION"}],
        "url": [{"value": "https://example.com/a", "source": "EXTRACTED_FILE"}]}
    assert list(await report.get_iocs(client, REPORT_ID, SHA256, ["url"])) == ["url"]


# String dumps and payload bytes are dropped.
async def test_get_malware_config(fake_aether):
    config = {"c2": ["203.0.113.5"], "decrypted_strings": ["..."], "payloads": [{"name": "stage2", "value": "TVqQ"}]}
    client = fake_aether({"reports": {REPORT_ID: {"resources": {"x": {"extendedData": {"malwareConfig": [{"data": config}]}}}}}})
    assert await report.get_malware_config(client, [(REPORT_ID, SHA256), (REPORT_ID, "b" * 64)]) == {"results": [
        {"report_id": REPORT_ID, "sha256": sha256, "configs": [{"c2": ["203.0.113.5"], "payloads": [{"name": "stage2"}]}]}
        for sha256 in (SHA256, "b" * 64)]}
    assert len(client.sent) == 2


# A report that fails returns its error, not the whole call.
async def test_get_malware_config_error(fake_aether):
    client = fake_aether({"detail": "Report not found"}, status=404)
    result = (await report.get_malware_config(client, [(REPORT_ID, SHA256)]))["results"][0]
    assert result["report_id"] == REPORT_ID and "Report not found" in result["error"]


# Only signal groups at the final verdict and one below count.
async def test_get_mitre_techniques(fake_aether):
    def group(name, verdict, technique):
        return {"identifier": name, "verdict": {"verdict": verdict}, "allMitreTechniques": [
            {"ID": technique, "name": f"{technique} name", "relatedTactic": {"name": "Defense Evasion"}}]}
    client = fake_aether({"reports": {REPORT_ID: {"finalVerdict": {"verdict": "MALICIOUS"},
                                                  "allSignalGroups": [group("g1", "MALICIOUS", "T1055"),
                                                                      group("g2", "NO_THREAT", "T1082")]}}})
    assert await report.get_mitre_techniques(client, REPORT_ID, SHA256) == {
        "tactics": {"Defense Evasion": [{"id": "T1055", "name": "T1055 name", "signal_groups": ["g1"]}]}}


# Only emulated files; payloads and response bodies dropped, request bodies decoded, repeats merged.
async def test_get_emulation(fake_aether):
    script = {"action": "ExecuteScript", "additionalInformation": {"Language": "Powershell", "Data": "JFggPSAx"}}
    invoke = {"action": "InvokeMethod", "additionalInformation": {"Arguments": ["aspnet_compiler.exe", "A" * 400]}}
    post = {"action": "HttpRequest", "additionalInformation": {"Request": {"Body": "eyJhIjogMX0="}, "Response": {"Body": "b2s="}}}
    client = fake_aether({"reports": {REPORT_ID: {"resources": {
        "file": {"emulationData": [], "extractedFiles": [{"submitName": "a.ps1", "emulationData": [script, script, invoke]}]},
        "download": {"fileDownloadResults": [{"submitName": "b.js", "emulationData": [post]}]}}}}})
    assert await report.get_emulation(client, REPORT_ID, SHA256) == {"files": [
        {"name": "a.ps1", "sha256": None, "origin": "extracted", "events": [
            {"action": "ExecuteScript", "Language": "Powershell"},
            {"action": "InvokeMethod", "Arguments": ["aspnet_compiler.exe", "<400 chars>"]}]},
        {"name": "b.js", "sha256": None, "origin": "downloaded", "events": [
            {"action": "HttpRequest", "Request": {"Body": '{"a": 1}'}, "Response": {}}]}]}


# Only interesting files by default, with a count of the others; all of them on request.
async def test_get_extracted_files(fake_aether):
    def extracted(name, interesting):
        return {"submitName": name, "digests": {"SHA-256": SHA256}, "mediaType": {"string": "pe"}, "interesting": interesting,
                "origin": {"type": "INPUT_FILE", "identifier": "p" * 64}, "allTags": [{"tag": {"name": "peexe"}, "source": "MEDIA_TYPE"}]}
    client = fake_aether({"reports": {REPORT_ID: {"resources": {"file": {"extractedFiles": [
        extracted("icon.ico", False), extracted("payload.exe", True)]}}}}})
    payload = {"name": "payload.exe", "sha256": SHA256, "type": "pe", "origin": "INPUT_FILE", "parent": "p" * 64,
               "interesting": True, "tags": [{"name": "peexe", "source": "MEDIA_TYPE"}]}
    assert await report.get_extracted_files(client, REPORT_ID, SHA256) == {"files": [payload], "not_interesting": 1}
    assert len((await report.get_extracted_files(client, REPORT_ID, SHA256, only_interesting=False))["files"]) == 2


# Only likely malicious and malicious matches, with the tags they carry.
async def test_get_yara_matches(fake_aether):
    def match(rule, verdict):
        return {"ruleName": rule, "metaData": {"author": "a", "description": "d"}, "matchedStrings": ["0x1:$a: x"],
                "verdict": {"verdict": verdict}, "tags": [{"tag": {"name": "hacktool"}, "source": "YARA_RULE"}]}
    client = fake_aether({"reports": {REPORT_ID: {"resources": {"file": {
        "submitName": "a.exe", "digests": {"SHA-256": SHA256},
        "yaraMatches": [match("CookieTools", "LIKELY_MALICIOUS"), match("anti_dbg", "NO_THREAT")],
        "extractedFiles": [{"yaraMatches": [match("WMI", "SUSPICIOUS")]}]}}}}})
    assert await report.get_yara_matches(client, REPORT_ID, SHA256) == {"files": [
        {"name": "a.exe", "sha256": SHA256, "origin": "input", "matches": [
            {"rule": "CookieTools", "description": "d", "author": "a", "verdict": "likely_malicious", "tags": ["hacktool"]}]}]}


# Families of every attributed file, with their evidences (without the repeated family name or OSINT source data).
async def test_get_threat_attribution(fake_aether):
    attribution = {"threatName": "remcos", "threatType": "backdoor", "aggregatedScore": 99, "description": "RAT",
                   "evidences": [{"threatName": "remcos", "origin": "MWCFG"},
                                 {"threatName": "remcos", "origin": "YARA_RULE", "ruleName": "win_remcos"},
                                 {"threatName": "remcos", "origin": "OSINT_LOOKUP", "avVendor": "V", "source": {"x": 1}}]}
    client = fake_aether({"reports": {REPORT_ID: {"resources": {"file": {
        "submitName": "a.exe", "digests": {"SHA-256": SHA256}, "threatAttribution": {"attributions": []},
        "extractedFiles": [{"submitName": "b.exe", "threatAttribution": {"attributions": [attribution]}}]}}}}})
    assert await report.get_threat_attribution(client, REPORT_ID, SHA256) == {"files": [
        {"name": "b.exe", "sha256": None, "origin": "extracted", "attributions": [
            {"family": "remcos", "type": "backdoor", "score": 99, "description": "RAT", "evidences": [
                {"origin": "MWCFG"}, {"origin": "YARA_RULE", "ruleName": "win_remcos"},
                {"origin": "OSINT_LOOKUP", "avVendor": "V"}]}]}]}


# The final page and its page redirects (not those of scripts), and the screenshot as an image.
async def test_get_url_render(fake_aether):
    png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
    requests = [{"request": {"type": "Document", "request": {"url": "https://b.example"},
                             "redirectResponse": {"url": "https://a.example", "status": 302}}},
                {"request": {"type": "Script", "request": {"url": "https://c.example/x.js"},
                             "redirectResponse": {"url": "https://c.example/y.js", "status": 301}}}]
    render = {"base64": png, "urlRenderData": {"url": "https://a.example", "result": {
        "page": {"url": "https://b.example", "ip": "203.0.113.5", "server": "nginx"}, "data": {"requests": requests, "links": [{}]},
        "phishDetection": {"brand": "Example Bank", "confidence": 0.9}}}}
    client = fake_aether({"reports": {REPORT_ID: {"resources": {"r": {"renderResults": [render]}}}}})
    data, image = await report.get_url_render(client, REPORT_ID, SHA256)
    assert data == {"renders": [{"url": "https://a.example", "final_url": "https://b.example", "ip": "203.0.113.5", "server": "nginx",
                                 "redirects": [{"from": "https://a.example", "status": 302, "to": "https://b.example"}],
                                 "brand": "Example Bank"}]}
    assert image.data.startswith(b"\x89PNG")
