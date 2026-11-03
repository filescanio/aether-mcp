# <img src="src/aether_mcp/icon.svg" width="40" alt=""> aether-mcp

**Scan files, hunt threats and pivot campaigns with MetaDefender Aether.**

Minimal MCP server for the Aether / Filescan.io API: a thin translation layer between the LLM and the
API. Each tool calls Aether and returns only what the LLM needs.
Scans are always **private**.

## Tools

### Scan (`tools/scan.py`)


| Tool        | What it does                          | API                   |
| ----------- | ------------------------------------- | --------------------- |
| `scan_file` | Upload a local file as a private scan | `POST /api/scan/file` |
| `scan_url`  | Submit a URL as a private scan        | `POST /api/scan/url`  |

**Try:**
- "Scan ~/Downloads/invoice.pdf in Aether and tell me if it is malicious and why."



### Lookup (`tools/lookup.py`)


| Tool                                         | What it does                                      | API                                   |
| -------------------------------------------- | ------------------------------------------------- | ------------------------------------- |
| `lookup_hash`                                | Reputation of up to 100 SHA-256s                  | `POST /api/reputation/hash`           |
| `lookup_file`                                | Hash a local file and look it up (never uploaded) | `GET /api/reputation/hash`            |
| `lookup_ip` / `lookup_domain` / `lookup_url` | Reputation of up to 100 IOCs of one type          | `POST /api/reputation/{ip,domain,url}` |

**Try:**
- "Is this IP malicious, and which samples use it? <ip>"
- "Check the reputation of these 20 domains from the incident: <domains>"



### Search (`tools/search.py`)


| Tool                   | What it does                                                                     | API                                           |
| ---------------------- | -------------------------------------------------------------------------------- | --------------------------------------------- |
| `resolve_family`       | Malware family names                                                             | `GET /api/reports/threat-attribution-options` |
| `resolve_file_type`    | File types and file type groups                                                  | `GET /api/system/config`                      |
| `resolve_technique`    | MITRE ATT&CK technique IDs and names                                             | `GET /api/system/mitre`                       |
| `resolve_signal_group` | Signal groups (sandbox indicators)                                               | `GET /api/system/signal-groups`               |
| `get_yara_rule`        | Source of a YARA rule, by name                                                   | `GET /api/system/yara`                        |
| `search`               | Search reports by family, file type, signal group, technique, tag, verdict, file name, registry key, YARA rule, date; newest report per file | `GET /api/reports/advanced-search`            |
| `pivot_ioc`            | Reports that contain an IP, domain, URL, email or SHA-256; newest report per file | `GET /api/reports/advanced-search`            |
| `find_similar`         | Samples with similar code, with similarity %, verdict and tags                   | `GET /api/similarity-search/similarity`       |
| `get_ioc_prevalence`   | Report counts per verdict for IOCs                                               | `POST /api/threatintel/get-prevalence`        |

**Try:**
- "Find AsyncRAT samples from this month and list their C2 servers."
- "Which other samples contact api.ip.sb? Are they the same campaign?"



### Report (`tools/report.py`)


| Tool                   | What it does                                                                | API                              |
| ---------------------- | --------------------------------------------------------------------------- | -------------------------------- |
| `get_scan_result`      | Verdict, file and tags of a scan by `flow_id`, waiting up to `wait_seconds` | `GET /api/scan/{flow_id}/report` |
| `get_iocs`             | IOCs extracted from a report, with where each was found                     | `GET /api/reports/{id}/{sha256}` |
| `get_malware_config`   | Malware configs extracted from up to 20 reports                             | `GET /api/reports/{id}/{sha256}` |
| `get_mitre_techniques` | MITRE ATT&CK techniques of a report, with the signal groups behind each     | `GET /api/reports/{id}/{sha256}` |
| `get_emulation`        | Emulation events of the input, extracted and downloaded files of a report   | `GET /api/reports/{id}/{sha256}` |
| `get_extracted_files`  | Files extracted from a report's file (interesting ones by default) | `GET /api/reports/{id}/{sha256}` |
| `get_yara_matches`     | YARA rules that matched each file of a report                      | `GET /api/reports/{id}/{sha256}` |
| `get_threat_attribution` | Malware families attributed to a report's files, with the evidence for each | `GET /api/reports/{id}/{sha256}` |
| `get_url_render`       | Rendered pages of a report: final URL, redirects and a screenshot  | `GET /api/reports/{id}/{sha256}` |

**Try:**
- "Extract the malware config and C2s of that sample."
- "Map that sample to MITRE ATT&CK tactics and techniques."
- "What does that script do when it runs? Any persistence or network activity?"
- "Which family is that sample, and what is the evidence?"


`client.py` allowlists the endpoints above; nothing can download sample files.

## Install

You need [uv](https://docs.astral.sh/uv/) and an Aether API key.

**Claude Code**

```bash
claude mcp add aether -s user -e AETHER_API_KEY=<your key> -- uvx --from git+https://github.com/filescanio/aether-mcp@v1.0.0 aether-mcp
```

**Claude Desktop**: download `aether-1.0.0.mcpb` from the
[latest release](https://github.com/filescanio/aether-mcp/releases/latest), open it, and enter your API key
when asked.

To build the bundle: `npx @anthropic-ai/mcpb pack . dist/aether-1.0.0.mcpb`.

**Codex**: add to `~/.codex/config.toml` (the first start downloads the server, so allow it more than the default 10s):

```toml
[mcp_servers.aether]
command = "uvx"
args = ["--from", "git+https://github.com/filescanio/aether-mcp@v1.0.0", "aether-mcp"]
env = { AETHER_API_KEY = "<your key>" }
startup_timeout_sec = 60
```

**Other MCP clients** (Cursor, Windsurf, Gemini CLI...): run the same command over stdio, e.g. in `mcp.json`:

```json
{
  "mcpServers": {
    "aether": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/filescanio/aether-mcp@v1.0.0", "aether-mcp"],
      "env": { "AETHER_API_KEY": "<your key>" }
    }
  }
}
```
