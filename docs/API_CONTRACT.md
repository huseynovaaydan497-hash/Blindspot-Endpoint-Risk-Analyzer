# API and data contract

Owner: D. Frozen at H1. Adding an **optional** key is allowed; renaming or removing a key is not.
Python constants live in `blindspot/contract.py`.

## Module interfaces

| Module | Function | Returns |
| --- | --- | --- |
| `analyzer/manifest.py` (B) | `load_manifest(ext_dir)` | `ManifestInfo` |
| `analyzer/permissions.py` (B) | `analyze_permissions(info)` | `SignalResult` |
| `analyzer/codescan.py` (C) | `scan_code(ext_dir)` | `SignalResult` (+ `files_scanned`) |
| `analyzer/network.py` (C) | `extract_endpoints(ext_dir, info)` | `SignalResult` (+ `endpoints`) |
| `analyzer/reputation.py` (C) | `check_reputation(ext_id, cache, now)` | `SignalResult` (+ `store`) |
| `analyzer/score.py` (B) | `combine(signals, known_good, exposure_count)` | `(score, level, extra_findings, rating)` |
| `pipeline.py` (D) | `analyze_extension(ext_dir)` | `AnalysisResult` |
| `collector/extensions.py` (A) | `find_installed_extensions()` | `[{browser, profile, id, version_dir}]` |
| `collector/software.py` (A) | `list_installed_software()` | `[{name, version, publisher, source}]` |

## Shapes

**ManifestInfo**
```json
{"id": "32 chars a-p", "name": "Weather Now", "version": "4.1.7", "manifest_version": 2,
 "description": "...", "permissions": ["tabs"], "host_permissions": ["<all_urls>"],
 "optional_permissions": [], "content_script_matches": [], "content_security_policy": ["..."],
 "externally_connectable": false, "update_url": null, "homepage_url": null, "path": "/abs/path"}
```

**Finding**
```json
{"signal": "permission|code|network|reputation|score", "severity": "info|low|medium|high|critical",
 "title": "Session cookies on every website", "detail": "One plain-language sentence.",
 "evidence": "cookies + broad host", "points": 15}
```

**SignalResult** — `{"score": 0-100, "findings": [Finding], "available": true}` plus module extras.
`available: false` means "no data", and the signal is left out of the composite score.

**AnalysisResult** (one extension)
```json
{"id": "...", "name": "...", "version": "...", "manifest_version": 3, "description": "...",
 "permissions": [], "host_permissions": [], "optional_permissions": [], "content_script_matches": [],
 "high_risk_permissions": ["broad host access", "cookies"],
 "capabilities": [{"permission": "cookies", "meaning": "Can read and change cookies..."}],
 "score": 86, "level": "high", "recommendation": "quarantine|block|contain|review|allow", "known_good": false,
 "signals": {"permission": {"score": 100, "available": true}, "code": {...}, "network": {...}, "reputation": {...}},
 "findings": [Finding], "endpoints": [{"host": "...", "url": "...", "scheme": "https", "known": false}],
 "store": {"users": 820, "last_updated": "2023-05-11", "publisher": "", "in_store": true} ,
 "exposure": [{"system": "SWIFT portal", "hosts": ["*://swift.bank.local"], "via": "host permission", "pattern": "<all_urls>"}],
 "ai": {"is_ai": true, "services": ["api.openai.com"], "evidence": "talks to AI providers"},
 "analyzed_at": "ISO-8601", "path": "local only, removed before sending"}
```

**Agent payload** — `POST /api/v1/inventory`
```json
{"machine": {"machine_id": "...", "hostname": "...", "os": "...", "collected_at": "ISO-8601"},
 "extensions": [AnalysisResult + {"browser": "chrome", "profile": "Default", "files": [{"path", "sha256", "size"}]}],
 "software": [{"name": "...", "version": "...", "publisher": "...", "source": "registry"}]}
```

## HTTP endpoints

| Method | Path | Returns |
| --- | --- | --- |
| GET | `/api/v1/health` | `{"status": "ok", "version"}` |
| POST | `/api/v1/inventory` | `{"machine_id", "extensions", "software"}`; 422 on a bad payload |
| GET | `/api/v1/fleet/summary` | `{machines, last_seen, extensions_installed, unique_extensions, by_level, by_recommendation, installs_at_high_risk, software_titles}` |
| GET | `/api/v1/extensions` | list of `{id, name, version, score, level, recommendation, known_good, installs, machines, high_risk_permissions, signals, top_finding}` |
| GET | `/api/v1/extensions/{id}` | `AnalysisResult` + `installs: [{machine_id, hostname, browser, profile, version}]`; 404 if unknown |
| GET | `/api/v1/machines` | list of `{machine_id, hostname, os, collected_at, extensions, high_risk}` |
| GET | `/api/v1/software` | list of `{name, version, publisher, machines}` |
| GET | `/api/v1/report.json` / `report.html` | structured report / printable HTML |
| GET | `/api/v1/exposure` | per crown-jewel system: `{system, hosts, extensions, extension_count, machine_count, machines, ai_count}` |
| GET | `/api/v1/policy.json?default_deny=&protect_all=&contain=&block_at=&review_at=` | `{decisions: {allow, contain, review, block}, chrome_policy, thresholds, mode, crown_jewels}` |
| GET | `/api/v1/policy.reg` | Windows registry file |

`fixtures/seed.json` (and `frontend/data/seed.json`) contains `summary`, `extensions`, `details`,
`machines` and `software` in exactly these shapes. Regenerate with `python -m blindspot fixtures`.


## Added in v4.1

Optional keys on AnalysisResult: `rating` (OWASP likelihood/impact/severity/factors), `attack`
(`[{id, name, why}]`), `content_hash` (SHA-256 of the files). The store adds `guard`
(`{pinned, quarantined: [{version, reasons, diff, at}]}`) and `installed_versions`.

| Method | Path | Returns |
| --- | --- | --- |
| GET | `/api/v1/machines/{id or hostname}` | machine with `extensions` (version installed there) and assessed `software` |
| GET | `/api/v1/software` | per program and version: `status` (blocked, review, allowed, unreviewed), `score` (CVSS × 10), `decision` (SSVC), `vulnerabilities`, `hostnames` |
| GET | `/api/v1/guard` | `extensions` (pinned, quarantined, not pinned), `catalog`, `unapproved`, `advisories`, `pending_advisories`, `events` |
| POST | `/api/v1/guard/extensions/{id}/approve?version=` | pins that version and releases it from quarantine |
| POST | `/api/v1/guard/advisories/sync` | adds new advisories from the feed: `{added, newly_blocked}` |
| POST | `/api/v1/guard/advisories/reset` | demo helper: back to the initial advisories |
| GET | `/api/v1/software-policy.json`, `/api/v1/software-policy.xml` | software decisions; AppLocker rules (audit mode) |
