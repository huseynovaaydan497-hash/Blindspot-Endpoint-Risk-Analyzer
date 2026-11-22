# Project Blindspot

**Endpoint supply-chain auditing for browser extensions.** Blindspot inventories the browser
extensions and software installed on corporate endpoints, scores each extension's risk from four
independent signals, explains every score in plain language, and turns the result into
ready-to-deploy Chrome Enterprise allowlist / blocklist policies.

Browser extensions run with access to every page a user opens, update themselves silently, and
are invisible to most endpoint security tools. Blindspot makes that layer visible.

## Hackathon requirements → where they are implemented

| Requirement (24-hour MVP) | Implementation | Test |
| --- | --- | --- |
| Parse manifests and permissions of sample browser extensions | `blindspot/analyzer/manifest.py` | `test_manifest_*` |
| Flag high-risk / excessive permissions (broad host access, cookies, webRequest) | `blindspot/analyzer/permissions.py`, `fixtures/permission_weights.json` | `test_flags_brief_permissions` |
| Calculate a basic risk score per extension | `blindspot/analyzer/score.py` | `test_levels_of_samples` |
| Produce a structured risk assessment report | `blindspot/report/report.py` → `report.json` + `report.html` | `test_report_structure_and_html` |

Beyond the minimum: static code analysis, network endpoint extraction, store reputation,
local software inventory, a fleet dashboard, and an allow / contain / review / block policy
generator (Chrome and Edge managed-policy JSON and a Windows `.reg` file).

## Built for organisations that already lock browsers down

Banks already restrict extension installs with Group Policy. Blindspot covers what an
allowlist cannot:

- **Crown-jewel blast radius.** The organisation lists its most sensitive web systems in
  `fixtures/crown_jewels.json` (core banking, SWIFT portal, HR...). Blindspot shows, per
  system, which extensions on which machines can read and change it if they turned malicious.
- **Shadow AI.** Extensions that can read every page *and* talk to AI providers
  (`fixtures/ai_services.json`) are flagged: page content, including customer data, can leave
  the organisation through them.
- **Containment instead of all-or-nothing.** Useful extensions do not have to be blocked. The
  policy generator adds Chrome/Edge `runtime_blocked_hosts` so they keep working everywhere
  except the crown-jewel systems; `--protect-all` applies this to every extension, including
  ones installed in the future.

## Quick start

Needs Python 3.10+.

**Server (one computer):** double-click `start_server.bat` (Windows) or run `sh start_server.sh`.
The first run creates `.venv` and installs the requirements. The dashboard then opens at
<http://localhost:8000>. The dashboard starts empty and shows only what agents report.

**Every computer to monitor:** in the dashboard, open **Add a computer**, download
`blindspot-agent.zip` (the server address is already inside), unzip it and double-click
`run_agent.bat` to report once, or `watch_agent.bat` to keep reporting every 10 minutes. The agent
uses only the Python standard library. The dashboard picks up new reports within 10 seconds.

Manual commands:

```bash
pip install -r requirements.txt
uvicorn backend.main:app --host 0.0.0.0 --port 8000           # server + dashboard
python -m blindspot agent --server http://SERVER-IP:8000          # report this computer once
python -m blindspot agent --server http://SERVER-IP:8000 --every 10   # keep watching
python -m blindspot scan samples/extensions                        # offline: analyse a folder -> reports/
python -m pytest -q                                                # tests
```

`python -m blindspot demo-fleet` and `fixtures` create **synthetic** data for tests and
development only. Use **Add a computer → Clear all data** to remove it from a server.

## How the score works

Extension ratings follow the **OWASP Risk Rating Methodology**: `Risk = Likelihood × Impact`,
with every factor on a 0–9 scale and OWASP's severity matrix. Software uses **CVSS v3.1 (NVD)**,
the **CISA KEV** catalog and **CISA SSVC** decisions. Capabilities are mapped to **MITRE ATT&CK**.
Each rule and its source is listed in [docs/METHODOLOGY.md](docs/METHODOLOGY.md).

| Side | Factor | Measured from |
| --- | --- | --- |
| Likelihood | Code | `eval`, runtime code, obfuscation, cookie dumping, script injection, hidden data |
| Likelihood | Network | Servers that are not on the known-services list, raw IPs, plain HTTP |
| Likelihood | Reputation | Removed from the store, not updated for 2+ years, very few users, unknown publisher |
| Impact | Technical | Host access, API permissions, dangerous combinations, `unsafe-eval` CSP |
| Impact | Business | Number of the organisation's crown-jewel systems it can reach |

Each side is `0.6 × strongest factor + 0.4 × average`. A critical finding sets its factor to at
least 8, and unknown likelihood counts as medium. The 0–100 score is the OWASP severity band:
**Critical 85+ / High 70+** means block, **Medium 35+** means review, and **Low / Note** means allow.
Every point is traced to a finding with evidence (a permission name or `file.js:line: code`).

## Guard: trust the code, not the ID

Allowlists approve an extension ID, and a hijacked update keeps the same ID (the Cyberhaven
incident, December 2024). Guard pins every approved extension to its version **and** a SHA-256
of its files. On every agent report:

- **Benign update** (no new permissions, sites or servers, and risk did not rise): approved automatically.
- **Risky update**: quarantined. The policy blocks it until a person approves the build.
- **Approved software**: when an advisory hits an approved version, that version is blocked, and
  installs are allowed again from the fixed version. Example: 7-Zip 24.08 is blocked by
  CVE-2025-0411 (CISA KEV) until 24.09. Outputs are Chrome/Edge policy, a Windows `.reg` and
  AppLocker rules (audit mode).

Continuous monitoring: `python -m blindspot agent --server http://HOST:8000 --every 15`.
Every extension is pinned the first time it is seen, so any later update is compared with it.

**Prove it on your own computer** with a harmless test extension:
`python -m blindspot test-extension create`, then Load unpacked it in `chrome://extensions` and run the agent;
`python -m blindspot test-extension hijack`, press reload on the extension card and run the agent again.
Guard quarantines the new build.

**Software:** the server checks installed programs against the live **NVD** (affected version ranges,
CVSS) and **CISA KEV** (exploited in the wild) every 6 hours. The programs it checks are listed in
`fixtures/software_watchlist.json`. Approve a version in the dashboard (Software → Approve this
version). If a CVE later hits it, that version is blocked and an alert is sent until the fix is installed.

**Telegram alerts:** dashboard → **Alerts**. Messages are sent when an update is quarantined, a new CVE
blocks installed software, or a High/Critical extension appears for the first time.

## Architecture

```
Endpoint agent ──► analyzer (permission · code · network · reputation) ──► composite score
      │                                                                          │
      └──── POST /api/v1/inventory ──► FastAPI + SQLite ──► dashboard · report · policy
```

Analysis runs **on the endpoint**. Only results, manifests and file hashes are sent to the
server — never browsing history, cookies, passwords or the extensions' source code.
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/API_CONTRACT.md](docs/API_CONTRACT.md).

## Repository layout

| Path | Contents |
| --- | --- |
| `blindspot/contract.py` | Shared data shapes and constants every module uses |
| `blindspot/analyzer/` | Manifest parser and the four signals + scoring |
| `blindspot/collector/` | Endpoint agent: extension discovery, software inventory |
| `blindspot/report/`, `blindspot/policy/` | Report and policy generation |
| `blindspot/pipeline.py`, `blindspot/store.py` | Glue and fleet storage |
| `backend/` | FastAPI server |
| `frontend/` | Dashboard (plain HTML/JS, no build step) |
| `fixtures/` | Permission weights, glossary, known domains, store cache, approved list, ATT&CK mapping, software catalog, advisories |
| `samples/extensions/` | Seven **inert, synthetic** test extensions (see below) |
| `samples/updates/` | Newer builds for the Guard demo: one benign, one hijacked (Cyberhaven-style) |
| `blindspot/guard.py`, `blindspot/software/` | Version pinning and drift checks; software CVE scoring |
| `tests/` | End-to-end tests; CI runs them on every pull request |

## About the samples

`samples/extensions/` holds six synthetic extensions built for testing. They are never loaded into
a browser, their suspicious-looking functions are never called, and every address uses reserved,
unroutable names (`.invalid`, `203.0.113.0/24`). Store data for them in `fixtures/store_cache.json`
is synthetic and marked as such. To analyse real extensions, copy them into `samples/real/`
(ignored by git) or run the agent.

## Known limitations

- Static analysis only: obfuscated or remotely loaded code can hide behaviour.
- Heuristic rules produce false positives (password managers and ad blockers legitimately need broad access); `fixtures/known_good.json` handles approved tools.
- The Chrome Web Store has no official API; reputation data is scraped ahead of time and cached.
- Chromium-based browsers only; Firefox is not yet supported.
- Chrome cannot block a single extension version, so quarantine blocks the ID until it is reviewed. Pinning to an internal update server (`mirror_url`) removes this limit.
- The advisory feed is a curated file (`fixtures/advisories.json`); production would pull NVD and CISA KEV.
- See [docs/METHODOLOGY.md](docs/METHODOLOGY.md#4-honest-limits) for the full list.

## Team

Project Blindspot — hackathon / capstone team. Contribution workflow: [CONTRIBUTING.md](CONTRIBUTING.md).
