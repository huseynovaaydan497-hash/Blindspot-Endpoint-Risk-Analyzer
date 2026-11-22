# How Blindspot rates risk, and where each rule comes from

When a judge asks "where does this number come from?", the answer is one of the sources below.
Every rule has a public reference. Where we adapted a framework, this file says what we changed
and why.

## 1. Browser extensions: OWASP Risk Rating Methodology

**Source:** OWASP Risk Rating Methodology,
<https://owasp.org/www-community/OWASP_Risk_Rating_Methodology>

OWASP's model is `Risk = Likelihood × Impact`. Each factor is scored from 0 to 9. A value from 0 to
less than 3 is LOW, from 3 to less than 6 is MEDIUM, and from 6 to 9 is HIGH. OWASP's severity
matrix (step 4) then combines the two levels:

| Impact \ Likelihood | LOW | MEDIUM | HIGH |
| --- | --- | --- | --- |
| **HIGH** | Medium | High | Critical |
| **MEDIUM** | Low | Medium | High |
| **LOW** | Note | Low | Medium |

### Our factors (code: `blindspot/analyzer/score.py`)

| Side | Factor | Measured from |
| --- | --- | --- |
| Likelihood | Code | Static analysis: `eval`, runtime code, obfuscation, cookie dumping, keylogging, hidden data |
| Likelihood | Network | Servers in the code that are not on the known-services list, raw IPs, plain HTTP |
| Likelihood | Reputation | Chrome Web Store status: removed, abandoned for 2+ years, few users, unknown publisher |
| Impact | Technical | What the permissions allow (`permission_weights.json`) |
| Impact | Business | How many of the organisation's crown-jewel systems it can reach (`crown_jewels.json`) |

Each analyzer gives 0 to 100. That value is rescaled to OWASP's 0 to 9.

### Customisations (OWASP step 6 allows these)

1. **Combination.** OWASP's default is a plain average. We use `0.6 × strongest factor + 0.4 × average`
   so that one severe fact is not diluted by clean ones. Example: "removed from the store" next to
   clean code would otherwise come out as medium.
2. **Critical findings set a floor.** A factor with a critical finding is never below 8. This covers
   "removed from the Chrome Web Store" and "collects cookies and sends them to an unknown server".
3. **Unknown is not safe.** If no likelihood factor could be measured, likelihood is 4.5 (medium).
4. **One number for sorting.** The 0 to 100 score is the OWASP severity band, refined by L × I inside
   the band: Critical 85–100, High 70–84, Medium 35–69, Low 10–34, Note 0–9. The band edges are the
   decision thresholds: 70+ block, 35+ review, below 35 allow.

### Where the permission weights come from

The idea of an objective risk value for each permission comes from Duo Security's CRXcavator
(2019). It scored every Chrome permission and combined the scores with CSP, external JavaScript,
store metadata and RetireJS findings
([Help Net Security](https://www.helpnetsecurity.com/2019/02/22/should-you-trust-that-chrome-extension/),
[TechTarget](https://www.techtarget.com/searchenterprisedesktop/opinion/You-can-now-see-if-Chrome-extensions-are-safe-with-Duos-free-new-CRXcavator-tool)).
CRXcavator was shut down in 2023. Our weights in `fixtures/permission_weights.json` follow the same
idea. The sentence shown to users for each permission follows Chrome's own permission warnings.

### MITRE ATT&CK mapping (`fixtures/attack_mapping.json`)

Every extension falls under **T1176.001 Software Extensions: Browser Extensions** (tactic
Persistence), <https://attack.mitre.org/techniques/T1176/001/>. The permissions and code findings
of an extension are mapped to what a hostile version could do next:

| Observed | Technique |
| --- | --- |
| `cookies`, code reading cookies | T1539 Steal Web Session Cookie |
| access to every site, `webRequest`, `debugger` | T1185 Browser Session Hijacking |
| `history`, `tabs`, `topSites`, `bookmarks` | T1217 Browser Information Discovery |
| `clipboardRead` | T1115 Clipboard Data |
| `desktopCapture`, `tabCapture` | T1113 Screen Capture |
| `proxy`, code changing the proxy | T1090 Proxy |
| `management`, code disabling extensions | T1562.001 Disable or Modify Tools |
| key listeners in content scripts | T1056.001 Keylogging |
| `eval`, `new Function`, script injection | T1059.007 JavaScript |
| obfuscation, encoded blobs | T1027 Obfuscated Files or Information |
| unrecognised servers, raw IPs | T1041 Exfiltration Over C2 Channel |

## 2. Guard: trusting the code, not the ID

**The problem.** Chrome allowlists work by extension ID, and a new version keeps the same ID. On
24 December 2024 an attacker phished a Cyberhaven employee's Chrome Web Store access and published
version 24.10.4 with code that stole session cookies. Browsers auto-updated it. It was live from
25 December 01:32 UTC to 26 December 02:50 UTC
([Cyberhaven](https://cyberhaven.com/blog/cyberhavens-chrome-extension-security-incident-and-what-were-doing-about-it),
[BleepingComputer](https://www.bleepingcomputer.com/news/security/cybersecurity-firms-chrome-extension-hijacked-to-steal-users-data/)).
Any organisation that had allowlisted the Cyberhaven ID was still trusting it.

**What Guard does (code: `blindspot/guard.py`, `Store._guard_check`).**

1. An approved extension is pinned to its version **and** a SHA-256 hash of all its files.
   Chrome's local `_metadata` folder is excluded from the hash.
2. Every agent report is compared with the pin. Guard looks for new permissions, new sites, new
   optional permissions, new unrecognised servers and a higher OWASP severity.
3. If nothing gained access, the update is approved automatically, with no ticket for IT. If anything
   gained access, the build is **quarantined** until a person approves it. If the code changed but
   the version number did not, the build is also quarantined.
4. A quarantined build loses the approved-ID discount. Its real rating is shown.

**Enforcement.** Chrome's `ExtensionSettings` policy cannot block a single version. Quarantine
therefore blocks the ID fleet-wide until someone reviews it. To stop a hijacked update before it
arrives, pin approved extensions to an internal update server. That uses `installation_mode:
normal_installed` with `update_url` and `override_update_url: true`, which makes Chrome take
updates from the URL in the policy instead of the store
([Google: Configure ExtensionSettings policy](https://support.google.com/chrome/a/answer/9867568)).
`generate_policy(..., mirror_url=...)` produces this configuration.

The `samples/updates/` folder holds a Cyberhaven-shaped test case: Corp SSO Helper 1.0.5 adds
`cookies`, `<all_urls>` and a new server under the approved ID. It is inert.

## 3. Software: CVSS, CISA KEV and SSVC

**Code:** `blindspot/software/assess.py`, `blindspot/software/feeds.py`.
**Live data:** the server pulls it by itself, see "Live feeds" below. `fixtures/advisories.json` holds a
few curated advisories that also work offline.

### Live feeds (server, every 6 hours, or "Check for new CVEs now")

1. **Which programs.** `fixtures/software_watchlist.json` lists about 40 common programs, each with
   a regex for the installed name and its NVD CPE `vendor:product` (for example `7-zip:7-zip`).
   Only programs that are installed somewhere or approved in the catalog are checked.
2. **NVD API 2.0.** For each product the server asks
   `GET services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:<vendor>:<product>`.
   It reads every CVE's CVSS base score and the affected ranges (`versionStartIncluding`,
   `versionEndExcluding` and so on), then compares them with the installed version. The
   `versionEndExcluding` value is the fixed version. Without an API key NVD allows 5 requests per
   30 seconds, so requests are spaced 6.5 s apart.
3. **CISA KEV.** The catalog is downloaded once a day. A CVE listed there counts as actively exploited.
4. **New hits** (a version that was not blocked before) are blocked, logged in the activity feed and
   sent to Telegram. A computer that reports a blocked version for the first time also triggers an
   alert.

| Element | Source |
| --- | --- |
| Severity score | CVSS v3.1 base score as published by NVD (<https://nvd.nist.gov>); the score shown is the highest open CVSS × 10 |
| Actively exploited? | CISA Known Exploited Vulnerabilities catalog (<https://www.cisa.gov/known-exploited-vulnerabilities-catalog>) |
| Decision | CISA Stakeholder-Specific Vulnerability Categorization: Track, Track*, Attend, Act (<https://www.cisa.gov/ssvc>) |
| Remote access tools | MITRE ATT&CK T1219 |

CISA's SSVC tree uses five decision points: exploitation, technical impact, automatable, mission
prevalence and public well-being. We apply a simplified version with the inputs a feed provides:

| Decision | Rule |
| --- | --- |
| Act | active exploitation (in KEV) and total technical impact (C, I and A all High), or a mission-essential product |
| Attend | active exploitation with partial impact, or a public PoC that is automatable with total impact |
| Track* | a public PoC, or total technical impact with no known exploitation |
| Track | everything else |

**Block until patched.** IT approves a package once (`fixtures/software_catalog.json`). If a version
gets an advisory at or above `block_at_decision` (default: Attend), that version is **blocked**, and
installs are allowed again from the fixed version upwards. Nobody has to open a ticket. Example with
real data:

| Date | Event | Blindspot |
| --- | --- | --- |
| 2024-11-30 | 7-Zip 24.08 reviewed and approved | allowed |
| 2025-01-25 | CVE-2025-0411 published: Mark-of-the-Web bypass, CVSS 7.0, fixed in 24.09 ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-0411)) | 24.08 blocked |
| 2025-02-06 | Added to CISA KEV (actively exploited) | decision **Act** |
| any time | 24.09 installed | allowed again |

**Enforcement on Windows.** The AppLocker export (`/api/v1/software-policy.xml`) writes publisher
rules that allow a signed product only from the lowest safe version upwards, for both EXE and MSI
files. It is generated in **AuditOnly** mode and must be merged with `Set-AppLockerPolicy -Merge`.
Unsigned products need hash rules built from the real installer; the XML says how. The JSON export
gives the same decisions to Intune, SCCM or a software portal.

## 4. Honest limits

- Static analysis does not run the code. Remote code loaded at runtime, or heavy obfuscation, can
  hide behaviour.
- Store metadata is a cached file (`fixtures/store_cache.json`). In production it is refreshed by
  `scripts/fetch_store_metadata.py`.
- The advisory feed is a curated file. In production it is fed from NVD, CISA KEV and EPSS.
- Our SSVC rules are a simplification of CISA's tree. Mission prevalence comes from the catalog,
  and public well-being is not modelled.
- Quarantine blocks the extension ID, not one version (a Chrome limitation). Pinning to an internal
  update server avoids this, but it needs the organisation to host approved CRX files.
- The demo fleet, the sample extensions and the crown-jewel hosts are synthetic. The CVEs are real.
