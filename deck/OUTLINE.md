# Hackathon təqdimatı — plan (sahibi: F)

**Format:** PDF, **5–10 dəqiqə** (limiti aşmaq bala təsir edir). Slaydlar İngiliscə.
**Qayda:** münsif vərəqəsindəki 6 meyarın hər birinə **bir slayd**, eyni sırada. Münsif axtarmasın.

| # | Slayd | Rubrika meyarı | Vaxt |
| --- | --- | --- | --- |
| 0 | Title | — | 0:15 |
| 1 | The problem | Overview of the problem and its relevance to cybersecurity | 1:00 |
| 2 | Our solution | Description of the proposed solution and its intended purpose | 0:45 |
| 3 | How it works | Explanation of the conceptual design and system approach | 1:30 |
| 4 | Live demo | Demonstration of prototype / mock-up / PoC | 3:00 |
| 5 | Features, limits, next steps | Key features, limitations, subsequent development steps | 1:00 |
| 6 | Feasibility & impact | Initial assessment of feasibility and potential impact | 1:00 |
| 7 | Team + thank you | — | 0:30 |

Cəmi ≈ 9 dəqiqə. Prova zamanı 8:30-a endirin — canlı demo həmişə gecikir.

---

## 0 · Title
**Project Blindspot** — *See every browser extension on every endpoint, and act on it.*
Komanda adı, tarix, Azerbaijan Cybersecurity Center.

## 1 · The problem  *(meyar 1)*
Başlıq: **Browser extensions are an unmonitored software supply chain.**
- Extensions can read every page you open, your cookies and your sessions.
- They **update themselves silently**; a trusted extension can turn malicious overnight.
- EDR and antivirus do not see them: they are "legitimate" software from an official store.

İki real hadisə (bir cümlə ilə, mənbə slaydın altında):
- **The Great Suspender** (~2 million users): sold to an unknown owner in 2020, Google removed it as malware in February 2021. [BleepingComputer](https://www.bleepingcomputer.com/news/security/the-great-suspender-chrome-extensions-fall-from-grace/), [LWN](https://lwn.net/Articles/846272/)
- **Cyberhaven, December 2024:** a phished developer account pushed a malicious update that reached about 400,000 users automatically and could steal cookies and sessions. [Cyberhaven](https://cyberhaven.com/blog/cyberhavens-chrome-extension-security-incident-and-what-were-doing-about-it), [RH-ISAC](https://rhisac.org/threat-intelligence/cyberhaven-extension-compromise-part-of-broader-campaign-affecting-multiple-chrome-extensions/)

Danışıq: *"Who in this room knows which extensions are installed across their organisation? That gap is our project."*

## 2 · Our solution  *(meyar 2)*
Bank üçün əsas cümlə: *"Group Policy tells you what is allowed. Blindspot tells you whether what is allowed is still safe — and what it can reach."*

**Blindspot inventories, scores, explains and governs browser extensions across corporate endpoints.**
- **Who:** security and IT teams in banks, telecoms, government, any company with 200+ endpoints.
- **Purpose:** turn an invisible risk into a ranked list with clear reasons and a deployable fix.
- Dörd fel: *Inventory → Analyse → Explain → Enforce.*

## 3 · How it works  *(meyar 3)*
- Arxitektura diaqramı: `docs/ARCHITECTURE.md` (və ya hackathon planı sənədindəki sxem).
- Four signals: permissions (35%), static code (30%), network endpoints (20%), store reputation (15%).
- Method: **OWASP Risk Rating** — likelihood (code, network, reputation) × impact (permissions, crown jewels), OWASP severity matrix. Software: **CVSS + CISA KEV + SSVC**. Capabilities → **MITRE ATT&CK T1176.001**. Sources: docs/METHODOLOGY.md.
- Guard slide: *"Allowlists trust the ID. Cyberhaven's hijacked 24.10.4 had the same ID. We pin version + code hash."*
- Privacy by design: analysis runs on the endpoint; only results and hashes leave the machine.
- Output is a **Chrome Enterprise policy** (allowlist / blocklist), not just a list of problems.

## 4 · Live demo  *(meyar 4)*
Ssenari (E ilə birlikdə prova edin; hər addımın kimin dediyi bəlli olsun):
1. Terminal: `python -m blindspot agent --server ...` — real noutbukda canlı skan, "N extensions found".
2. Dashboard: fleet plitələri → risk cədvəli, ən yuxarıdakı extension-a klik.
3. Detal: **"What it can do"** sadə dildə, **"Why this score"** — kod sətri sübut kimi, **naməlum serverlər**. Burada 3 saniyə susun.
4. **Risk report** düyməsi → strukturlaşdırılmış hesabat (tələb 4).
5. **Crown jewels** tabı — **vau anı:** *"Your SWIFT portal can be read by 4 extensions on 4 machines, one of them an AI tool that sends page content to OpenAI."* 3 saniyə susun.
6. **Download containment policy** → JSON faylı açın: *"The AI tool keeps working everywhere — except on SWIFT and core banking. Nothing blocked, nothing exposed."*

**Ehtiyat plan:** internet və ya server sınarsa → `frontend`-i oflayn açın (`python -m http.server`) və ya 60 saniyəlik videonu göstərin. Canlı demoda internetdən asılı heç nə olmasın.

## 5 · Features, limitations, next steps  *(meyar 5)*
**Features:** multi-browser inventory · 4-signal explainable scoring · plain-language report · policy export · offline-capable.

**Limitations** (dürüst yazın — bu, pulsuz baldır):
- Static analysis only: obfuscated or remotely loaded code can hide behaviour.
- Heuristics cause false positives (password managers legitimately need broad access) → approved list.
- No official Chrome Web Store API → reputation data is cached ahead of time.
- Chromium browsers only; no Firefox yet.

**Next steps (capstone):** malicious-update detection by diffing versions · AST/data-flow analysis ·
scheduled agent across many endpoints · policy simulation and approval workflow · software risk scoring.

## 6 · Feasibility & impact  *(meyar 6)*
- **Feasible:** working prototype built in 24 hours; agent needs only Python, no admin installs; uses standard Chrome Enterprise policies that companies already deploy.
- **Impact:** closes a blind spot that EDR does not cover; cuts manual review from hours to minutes per extension; produces evidence auditors can read.
- **Market:** regional banks, telecoms and government agencies that cannot afford global browser-security platforms.

## 7 · Team
Hər üzvün adı + bir sətir töhfə (`deck/CONTRIBUTIONS.md`-dən). *Thank you — questions?*

---

### Gözlənilən suallar (cavabları hazırlayın)
- *"How is this different from just reading the manifest?"* → code, network and reputation signals; explainable score; policy output.
- *"Where does the score come from?"* → OWASP Risk Rating Methodology (likelihood × impact, 0–9 factors, OWASP severity matrix); customisations allowed by OWASP step 6 are listed in docs/METHODOLOGY.md.
- *"Can Chrome block one version?"* → No. Quarantine blocks the ID until review; production pins approved builds to an internal update server (update_url + override_update_url).
- *"What about false positives?"* → evidence per finding, approved list, tunable weights.
- *"Does the agent see user data?"* → no; results and hashes only (slayd 3).
- *"Why not use Google's own admin console?"* → it lists extensions but does not analyse code behaviour or explain risk.
