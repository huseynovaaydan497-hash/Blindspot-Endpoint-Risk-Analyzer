# Tapşırıqlar — 6 nəfər, 24 saat

**Başlanğıc nöqtəsi:** dörd məcburi tələbin hamısı artıq işləyən əsas versiyada repodadır və
testlərlə yoxlanılır (`python -m pytest -q`). Sizin işiniz sıfırdan yazmaq deyil:

1. **MUST** — tələbləri real datada möhkəmləndirmək, demo üçün hazırlamaq və **öz modulunu
   tam başa düşmək**. Capstone-da "Contribution" fərdi qiymətləndirilir: hər kəs öz hissəsini
   İngiliscə izah edə bilməlidir.
2. **BONUS** — yalnız H13 dondurmasından sonra, ya da MUST bitəndən sonra.

Hər tapşırıq üçün qayda eynidir: öz branch-ında işlə → test → kiçik PR → D birləşdirir
([CONTRIBUTING.md](../CONTRIBUTING.md)).

Hər kəs H18-ə qədər `deck/CONTRIBUTIONS.md` faylına öz bölməsini yazsın: nə qurdu (3 cümlə, İngiliscə).

---

## A — Kollektor · `blindspot/collector/`

**Hazırdır:** Chrome / Edge / Brave / Chromium-da extension-ların tapılması (Windows, macOS, Linux),
yerli proqram inventarı, agent əmri (`python -m blindspot agent`), serverə göndərmə.

**MUST**
- [ ] Agenti öz noutbukunda və ən azı bir başqa OS-da işlət: `python -m blindspot agent --out inventory.json`. Yol problemlərini düzəlt.
- [ ] Windows-da proqram inventarının (registry) işlədiyini yoxla.
- [ ] Komandanın brauzerlərindən **15–20 real extension** topla və `samples/real/` qovluğuna `Extensions/<id>/<version>/` quruluşu ilə kopyala. Bu, demonun əsas datasıdır (git-ə düşmür).
- [ ] Demo üçün: H18-də 2–3 komanda noutbukunda agenti eyni serverə qarşı işlət ki, fleet ekranı real olsun.

**BONUS**
- [ ] `Secure Preferences` faylından quraşdırma mənbəyi: store-dan, yoxsa sideload (sideload = qırmızı bayraq).
- [ ] Riskli proqramlar siyahısı (uzaq idarəetmə alətləri və s.) → software üçün sadə bayraq.
- [ ] Firefox (`extensions.json` + `.xpi`).

**Yoxla:** `python -m blindspot agent --no-software`

---

## B — İcazə və skor · `analyzer/manifest.py`, `permissions.py`, `score.py` · **tələb 1, 2, 3**

**Hazırdır:** MV2/MV3 parser (şərhlər, `__MSG_` adlar), çəki cədvəli, təhlükəli kombinasiyalar,
`unsafe-eval` CSP, birləşmiş skor düsturu, təsdiqlənmiş extension-lar üçün tavan.

**MUST**
- [ ] `samples/real` üzərində işlət: `python -m blindspot scan samples/real`. Skorlar ağlabatandırmı?
- [ ] `fixtures/permission_weights.json`-u kalibrlə. Məşhur parol meneceri səbəbsiz "high" olmamalıdır.
- [ ] `fixtures/known_good.json`-a 10–20 real təsdiqlənmiş extension əlavə et.
- [ ] Skor düsturunu bir slaydda izah etməyi hazırla (F ilə). Testlər yaşıl qalmalıdır.
- [ ] **H8 yoxlaması:** real datada skor və bayraqlar işləyir.

**BONUS**
- [ ] **Zərərli yeniləmə aşkarlanması** (capstone-un əsas mövzusu): `analyzer/diff.py` — eyni extension-ın iki versiyasını müqayisə et; yeni icazə, yeni host, yeni naməlum server → finding.
- [ ] Siyasət hədlərini (block / review) panel üçün parametr kimi açmaq (D ilə).

**Yoxla:** `python -m pytest -q -k "manifest or flag or level or score or known_good"`

---

## C — Kod, şəbəkə, reputasiya · `analyzer/codescan.py`, `network.py`, `reputation.py`

**Hazırdır:** 14 kod qaydası + base64 / hex / entropiya, kitabxana fayllarında yarım çəki,
URL çıxarılması, tanınmış domenlər siyahısı, oflayn store reputasiyası.

**MUST**
- [ ] `samples/real` üzərində yanlış pozitivləri azalt; `fixtures/known_domains.json`-u genişləndir.
- [ ] Demo extension-ları üçün real store datası: `python scripts/fetch_store_metadata.py --from-folder samples/real`. Səhifə dəyişibsə, regex-ləri düzəlt; alınmayan sahələri əl ilə doldur.
- [ ] Hər qaydanın nəyi tutduğunu və niyə təhlükəli olduğunu bir cümlə ilə izah edə bil.

**BONUS**
- [ ] AST təhlili (`esprima` və ya `tree-sitter`): təhlükəli çağırış həqiqətən icra olunurmu, yoxsa ölü koddur?
- [ ] Uzaqdan kod yükləmə zənciri: `fetch` → `eval` / `new Function`.
- [ ] Data axını: cookie oxunub şəbəkəyə gedirmi?

**Yoxla:** `python -m pytest -q -k "code or network or reputation"`

---

## D — API, inteqrasiya, hesabat · **tələb 4** · repo sahibi

**Hazırdır:** contract, pipeline, SQLite store, CLI, JSON + HTML hesabat, siyasət generatoru,
FastAPI server, testlər, GitHub Actions CI.

**MUST**
- [ ] H0: repo, dəvətlər (komanda + `@diemarx` + `marcos.f@cyberpro-ai.com`), branch qoruması, linki portala yazmaq.
- [ ] Serveri işə sal (`uvicorn backend.main:app --reload --host 0.0.0.0`), `python -m blindspot demo-fleet --server http://localhost:8000`, bütün endpoint-ləri `/docs`-da yoxla.
- [ ] PR-ları birləşdir, `main` həmişə yaşıl qalsın. H13 dondurmasını sən elan edirsən.
- [ ] Hesabatın "Executive summary" mətnini F ilə birlikdə oxu və cilala; "Recommendations" bölməsi əlavə et.

**BONUS**
- [ ] `/api/v1/inventory` üçün API açarı (header) — təhlükəsizlik sualına cavab.
- [ ] `Dockerfile` + `docker compose up` — Phase 4 deployment tələbi.
- [ ] Siyasət simulyasiyası: "bu siyasət neçə quraşdırmanı bloklayacaq?"

**Yoxla:** `python -m pytest -q` (hamısı)

---

## E — Frontend · `frontend/`

**Hazırdır:** fleet plitələri, risk cədvəli, filtr, detal paneli (sadə dildə icazələr, səbəblər, sübut,
naməlum serverlər), maşınlar və proqram tabları, hesabat linki, siyasət ixracı. Panel yalnız
serverdəki real datanı göstərir, hər 10 saniyədən bir yenilənir.

**MUST**
- [ ] Boş serverdən başla (`start_server.bat`), "Add a computer" ilə 2–3 komanda kompüterini qoş və hər ekranı real datada yoxla.
- [ ] Proyektor üçün cilala: şrift ölçüsü, uzun "Why this score" siyahısında ilk 5 + "Show all", boş vəziyyətlər.
- [ ] Demo ssenarisindəki klik axınını hamarla (`deck/OUTLINE.md`, slayd 4).
- [ ] H18–20: F üçün ekran görüntüləri.

**BONUS**
- [ ] **Siyasət ekranı:** allow / review / block sütunları, hədd sürgüsü, default-deny açarı, JSON önizləmə.
- [ ] Səviyyə paylanması üçün kiçik diaqram.

**Yoxla:** brauzerdə konsolda xəta olmamalıdır.

---

## F — Təqdimat · `deck/` · **münsif balının 83%-i**

**Hazırdır:** `deck/OUTLINE.md` — rubrikaya bir-bir uyğun 6 slayd və demo ssenarisi.

**MUST**
- [ ] H1–H12: slayd 1, 2, 3, 5, 6. Slayd 4 (demo) sonda.
- [ ] Hər kəsdən `deck/CONTRIBUTIONS.md` üçün 3 cümlə yığ.
- [ ] H18–H20: E-dən ekran görüntüləri, slayd 4, **PDF ixracı**.
- [ ] H20–H23: 3 prova, xronometrlə. **Maksimum 10 dəqiqə.**
- [ ] H23: PDF portala yüklənir.

**BONUS**
- [ ] Canlı demo sınarsa, ehtiyat üçün 60 saniyəlik demo videosu (ekran yazısı).
- [ ] Münsiflər üçün 1 səhifəlik xülasə.

---

## Yeni (v4.1): Guard, OWASP skoru, software skoru, yeni interfeys

Hamı öz bölməsini oxusun: [docs/METHODOLOGY.md](METHODOLOGY.md). Münsif "bu rəqəm haradandır?"
soruşanda cavab oradadır.

- **B:** `analyzer/score.py` (OWASP L × I), `guard.py` (drift qaydaları). Matrisi və "Guard ID-yə yox, koda güvənir" fikrini ingiliscə izah etməyi məşq et.
- **C:** `software/assess.py` (CVSS, KEV, SSVC), `fixtures/advisories.json`. BONUS: CISA KEV JSON-dan avtomatik yeniləmə.
- **A:** `--every` rejimini real Windows-da sına. `fixtures/software_catalog.json`-a 3–5 real proqram əlavə et (registry-dəki DisplayName ilə uyğunlaşdır).
- **D:** yeni endpoint-lər: `/api/v1/machines/{id}`, `/api/v1/guard`, `/api/v1/guard/advisories/sync`, `/api/v1/software-policy.xml`. CI-də API testi yaşıl olmalıdır.
- **E:** interfeys yenidir (`frontend/`). Real datada uzun adlar və 50+ extension ilə yoxla.
- **F:** demo ssenarisi aşağıdadır.

### Demo ssenarisi (3 dəqiqə)

1. **Extensions:** Weather Now → bir cümləlik hökm, OWASP matrisi, "Installed on".
2. **Corp SSO Helper:** ID-si allowlist-dədir, amma 1.0.5 karantindədir. "Cyberhaven-da allowlist bunu buraxdı, biz buraxmırıq."
3. **Guard:** fərqlər (+cookies, +bütün saytlar, +yeni server). Quick Translate isə avtomatik təsdiqlənib, IT-yə ticket getməyib.
4. **Guard → Sync advisory feed:** CVE-2025-0411 gəlir, 7-Zip 24.08 3 maşında bloklanır, 24.09 icazəli qalır.
5. **Enforce:** Chrome policy və AppLocker faylını endir, göstər.
6. CVE hissəsini təkrarlamaq üçün **Reset feed** bas. Hər şeyi sıfırlamaq üçün **Add a computer → Clear all data** bas, sonra agentləri yenidən işlət.

Qeyd: panel yalnız agentlərin real göndərdiyi datanı göstərir. Guard ssenarisini (2-3) real göstərmək üçün
`fixtures/known_good.json`-a komandanın kompüterlərindəki real bir extension ID-sini əlavə edin.

### Telegram alert (v4.4)

Saytda **Alerts** bölməsi: @BotFather → `/newbot` → token-i yapışdır → bota "hi" yaz → **Find my chat** → **Save and send a test message**.
Alert bu hallarda gəlir: extension karantinə düşəndə, yeni CVE proqramı bloklayanda, ilk dəfə High/Critical extension görünəndə.
Demo: `py -m blindspot test-extension hijack` → Chrome-da ↻ → agent → telefona mesaj gəlir. Hər `hijack` yeni versiya yazır, demo təkrarlana bilər.

### Software: canlı NVD + CISA KEV (v4.7)

Server hər 6 saatdan bir quraşdırılmış proqramları NVD-də yoxlayır və CISA KEV-dən aktiv istismar olunan CVE-ləri götürür.
Software səhifəsində **Check for new CVEs now** düyməsi var. Proqrama klik edib **Approve this version** ilə təsdiqləyin.
**C:** `fixtures/software_watchlist.json`-a komandanın kompüterlərində olan, amma siyahıda olmayan proqramları əlavə et
(CPE-ni https://nvd.nist.gov/products/cpe/search-dən tap).
