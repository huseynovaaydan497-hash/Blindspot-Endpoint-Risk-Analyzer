# Komanda iş qaydası — 6 nəfər, 6 kompüter, 1 repo

Hər kəs öz kompüterində işləyir. Hamının işi GitHub-dakı **bir repoda** birləşir.
Birləşmə problemsiz keçir, çünki üç şey əvvəlcədən həll olunub:

1. **Hər kəsin öz qovluğu/faylları var.** İki nəfər eyni faylı redaktə etmir → konflikt olmur.
2. **Modullar arasındakı interfeys sabitdir** (`blindspot/contract.py`, `docs/API_CONTRACT.md`).
   Sənin modulun içini istədiyin kimi dəyiş, amma funksiyanın adı, parametrləri və qaytardığı
   formanı dəyişmə. Belə olanda başqasının kodu sənin dəyişikliyindən sınmır.
3. **Pipeline ilk dəqiqədən uçdan-uca işləyir.** Hamı sıfırdan yox, işləyən versiyanı
   yaxşılaşdırır. Kiminsə modulu yarımçıq qalsa və ya xəta atsa, `pipeline.py` həmin siqnalı
   "n/a" edir, qalan hissə işləməyə davam edir — demo heç vaxt tam sınmır.

## Kim nəyin sahibidir

| Rol | Sahib olduğu fayllar |
| --- | --- |
| **A** — Kollektor | `blindspot/collector/` |
| **B** — İcazə və skor | `blindspot/analyzer/manifest.py`, `permissions.py`, `score.py`, `fixtures/permission_*.json`, `fixtures/known_good.json` |
| **C** — Kod və şəbəkə | `blindspot/analyzer/codescan.py`, `network.py`, `reputation.py`, `fixtures/known_domains.json`, `fixtures/store_cache.json`, `scripts/` |
| **D** — API, inteqrasiya, hesabat | `blindspot/contract.py`, `pipeline.py`, `store.py`, `demo.py`, `__main__.py`, `blindspot/report/`, `blindspot/policy/`, `backend/`, `tests/` |
| **E** — Frontend | `frontend/` |
| **F** — Təqdimat | `deck/`, `docs/` (README-ni D ilə birlikdə) |

Başqasının faylında səhv görsən: düzəltmə, **sahibinə yaz**. Kiçik bir şeydirsə, o özü 2 dəqiqəyə düzəldər.

---

## Birinci saat (H0–H1) — bir dəfə edilir

### D (repo sahibi)

1. GitHub-da **private** repo yarat: `blindspot`.
2. Bu qovluğun içindəkiləri yüklə:
   ```bash
   cd blindspot
   git init -b main          # artıq git repodursa, bu addımı ötür
   git add .
   git commit -m "Initial skeleton: working end-to-end pipeline"
   git remote add origin https://github.com/<user>/blindspot.git
   git push -u origin main
   ```
3. **Settings → Collaborators**: 5 komanda yoldaşını **Write** icazəsi ilə dəvət et.
4. Müəllimləri **Read** icazəsi ilə dəvət et: `@diemarx` (Marcos Feliciano) və
   `marcos.f@cyberpro-ai.com`. Repo linkini portala yaz. **Bu məcburidir.**
5. **Settings → Branches → Add rule** `main` üçün: "Require a pull request before merging" və
   "Require status checks to pass" (`tests`). Bundan sonra `main`-ə birbaşa push mümkün olmur.

### Hər kəs (A–F)

```bash
git clone https://github.com/<user>/blindspot.git
cd blindspot
python -m venv .venv
# Windows: .venv\Scripts\activate      macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q                      # hamısı yaşıl olmalıdır
python -m blindspot scan samples/extensions
git checkout -b a-collector              # öz branch-ın: a-collector, b-scoring, c-codescan, d-api, e-frontend, f-deck
```

Git terminalı ilə rahat deyilsənsə: **GitHub Desktop** quraşdır. Clone, branch, commit,
push və Pull Request hamısı düymə ilə edilir.

---

## Gün ərzində iş dövrü (hər 1–2 saatdan bir)

```bash
# 1. İşlə, sonra yoxla
python -m pytest -q

# 2. Yadda saxla
git add <öz faylların>
git commit -m "Score: add combo rule for cookies + broad host"     # nə etdiyini yaz, "fix" yox

# 3. main-dəki yenilikləri öz branch-ına al (başqalarının birləşdirdiyi işlər)
git fetch origin
git merge origin/main

# 4. Yenə test, sonra göndər
python -m pytest -q
git push -u origin <branch-adın>
```

Sonra GitHub-da **Pull Request** aç: `<branch-adın>` → `main`. Testlər avtomatik işləyir (yaşıl ✓
görünməlidir). **D** baxır və birləşdirir. Birləşəndən sonra eyni branch-da işləməyə davam et.

### Qızıl qaydalar

- **Kiçik və tez-tez.** 6 saat sonra bir böyük PR yox — hər 1–2 saatdan bir kiçik PR.
  Kiçik PR-ı birləşdirmək 1 dəqiqədir, böyüyü 1 saat.
- **Testlər yaşıl olmadan PR açma.** Qəsdən davranışı dəyişirsənsə, testi də eyni PR-da yenilə
  və PR təsvirində səbəbini yaz.
- **`contract.py` və `docs/API_CONTRACT.md` yalnız D-nin PR-ı ilə dəyişir.** Yeni sahə lazımdırsa,
  D-yə yaz. Yeni **opsional** sahə əlavə etmək olar; ad dəyişmək və silmək olmaz.
- **Sirr commit etmə:** parol, token, `.env`, real şirkət datası. `.gitignore` artıq qoruyur.
- **Real extension-ları** `samples/real/` qovluğuna qoy — git onu görmür, repoya düşmür.

---

## Sinxronizasiya nöqtələri

Hər 4 saatdan bir **5 dəqiqə, ayaqüstü**, eyni qaydada: nə birləşdi, nə bloklayır, kimə kömək lazımdır.

| Saat | Nə olmalıdır |
| --- | --- |
| **H5** | Hər kəsin ən azı bir PR-ı `main`-ə birləşib. B-nin parser + bayraqları işləyir. |
| **H8** | **Kritik yoxlama:** B-nin skorlaması işləyir. İşləmirsə, D dayanıb B ilə cütləşir. |
| **H13** | **Dondurma:** 4 məcburi tələb `main`-də işləyir, CI yaşıldır. Bu nöqtədən sonra hər şey bonusdur. |
| **H20** | **Kod dondurulur.** Yalnız bug fix. Demo `main`-dən işləyir. |

---

## Problem olanda

**`git merge origin/main` konflikt verdi.** Bu, adətən iki nəfərin eyni faylı dəyişdiyi deməkdir.
Faylı aç, `<<<<<<<` və `>>>>>>>` arasındakı hissəni seç, sonra:
```bash
git add <fayl> && git commit
```
Əmin deyilsənsə, D-yə yaz — tək başına təxmin etmə.

**Testlər `main`-də sındı.** D həmin PR-ı geri qaytarır (`git revert`), sahibi düzəldib yenidən göndərir.
`main` həmişə işləyən vəziyyətdə qalmalıdır.

**Kiminsə modulu hazır deyil, mən onu gözləyirəm.** Gözləmə. `fixtures/seed.json` və mövcud
işləyən versiya ilə davam et — interfeys sabitdir, onun yeni versiyası gələndə sənin kodun dəyişmədən işləyəcək.
