"""Store (stdlib) tests always run; API tests run when FastAPI is installed."""
from __future__ import annotations

import pytest

from blindspot.contract import REPO_ROOT
from blindspot.demo import demo_payloads
from blindspot.pipeline import analyze_tree
from blindspot.policy.policy import generate_policy
from blindspot.software.assess import load_catalog
from blindspot.store import PayloadError
from blindspot.store import Store as _Store

SAMPLES = REPO_ROOT / "samples" / "extensions"
EXAMPLE_CATALOG = load_catalog(REPO_ROOT / "fixtures" / "software_catalog.example.json")


def Store(path=":memory:", **kwargs):  # noqa: N802 -- the demo fleet expects the example catalog
    kwargs.setdefault("catalog", EXAMPLE_CATALOG)
    return _Store(path, **kwargs)


@pytest.fixture()
def store():
    s = Store(":memory:")
    for payload in demo_payloads(analyze_tree(SAMPLES)):
        s.ingest(payload)
    return s


def test_fleet_summary(store):
    summary = store.summary()
    assert summary["machines"] == 5
    assert summary["unique_extensions"] == 7
    # 5: the hijacked Corp SSO Helper 1.0.5 (samples/updates) reaches every site
    assert summary["ai_extensions"] == 1 and summary["crown_jewel_exposed"] == 5
    assert summary["by_level"]["high"] == 3  # the quarantined 1.0.5 build loses the approved-ID cap


def test_extension_detail_has_installs(store):
    top = store.extensions()[0]
    detail = store.extension(top["id"])
    assert detail["installs"] and detail["findings"]


def test_store_exposure(store):
    swift = next(c for c in store.exposure() if c["system"] == "SWIFT portal")
    assert swift["extension_count"] == 5 and swift["machine_count"] == 4 and swift["ai_count"] == 1
    assert "SOC-ANALYST-01" not in swift["machines"]  # it runs Corp SSO Helper 1.0.4, which cannot
    sso = next(e for e in swift["extensions"] if e["name"] == "Corp SSO Helper")
    assert sso["machines"] == ["SALES-LAPTOP-15"]   # only the machine with the hijacked build


def test_reingest_replaces_machine(store):
    payload = demo_payloads(analyze_tree(SAMPLES))[0]
    payload["extensions"] = []
    store.ingest(payload)
    assert next(m for m in store.machines() if m["hostname"] == "FIN-LAPTOP-07")["extensions"] == 0


def test_rejects_bad_payload(store):
    with pytest.raises(PayloadError):
        store.ingest({"extensions": []})


def test_api_end_to_end(monkeypatch, tmp_path):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    monkeypatch.setenv("BLINDSPOT_DB", str(tmp_path / "test.db"))
    monkeypatch.setenv("BLINDSPOT_FEEDS", "off")  # no network in tests
    import importlib

    import backend.main as main
    importlib.reload(main)
    from fastapi.testclient import TestClient

    client = TestClient(main.app)
    assert client.get("/api/v1/health").json()["status"] == "ok"
    for payload in demo_payloads(analyze_tree(SAMPLES)):
        assert client.post("/api/v1/inventory", json=payload).status_code == 200
    assert client.post("/api/v1/inventory", json={"bad": 1}).status_code == 422
    exts = client.get("/api/v1/extensions").json()
    assert len(exts) == 7
    swift = next(c for c in client.get("/api/v1/exposure").json() if c["system"] == "SWIFT portal")
    assert swift["extension_count"] == 5 and swift["ai_count"] == 1
    assert "*" in client.get("/api/v1/policy.json?protect_all=true").json()["chrome_policy"]["ExtensionSettings"]
    assert client.get(f"/api/v1/extensions/{exts[0]['id']}").status_code == 200
    assert client.get("/api/v1/extensions/doesnotexist").status_code == 404
    assert "Executive summary" in client.get("/api/v1/report.html").text
    assert client.get("/api/v1/policy.json").json()["decisions"]["block"]
    assert client.get("/").status_code == 200
    # machine drill-down, software, guard
    assert client.get("/api/v1/machines/SALES-LAPTOP-15").json()["extensions"]
    assert client.get("/api/v1/machines/nope").status_code == 404
    assert client.get("/api/v1/guard").json()["extensions"][0]["state"] == "quarantined"
    assert client.post("/api/v1/guard/advisories/sync").json()["added"] == ["CVE-2025-0411"]
    sw = client.get("/api/v1/software").json()
    assert next(x for x in sw if x["version"] == "24.08")["status"] == "blocked"
    assert "AppLockerPolicy" in client.get("/api/v1/software-policy.xml").text
    assert client.post("/api/v1/guard/extensions/jfgjnbepeobbehklgokacfpkpebahoma/approve?version=1.0.5").status_code == 200
    assert client.get("/api/v1/guard").json()["extensions"][0]["state"] != "quarantined"
    assert client.post("/api/v1/guard/extensions/nope/approve").status_code == 404
    assert client.get("/api/v1/agent.zip?server=http://10.0.0.5:8000").headers["content-type"] == "application/zip"
    assert client.get("/api/v1/agent.zip?server=bad value").status_code == 422
    assert "suggested" in client.get("/api/v1/server-info").json()
    assert client.post("/api/v1/software/approve", json={"name": "AnyDesk", "version": "8.1.0"}).json()["name"] == "AnyDesk"
    assert next(x for x in client.get("/api/v1/software").json() if x["name"] == "AnyDesk")["status"] == "allowed"
    assert "tracked" in client.get("/api/v1/software/feeds").json()["nvd"]
    client.post("/api/v1/admin/clear")
    assert client.get("/api/v1/fleet/summary").json()["machines"] == 0


# ---------------------------------------------------------------- Guard: trust the code, not the ID

SSO = "jfgjnbepeobbehklgokacfpkpebahoma"
TRANSLATE = "apkpogiehjchcpanckkkamkjkknfeifm"


def test_guard_pins_approved_extensions(store):
    g = {e["id"]: e for e in store.guard()["extensions"]}
    assert g[TRANSLATE]["state"] == "pinned" and g[SSO]["baseline_version"] == "1.0.4"
    assert g[SSO]["baseline_hash"]


def test_guard_auto_approves_benign_update(store):
    g = {e["id"]: e for e in store.guard()["extensions"]}
    assert "1.9.1" in g[TRANSLATE]["approved_versions"]
    assert any(ev["kind"] == "auto-approved" for ev in store.guard()["events"])


def test_guard_quarantines_hijacked_update_with_same_id(store):
    ext = next(e for e in store.extensions() if e["id"] == SSO)
    assert ext["known_good"]                      # the ID is on the allowlist ...
    assert ext["recommendation"] == "quarantine"  # ... and Guard still stops the new build
    q = store.guard()["extensions"][0]
    assert q["id"] == SSO and q["state"] == "quarantined"
    reasons = " ".join(q["quarantine"][0]["reasons"])
    assert "cookies" in reasons and "every website" in reasons and "sso-config-sync.invalid" in reasons
    soc = next(m for m in store.machines() if m["hostname"] == "SOC-ANALYST-01")
    assert soc["quarantined"] == 0                # SOC still runs the approved 1.0.4


def test_quarantine_goes_into_policy(store):
    policy = generate_policy(store.results())
    assert SSO in policy["chrome_policy"]["ExtensionInstallBlocklist"]
    assert policy["decisions"]["quarantine"][0]["id"] == SSO
    pinned = generate_policy(store.results(), mirror_url="https://ext.bank.local")
    assert pinned["chrome_policy"]["ExtensionSettings"][TRANSLATE]["override_update_url"] is True


def test_approving_releases_quarantine(store):
    store.approve_extension(SSO, "1.0.5", by="test")
    assert next(e for e in store.extensions() if e["id"] == SSO)["recommendation"] != "quarantine"


def test_same_version_different_code_is_quarantined():
    from blindspot import guard
    base = {"version": "1.0", "content_hash": "aaa", "permissions": [], "hosts": [], "servers": [],
            "severity": "Low", "score": 10}
    decision, reasons = guard.verdict(guard.diff(base, dict(base, content_hash="bbb")))
    assert decision == "quarantine" and "without a new version" in reasons[0]


# ---------------------------------------------------------------- software: CVE -> block until patched

def test_software_blocked_when_cve_arrives_and_released_by_patch(store):
    def status(version):
        return next(s for s in store.software() if s["catalog_name"] == "7-Zip" and s["version"] == version)

    assert status("24.08")["status"] == "allowed"
    result = store.sync_advisories()
    assert result["added"] == ["CVE-2025-0411"]
    s = status("24.08")
    assert s["status"] == "blocked" and s["decision"] == "Act" and s["kev"] and s["score"] == 70
    assert status("24.09")["status"] == "allowed"     # the patched build stays allowed
    assert store.guard()["catalog"][0]["allowed_from"] == "24.09"
    assert any(ev["kind"] == "advisory" for ev in store.guard()["events"])
    store.reset_advisories()
    assert status("24.08")["status"] == "allowed"


def test_remote_access_tool_needs_review(store):
    assert next(s for s in store.software() if s["name"] == "AnyDesk")["status"] == "review"


def test_machine_detail(store):
    m = store.machine("SALES-LAPTOP-15")
    assert {e["name"] for e in m["extensions"]} >= {"Corp SSO Helper", "Weather Now"}
    assert m["extensions"][0]["quarantined"] and m["software"]
    assert store.machine("does-not-exist") is None


@pytest.mark.parametrize("advisory,decision", [
    ({"kev": True, "vector": "C:H/I:H/A:H"}, "Act"),
    ({"exploitation": "active", "vector": "C:L/I:H/A:N"}, "Attend"),
    ({"exploitation": "poc", "automatable": "yes", "vector": "C:H/I:H/A:H"}, "Attend"),
    ({"exploitation": "poc", "vector": "C:L/I:L/A:N"}, "Track*"),
    ({"exploitation": "none", "vector": "C:H/I:H/A:H"}, "Track*"),
    ({"exploitation": "none", "vector": "C:L/I:N/A:N"}, "Track"),
])
def test_ssvc_decisions(advisory, decision):
    from blindspot.software.assess import ssvc_decision
    assert ssvc_decision(advisory) == decision


def test_version_compare():
    from blindspot.software.assess import version_lt
    assert version_lt("24.08.00.0", "24.09") and not version_lt("24.09", "24.09.0") and version_lt("9.9", "24.07")


# ---------------------------------------------------------------- adding computers, clearing data

def test_clear_removes_fleet_but_keeps_feed(store):
    store.clear()
    assert store.summary()["machines"] == 0 and store.extensions() == [] and store.software() == []
    assert store.advisories()  # the advisory feed is configuration, not fleet data


def test_agent_zip_contains_runner_with_server_address():
    import io
    import zipfile

    from blindspot.agent_bundle import build_agent_zip
    data = build_agent_zip("http://192.168.20.19:8000/")
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = zf.namelist()
        assert "blindspot-agent/blindspot/__main__.py" in names
        assert "blindspot-agent/fixtures/permission_weights.json" in names
        assert not any(n.endswith("seed.json") for n in names)
        assert "http://192.168.20.19:8000" in zf.read("blindspot-agent/run_agent.bat").decode()
    with pytest.raises(ValueError):
        build_agent_zip("http://evil & calc.exe")


def test_agent_zip_runs_standalone(tmp_path):
    import io
    import subprocess
    import sys
    import zipfile

    from blindspot.agent_bundle import build_agent_zip
    zipfile.ZipFile(io.BytesIO(build_agent_zip("http://127.0.0.1:9"))).extractall(tmp_path)
    out = tmp_path / "inv.json"
    proc = subprocess.run([sys.executable, "-m", "blindspot", "agent", "--no-software", "--out", str(out)],
                          cwd=tmp_path / "blindspot-agent", capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert out.is_file()


# ---------------------------------------------------------------- own-computer drift test, unpacked discovery

def test_test_extension_hijack_is_quarantined(tmp_path):
    from blindspot.pipeline import analyze_extension
    from blindspot.testext import CLEAN, HIJACKED, write
    ext_id = "a" * 32
    s = Store(":memory:")
    machine = {"machine_id": "m1", "hostname": "MY-LAPTOP"}
    write(CLEAN, tmp_path)
    first = s.ingest({"machine": machine, "extensions": [analyze_extension(tmp_path, ext_id=ext_id)]})
    assert first["guard"][0]["action"] == "pinned"            # every extension is watched from day one
    write(HIJACKED, tmp_path)
    second = s.ingest({"machine": machine, "extensions": [analyze_extension(tmp_path, ext_id=ext_id)]})
    hit = second["guard"][0]
    assert hit["action"] == "quarantined"
    assert any("cookies" in r for r in hit["reasons"]) and any("every website" in r for r in hit["reasons"])


def test_unpacked_extensions_found_in_preferences(tmp_path, monkeypatch):
    import json

    from blindspot.collector import extensions as ex
    ext_dir = tmp_path / "my-ext"
    ext_dir.mkdir()
    (ext_dir / "manifest.json").write_text('{"manifest_version": 3, "name": "x", "version": "1"}')
    profile = tmp_path / "User Data" / "Default"
    profile.mkdir(parents=True)
    (profile / "Secure Preferences").write_text(json.dumps({"extensions": {"settings": {
        "b" * 32: {"location": 4, "path": str(ext_dir)},
        "c" * 32: {"location": 1, "path": "ignored"}}}}))
    monkeypatch.setattr(ex, "user_data_dirs", lambda: [("chrome", tmp_path / "User Data")])
    found = ex.find_installed_extensions()
    assert [(f["id"], f["source"]) for f in found] == [("b" * 32, "unpacked")]


# ---------------------------------------------------------------- alerts

def test_alerts_quarantine_and_high_risk_and_cve():
    captured = []
    s = Store(":memory:")
    s.alert_sink = captured.extend
    for payload in demo_payloads(analyze_tree(SAMPLES)):
        s.ingest(payload)
    kinds = [a["kind"] for a in captured]
    assert "quarantine" in kinds and "high_risk" in kinds
    q = next(a for a in captured if a["kind"] == "quarantine")
    assert "1.0.5" in q["subject"] and "SALES-LAPTOP-15" in q["detail"]
    # High-risk alert only on first sight, not on every report
    before = len(captured)
    s.ingest(demo_payloads(analyze_tree(SAMPLES))[0])
    assert not [a for a in captured[before:] if a["kind"] == "high_risk"]
    s.sync_advisories()
    assert captured[-1]["kind"] == "advisory" and "CVE-2025-0411" in captured[-1]["subject"]


def test_alert_kinds_can_be_switched_off():
    captured = []
    s = Store(":memory:")
    s.alert_sink = captured.extend
    s.save_alert_settings(kinds=["quarantine"])
    for payload in demo_payloads(analyze_tree(SAMPLES)):
        s.ingest(payload)
    assert {a["kind"] for a in captured} == {"quarantine"}


def test_alert_settings_mask_token():
    s = Store(":memory:")
    s.save_alert_settings(token="123456789:AAEabcdefghijklmnop", chat_id="42", chat_name="SOC")
    shown = s.alert_settings()
    assert shown["telegram"]["configured"] and "abcdefghijk" not in shown["telegram"]["token"]
    assert s.telegram_config().chat_id == "42"


def test_telegram_message_and_send(monkeypatch):
    import json as _json

    from blindspot import alerts
    sent = {}

    class Resp:
        def __init__(self, body): self.body = body
        def read(self): return _json.dumps(self.body).encode()
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout=0):
        sent["url"], sent["body"] = req.full_url, _json.loads(req.data)
        if req.full_url.endswith("getUpdates"):
            return Resp({"ok": True, "result": [{"message": {"chat": {"id": 42, "first_name": "Nijat"}}}]})
        return Resp({"ok": True, "result": {}})

    monkeypatch.setattr(alerts.urllib.request, "urlopen", fake_urlopen)
    text = alerts.format_alerts([{"kind": "quarantine", "subject": "X <1.1>", "detail": "on PC"}], "http://10.0.0.5:8000")
    assert "<b>Blindspot: Extension quarantined</b>" in text and "X &lt;1.1&gt;" in text and "#guard" in text
    alerts.send_telegram(alerts.TelegramConfig("T", "42"), text)
    assert sent["url"].endswith("/botT/sendMessage") and sent["body"]["chat_id"] == "42"
    assert alerts.find_chats("T") == [{"chat_id": "42", "name": "Nijat"}]


def test_concurrent_reads_and_writes_do_not_break(store):
    """Regression: the dashboard fires several requests at once; FastAPI serves them on
    worker threads that share one SQLite connection."""
    import threading
    errors = []
    payloads = demo_payloads(analyze_tree(SAMPLES))

    def reader():
        try:
            for _ in range(15):
                store.summary(); store.extensions(); store.machines(); store.software(); store.guard()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    def writer():
        try:
            for p in payloads * 3:
                store.ingest(p)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(6)] + [threading.Thread(target=writer)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []


def test_telegram_errors_are_explained(monkeypatch):
    import io
    import urllib.error

    from blindspot import alerts

    def bad_token(req, timeout=0):
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b'{"ok":false,"description":"Not Found"}'))
    monkeypatch.setattr(alerts.urllib.request, "urlopen", bad_token)
    with pytest.raises(alerts.AlertError, match="bot token"):
        alerts.find_chats("wrong")

    def offline(req, timeout=0):
        raise urllib.error.URLError("getaddrinfo failed")
    monkeypatch.setattr(alerts.urllib.request, "urlopen", offline)
    with pytest.raises(alerts.AlertError, match="hotspot"):
        alerts.find_chats("t")


def test_critical_test_extension_alerts_on_first_sight(tmp_path):
    from blindspot.pipeline import analyze_extension
    from blindspot.testext import CRITICAL, write
    captured = []
    s = Store(":memory:")
    s.alert_sink = captured.extend
    write(CRITICAL, tmp_path)
    ext = analyze_extension(tmp_path, ext_id="d" * 32)
    assert ext["rating"]["severity"] == "Critical"
    s.ingest({"machine": {"machine_id": "m", "hostname": "PC-1"}, "extensions": [ext]})
    assert [a["kind"] for a in captured] == ["high_risk"] and "Critical" in captured[0]["subject"]
    s.ingest({"machine": {"machine_id": "m", "hostname": "PC-1"}, "extensions": [ext]})
    assert len(captured) == 1  # not repeated on every report


def test_alert_when_same_build_becomes_high_risk():
    captured = []
    s = Store(":memory:")
    s.alert_sink = captured.extend
    clean = {"id": "e" * 32, "name": "Helper", "version": "2.0", "score": 5, "level": "low",
             "findings": [], "rating": {"severity": "Low", "raw_severity": "Low", "raw_score": 5}}
    s.ingest({"machine": {"machine_id": "m", "hostname": "PC-1"}, "extensions": [clean]})
    removed = dict(clean, score=90, level="high",
                   findings=[{"severity": "critical", "title": "Removed from the Chrome Web Store", "signal": "reputation"}],
                   rating={"severity": "Critical", "raw_severity": "Critical", "raw_score": 90})
    s.ingest({"machine": {"machine_id": "m", "hostname": "PC-1"}, "extensions": [removed]})
    assert captured and captured[-1]["kind"] == "high_risk" and "Low to Critical" in captured[-1]["detail"]
