"""
End-to-end checks. These are the merge gate: a pull request is merged only when
`python -m pytest` passes. If you change behaviour on purpose, update the test
in the same pull request and say why.
"""
from __future__ import annotations

import json
from datetime import date

import pytest

from blindspot.analyzer import codescan, manifest, network, permissions, reputation, score
from blindspot.contract import REPO_ROOT, SIGNALS, level_for
from blindspot.pipeline import analyze_extension, analyze_tree, discover_extensions
from blindspot.policy.policy import generate_policy, render_windows_reg
from blindspot.report.report import build_report, render_html

SAMPLES = REPO_ROOT / "samples" / "extensions"
TODAY = date(2026, 11, 20)


@pytest.fixture(scope="module")
def results():
    return {r["name"]: r for r in analyze_tree(SAMPLES, now=TODAY)}


def sample_dir(name, results):
    return results[name]["path"]


# ---------------------------------------------------------------- requirement 1: parsing

def test_discovers_all_samples():
    assert len(discover_extensions(SAMPLES)) == 7


def test_manifest_resolves_localised_name(results):
    assert "Tab Notes" in results


def test_manifest_with_comments_and_mv2_host_split(results):
    info = manifest.load_manifest(sample_dir("Weather Now", results))
    assert info["manifest_version"] == 2
    assert "<all_urls>" in info["host_permissions"]
    assert "<all_urls>" not in info["permissions"]


def test_strip_comments_keeps_urls():
    text = '{"u": "https://example.com/x" // comment\n}'
    assert json.loads(manifest.strip_json_comments(text)) == {"u": "https://example.com/x"}


# ---------------------------------------------------------------- requirement 2: flagging

@pytest.mark.parametrize("pattern,broad", [
    ("<all_urls>", True), ("*://*/*", True), ("https://*/*", True),
    ("https://*.google.com/*", False), ("http://localhost/*", False),
])
def test_broad_host_detection(pattern, broad):
    assert permissions.is_broad_host(pattern) is broad


def test_flags_brief_permissions(results):
    flags = results["Coupon Finder Pro"]["high_risk_permissions"]
    assert {"broad host access", "cookies", "webRequest"} <= set(flags)


def test_every_capability_has_plain_language(results):
    for r in results.values():
        for cap in r["capabilities"]:
            assert cap["meaning"] and "No plain-language" not in cap["meaning"], cap


# ---------------------------------------------------------------- requirement 3: scoring

def test_levels_of_samples(results):
    assert results["Weather Now"]["level"] == "high"
    assert results["Coupon Finder Pro"]["level"] == "high"
    assert results["Dark Mode Everywhere"]["level"] == "medium"
    assert results["Tab Notes"]["level"] == "low"
    assert results["Quick Translate"]["level"] == "low"


def test_known_good_is_allowed(results):
    r = results["Corp SSO Helper"]
    assert r["known_good"] and r["recommendation"] == "allow"


def test_score_is_explainable(results):
    for r in results.values():
        assert 0 <= r["score"] <= 100
        assert set(r["signals"]) == set(SIGNALS)
        if r["level"] != "low":
            assert r["findings"], f"{r['name']} has a score but no reasons"


def test_unavailable_signal_is_excluded():
    # Behaviour changed on purpose (OWASP rating): an unavailable signal is left out,
    # and when NO likelihood factor could be measured, likelihood is "unknown" = 4.5, not 0.
    signals = {"permission": {"score": 50, "available": True},
               "reputation": {"score": 0, "available": False}}
    rating = score.rate(signals)
    assert "reputation" not in rating["factors"]["likelihood"]
    assert rating["likelihood"] == 4.5 and rating["likelihood_unknown"]


@pytest.mark.parametrize("impact,likelihood,severity", [
    ("HIGH", "LOW", "Medium"), ("HIGH", "MEDIUM", "High"), ("HIGH", "HIGH", "Critical"),
    ("MEDIUM", "LOW", "Low"), ("MEDIUM", "MEDIUM", "Medium"), ("MEDIUM", "HIGH", "High"),
    ("LOW", "LOW", "Note"), ("LOW", "MEDIUM", "Low"), ("LOW", "HIGH", "Medium"),
])
def test_owasp_severity_matrix(impact, likelihood, severity):
    assert score.SEVERITY_MATRIX[impact][likelihood] == severity


def test_owasp_bands_match_levels():
    assert score.band(2.9) == "LOW" and score.band(3) == "MEDIUM" and score.band(6) == "HIGH"
    # severity bands line up with the block / review / allow levels
    for severity, (low, high) in score.SEVERITY_BANDS.items():
        expected = {"Critical": "high", "High": "high", "Medium": "medium"}.get(severity, "low")
        assert level_for(low) == expected and level_for(high) == expected


def test_removed_from_store_is_critical(results):
    rating = results["Weather Now"]["rating"]
    assert rating["severity"] == "Critical" and rating["factors"]["likelihood"]["reputation"] >= 8


def test_attack_mapping(results):
    ids = {t["id"] for t in results["Coupon Finder Pro"]["attack"]}
    assert {"T1176.001", "T1539", "T1185"} <= ids


def test_content_hash_changes_with_code(tmp_path):
    from blindspot.pipeline import content_hash
    (tmp_path / "manifest.json").write_text('{"manifest_version": 3, "name": "t", "version": "1"}')
    (tmp_path / "a.js").write_text("console.log(1)")
    first = content_hash(tmp_path)
    (tmp_path / "_metadata").mkdir()
    (tmp_path / "_metadata" / "computed_hashes.json").write_text("{}")
    assert content_hash(tmp_path) == first  # Chrome's local metadata is ignored
    (tmp_path / "a.js").write_text("console.log(2)")
    assert content_hash(tmp_path) != first


def test_level_thresholds():
    assert level_for(70) == "high" and level_for(35) == "medium" and level_for(34) == "low"


# ---------------------------------------------------------------- signals C owns

def test_code_scan_finds_inert_patterns(results):
    found = score_titles(codescan.scan_code(sample_dir("Weather Now", results)))
    assert any("eval" in t for t in found) and any("Obfuscated" in t for t in found)


def test_network_flags_unknown_servers(results):
    sig = network.extract_endpoints(sample_dir("Coupon Finder Pro", results))
    hosts = {e["host"] for e in sig["endpoints"] if not e["known"]}
    assert "api.coupon-sync.invalid" in hosts and "203.0.113.27" in hosts


def test_reputation_removed_from_store(results):
    sig = reputation.check_reputation(results["Weather Now"]["id"], now=TODAY)
    assert sig["available"] and sig["score"] >= 45


def test_broken_module_does_not_stop_pipeline(results, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("half-finished module")
    monkeypatch.setattr(codescan, "scan_code", boom)
    r = analyze_extension(sample_dir("Coupon Finder Pro", results), now=TODAY)
    assert r["signals"]["code"]["available"] is False and r["level"] == "high"


# ---------------------------------------------------------------- requirement 4: report

def test_report_structure_and_html(results):
    report = build_report(list(results.values()))
    assert report["summary"]["extensions_analyzed"] == 7
    assert report["summary"]["by_level"] == {"high": 2, "medium": 2, "low": 3}
    assert report["summary"]["by_recommendation"] == {"block": 2, "contain": 2, "review": 0, "allow": 3}
    assert next(c for c in report["crown_jewels"] if c["system"] == "SWIFT portal")["extensions"]
    assert report["top_risks"][0]["level"] == "high"
    html = render_html(report)
    assert "Executive summary" in html and "Weather Now" in html
    json.dumps(report)  # must be serialisable


# ---------------------------------------------------------------- bonus: policy

def test_policy_blocks_high_and_allows_known_good(results):
    policy = generate_policy(list(results.values()), default_deny=True)
    chrome = policy["chrome_policy"]
    assert results["Weather Now"]["id"] in chrome["ExtensionInstallBlocklist"]
    assert chrome["ExtensionInstallBlocklist"][0] == "*"
    assert results["Corp SSO Helper"]["id"] in chrome["ExtensionInstallAllowlist"]
    assert "ExtensionInstallBlocklist" in render_windows_reg(chrome)


def score_titles(signal):
    return [f["title"] for f in signal["findings"]]


def test_entropy_rule_ignores_minified_code_but_finds_keys(tmp_path):
    (tmp_path / "manifest.json").write_text('{"manifest_version": 3, "name": "t", "version": "1"}')
    (tmp_path / "a.js").write_text(
        'var f=a.split(".");a=1===f.length;var g=f[0];g=!a&&g in e.polyfills?e.polyfills:e.glob;k.x="x";\n'
        'var Z="\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00";\n')
    assert not codescan.scan_code(tmp_path)["findings"]
    (tmp_path / "b.js").write_text('const KEY = "AIzaSyD3x9Qv7Lk2mPz8Rt5Wc1Hn4Bj6Yf0Ue2Ga";\n')
    assert any("Random-looking" in f["title"] for f in codescan.scan_code(tmp_path)["findings"])


def test_approved_extension_explains_itself_first(results):
    assert results["Corp SSO Helper"]["findings"][0]["title"] == "On the organisation's approved list"



# ---------------------------------------------------------------- crown jewels, Shadow AI, containment

from blindspot.analyzer import exposure  # noqa: E402


@pytest.mark.parametrize("ext,target,covered", [
    ("*", "corebanking.bank.local", True),
    ("*.bank.local", "swift.bank.local", True),
    ("*.bank.local", "*.bank.local", True),
    ("swift.bank.local", "*.bank.local", True),       # partial access to the zone is still access
    ("*.google.com", "swift.bank.local", False),
    ("swift.bank.local", "hr.bank.local", False),
])
def test_host_covers(ext, target, covered):
    assert exposure.host_covers(ext, target) is covered


def test_exposure_via_host_and_content_script(results):
    systems = [{"name": "SWIFT", "hosts": ["*://swift.bank.local"]}]
    assert exposure.exposure({"host_permissions": ["<all_urls>"]}, systems)[0]["via"] == "host permission"
    assert exposure.exposure({"content_script_matches": ["https://*/*"]}, systems)[0]["via"] == "content script"
    assert exposure.exposure({"host_permissions": ["https://*.google.com/*"]}, systems) == []
    assert results["Quick Translate"]["exposure"] == []


def test_shadow_ai_detected(results):
    r = results["Page Summarizer AI"]
    assert r["ai"]["is_ai"] and "api.openai.com" in r["ai"]["services"]
    assert any(f["title"] == "Can send page content to AI services" for f in r["findings"])
    assert not results["Quick Translate"]["ai"]["is_ai"]  # googleapis translate is not an AI provider


def test_containment_policy(results):
    policy = generate_policy(list(results.values()), protect_all=True)
    settings = policy["chrome_policy"]["ExtensionSettings"]
    ai_id = results["Page Summarizer AI"]["id"]
    assert results["Page Summarizer AI"]["recommendation"] == "contain"
    assert "*://swift.bank.local" in settings[ai_id]["runtime_blocked_hosts"]
    assert all("/" not in h.split("://", 1)[1] for h in settings[ai_id]["runtime_blocked_hosts"])  # no paths
    assert "*://corebanking.bank.local" in settings["*"]["runtime_blocked_hosts"]
    assert settings[results["Weather Now"]["id"]]["installation_mode"] == "blocked"


def test_reg_file_covers_chrome_and_edge_with_valid_json(results):
    reg = render_windows_reg(generate_policy(list(results.values()))["chrome_policy"])
    assert "Policies\\Google\\Chrome" in reg and "Policies\\Microsoft\\Edge" in reg
    line = next(x for x in reg.split("\r\n") if x.startswith('"ExtensionSettings"='))
    raw = line.split("=", 1)[1][1:-1].replace('\\"', '"').replace("\\\\", "\\")
    assert "runtime_blocked_hosts" in json.loads(raw)[results["Page Summarizer AI"]["id"]]
