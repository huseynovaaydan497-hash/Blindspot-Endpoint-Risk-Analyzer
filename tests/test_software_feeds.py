"""Live software vulnerability feeds (NVD + CISA KEV), with the network replaced by fixtures."""
from __future__ import annotations

from blindspot.software import feeds
from blindspot.software.assess import in_ranges
from blindspot.store import Store

NVD_7ZIP = {
    "resultsPerPage": 2, "startIndex": 0, "totalResults": 2,
    "vulnerabilities": [
        {"cve": {
            "id": "CVE-2025-0411", "published": "2025-01-25T05:15:09.000", "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "7-Zip Mark-of-the-Web Bypass Vulnerability. More text."}],
            "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
                "baseScore": 7.0, "vectorString": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"}}]},
            "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
                {"vulnerable": True, "criteria": "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*", "versionEndExcluding": "24.09"}]}]}],
        }},
        {"cve": {
            "id": "CVE-2016-2335", "published": "2016-12-13T00:00:00.000", "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "Old 7-Zip bug."}],
            "metrics": {"cvssMetricV30": [{"type": "Primary", "cvssData": {
                "baseScore": 7.8, "vectorString": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"}}]},
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": True, "criteria": "cpe:2.3:a:7-zip:7-zip:16.00:*:*:*:*:*:*:*"},
                {"vulnerable": False, "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}]}]}],
        }},
    ],
}
KEV = {"vulnerabilities": [{"cveID": "CVE-2025-0411", "dateAdded": "2025-02-06"}]}


def fake_get(calls):
    def get(url, headers=None):
        calls.append(url)
        if url == feeds.KEV_URL:
            return KEV
        if "7-zip%3A7-zip" in url:
            return NVD_7ZIP
        return {"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []}
    return get


def test_parse_nvd_ranges_and_scores():
    entry = {"name": "7-Zip", "match": r"^7-Zip\b", "cpe": ["7-zip:7-zip"]}
    advs = {a["cve"]: a for a in feeds.parse_nvd([NVD_7ZIP], entry)}
    assert advs["CVE-2025-0411"]["cvss"] == 7.0 and advs["CVE-2025-0411"]["ranges"] == [{"end_excl": "24.09"}]
    assert advs["CVE-2016-2335"]["ranges"] == [{"exact": "16.00"}]  # the Windows cpe is not vulnerable, skipped
    assert advs["CVE-2025-0411"]["title"] == "7-Zip Mark-of-the-Web Bypass Vulnerability."


def test_in_ranges():
    assert in_ranges("24.08", [{"end_excl": "24.09"}]) == (True, "24.09")
    assert in_ranges("24.09", [{"end_excl": "24.09"}])[0] is False
    assert in_ranges("16.00", [{"exact": "16.0"}])[0] is True
    assert in_ranges("5.0", [{"start_incl": "4.0", "end_incl": "5.0"}])[0] is True
    assert in_ranges("3.9", [{"start_incl": "4.0", "end_incl": "5.0"}])[0] is False


def machine(software):
    return {"machine": {"machine_id": "m1", "hostname": "PC-1"}, "extensions": [], "software": software}


def test_refresh_blocks_vulnerable_version_and_alerts():
    captured, calls = [], []
    s = Store(":memory:", catalog={"approved": [], "remote_access_tools": [], "block_at_decision": "Attend"},
              advisories={"published": [], "incoming": []})
    s.alert_sink = captured.extend
    s.ingest(machine([{"name": "7-Zip 24.08 (x64)", "version": "24.08", "publisher": "Igor Pavlov"},
                      {"name": "7-Zip 24.09 (x64)", "version": "24.09"}]))
    assert s.feeds_missing()
    assert {x["status"] for x in s.software()} == {"unreviewed"}

    status = s.refresh_feeds(get=fake_get(calls), sleep=lambda _: None)
    assert status["kev"]["count"] == 1 and status["nvd"]["products"] == 1 and not status["running"]
    old = next(x for x in s.software() if x["version"] == "24.08")
    assert old["status"] == "blocked" and old["decision"] == "Act" and old["kev"] and old["fixed_in"] == "24.09"
    assert old["vulnerabilities"][0]["source"] == "nvd"
    assert next(x for x in s.software() if x["version"] == "24.09")["status"] == "unreviewed"
    assert captured and captured[-1]["kind"] == "advisory" and "7-Zip 24.08" in captured[-1]["subject"]
    assert not s.feeds_missing()
    # second refresh uses the cache: no new NVD calls
    n = len(calls)
    s.refresh_feeds(get=fake_get(calls), sleep=lambda _: None)
    assert len(calls) == n


def test_new_machine_installing_blocked_version_alerts():
    captured = []
    s = Store(":memory:", catalog={"approved": [], "remote_access_tools": [], "block_at_decision": "Attend"},
              advisories={"published": [], "incoming": []})
    s.refresh_feeds(get=fake_get([]), sleep=lambda _: None)  # nothing installed yet: only KEV
    s.ingest(machine([{"name": "7-Zip 24.08 (x64)", "version": "24.08"}]))
    s.refresh_feeds(get=fake_get([]), sleep=lambda _: None)
    s.alert_sink = captured.extend
    s.ingest({"machine": {"machine_id": "m2", "hostname": "NEW-PC"}, "extensions": [],
              "software": [{"name": "7-Zip 24.08 (x64)", "version": "24.08"}]})
    assert captured and "NEW-PC" in captured[0]["subject"]


def test_approve_from_dashboard():
    s = Store(":memory:", catalog={"approved": [], "remote_access_tools": [], "block_at_decision": "Attend"},
              advisories={"published": [], "incoming": []})
    s.ingest(machine([{"name": "Notepad++ (64-bit x64)", "version": "8.6.9"}]))
    assert s.software()[0]["status"] == "unreviewed"
    entry = s.approve_software("Notepad++ (64-bit x64)", "8.6.9")
    assert entry["name"] == "Notepad++"
    assert s.software()[0]["status"] == "allowed"
    assert s.unapprove_software("Notepad++") and s.software()[0]["status"] == "unreviewed"


def test_product_name():
    assert Store.product_name("7-Zip 24.08 (x64)") == "7-Zip"
    assert Store.product_name("Notepad++ (64-bit x64)") == "Notepad++"
    assert Store.product_name("Mozilla Firefox (x64 en-US)") == "Mozilla Firefox"
    assert Store.product_name("Google Chrome") == "Google Chrome"


def test_watchlist_is_valid():
    wl = feeds.load_watchlist()
    assert len(wl) > 30 and all(w["cpe"] and ":" in w["cpe"][0] for w in wl)


def test_unbounded_nvd_range_is_ignored():
    assert in_ranges("152.0.4", [{}]) == (False, None)
    assert in_ranges("152.0.4", [{}, {"end_excl": "153.0"}]) == (True, "153.0")


def test_summary_skips_product_blurb():
    text = ("7-Zip is a file archiver with a high compression ratio. Prior to version 25.00, the handling of "
            "symbolic links in ZIP files allows writing outside the target folder. This is fixed in 25.00.")
    assert feeds.summary(text).startswith("Prior to version 25.00")
    assert feeds.summary("7-Zip Mark-of-the-Web Bypass Vulnerability. More.") == "7-Zip Mark-of-the-Web Bypass Vulnerability."


def test_block_reason_names_the_blocking_fix():
    from blindspot.software.assess import assess
    advs = [
        {"cve": "CVE-A", "match": r"^7-Zip\b", "ranges": [{"end_excl": "24.09"}], "cvss": 7.0,
         "vector": "C:H/I:H/A:H", "kev": True, "exploitation": "active"},
        {"cve": "CVE-B", "match": r"^7-Zip\b", "ranges": [{"end_excl": "26.03"}], "cvss": 8.8,
         "vector": "C:H/I:H/A:N", "exploitation": "none"},
    ]
    a = assess({"name": "7-Zip 24.08 (x64)", "version": "24.08"}, advs,
               {"approved": [], "remote_access_tools": [], "block_at_decision": "Attend"})
    assert a["status"] == "blocked" and a["fixed_in"] == "24.09" and a["fixes_all"] == "26.03"
    assert "until 24.09" in a["reasons"][0] and "26.03" in a["reasons"][1]
