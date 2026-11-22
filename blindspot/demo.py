"""
Synthetic demo fleet: spreads the sample extensions over five fictional
machines so the fleet dashboard has something realistic to show.

Owner: D. Everything here is synthetic and labelled as such.
"""
from __future__ import annotations

from blindspot.contract import now_iso

# (hostname, os, extensions: "Name" or "Name@version" for a newer build from samples/updates)
DEMO_MACHINES = [
    ("FIN-LAPTOP-07", "Windows 11 Pro 23H2",
     ["Tab Notes", "Coupon Finder Pro", "Quick Translate", "Page Summarizer AI"]),
    ("HR-DESKTOP-02", "Windows 10 Enterprise 22H2",
     ["Dark Mode Everywhere", "Coupon Finder Pro", "Corp SSO Helper", "Page Summarizer AI"]),
    ("DEV-WS-11", "Ubuntu 24.04 LTS",
     ["Weather Now", "Dark Mode Everywhere", "Quick Translate@1.9.1", "Corp SSO Helper"]),
    ("SOC-ANALYST-01", "Windows 11 Enterprise 23H2",
     ["Corp SSO Helper", "Tab Notes"]),
    ("SALES-LAPTOP-15", "macOS 15 Sequoia",
     ["Coupon Finder Pro", "Weather Now", "Tab Notes", "Dark Mode Everywhere", "Page Summarizer AI",
      "Corp SSO Helper@1.0.5"]),
]

DEMO_SOFTWARE = [
    {"name": "Google Chrome", "version": "131.0.6778.86", "publisher": "Google LLC"},
    {"name": "Microsoft Edge", "version": "131.0.2903.70", "publisher": "Microsoft Corporation"},
    {"name": "7-Zip 24.08 (x64)", "version": "24.08", "publisher": "Igor Pavlov"},
    {"name": "Zoom Workplace", "version": "6.2.11", "publisher": "Zoom Video Communications"},
    {"name": "AnyDesk", "version": "8.1.0", "publisher": "AnyDesk Software GmbH"},
    {"name": "Notepad++ (64-bit x64)", "version": "8.6.9", "publisher": "Notepad++ Team"},
]
# per machine index: software to swap in (patched 7-Zip on the SOC machine, an old one in HR)
SOFTWARE_OVERRIDES = {
    1: {"7-Zip 24.08 (x64)": {"name": "7-Zip 24.06 (x64)", "version": "24.06"}},
    3: {"7-Zip 24.08 (x64)": {"name": "7-Zip 24.09 (x64)", "version": "24.09"}},
}


def demo_payloads(results: list[dict], updates: list[dict] | None = None) -> list[dict]:
    """`updates`: analyses of samples/updates (defaults to analysing that folder)."""
    if updates is None:
        from blindspot.contract import REPO_ROOT
        from blindspot.pipeline import analyze_tree
        updates = analyze_tree(REPO_ROOT / "samples" / "updates")
    by_name = {r["name"]: r for r in results}
    by_build = {f"{r['name']}@{r['version']}": r for r in updates}
    payloads = []
    for index, (hostname, os_name, names) in enumerate(DEMO_MACHINES):
        extensions = []
        for name in names:
            source = by_build.get(name) if "@" in name else by_name.get(name)
            if source:
                ext = {k: v for k, v in source.items() if k != "path"}
                ext.update(browser="chrome", profile="Default")
                extensions.append(ext)
        software = []
        for item in DEMO_SOFTWARE:
            if item["name"] == "AnyDesk" and index % 2:
                continue
            if item["name"].startswith("Notepad++") and index not in (2, 3):
                continue
            item = dict(item, **SOFTWARE_OVERRIDES.get(index, {}).get(item["name"], {}))
            software.append(dict(item, source="synthetic"))
        payloads.append({
            "machine": {"machine_id": f"demo-{hostname.lower()}", "hostname": hostname, "os": os_name,
                        "collected_at": now_iso(), "synthetic": True},
            "extensions": extensions,
            "software": software,
        })
    return payloads
