"""
Reputation signal from Chrome Web Store metadata.

Owner: C (A helps with the fetcher)

Public interface:
    check_reputation(ext_id, cache=None, now=None) -> signal_result

Works OFFLINE from fixtures/store_cache.json so the demo never depends on
conference wifi. scripts/fetch_store_metadata.py fills that cache before the
demo. When an extension has no cached entry the signal is marked unavailable
and is left out of the composite score (it does not count as "safe").
"""
from __future__ import annotations

import json
from datetime import date, datetime, timezone

from blindspot.contract import FIXTURES, finding, signal_result

ABANDONED_DAYS = 730
LOW_USERS = 1000
POINTS_REMOVED = 45
POINTS_ABANDONED = 25
POINTS_LOW_USERS = 15
POINTS_NO_PUBLISHER = 5


def load_cache(path=None) -> dict:
    path = path or FIXTURES / "store_cache.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data.get("extensions", {})


def check_reputation(ext_id: str, cache: dict | None = None, now: date | None = None) -> dict:
    cache = load_cache() if cache is None else cache
    entry = cache.get(ext_id)
    if not entry:
        return signal_result(0, [finding("reputation", "info", "No store data",
                                         "No Chrome Web Store information is cached for this extension.",
                                         evidence=ext_id)], available=False)

    today = now or datetime.now(timezone.utc).date()
    findings = []
    total = 0.0

    if entry.get("in_store") is False:
        total += POINTS_REMOVED
        findings.append(finding("reputation", "critical", "Removed from the Chrome Web Store",
                                "The store no longer lists it, which often follows a malware report, "
                                "yet it is still installed here.", evidence="in_store: false",
                                points=POINTS_REMOVED))

    updated = entry.get("last_updated")
    if updated:
        try:
            age = (today - date.fromisoformat(updated[:10])).days
        except ValueError:
            age = None
        if age is not None and age > ABANDONED_DAYS:
            total += POINTS_ABANDONED
            findings.append(finding("reputation", "medium", "Not updated for over two years",
                                    "Abandoned extensions are often sold to new owners who push "
                                    "malicious updates.", evidence=f"last_updated: {updated} ({age} days)",
                                    points=POINTS_ABANDONED))

    users = entry.get("users")
    if isinstance(users, int) and users < LOW_USERS:
        total += POINTS_LOW_USERS
        findings.append(finding("reputation", "low", "Very few users",
                                "Fewer users means less scrutiny from the community.",
                                evidence=f"users: {users}", points=POINTS_LOW_USERS))

    if not entry.get("publisher"):
        total += POINTS_NO_PUBLISHER
        findings.append(finding("reputation", "low", "Unknown publisher",
                                "The store shows no identifiable publisher.", evidence="publisher: none",
                                points=POINTS_NO_PUBLISHER))

    if not findings:
        findings.append(finding("reputation", "info", "Healthy store profile",
                                "Listed, maintained and widely used.",
                                evidence=f"users: {users}, last_updated: {updated}", points=0))

    return signal_result(total, findings, store=entry)
