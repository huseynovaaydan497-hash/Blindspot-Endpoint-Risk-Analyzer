"""
Software risk: known vulnerabilities, approval status and the install decision.

Owner: C (scoring) + A (catalog)

Public interface:
    load_catalog(path=None) -> dict
    load_advisories(path=None) -> {"published": [...], "incoming": [...]}
    version_key(text) -> tuple
    ssvc_decision(advisory, mission="support") -> "Act" | "Attend" | "Track*" | "Track"
    assess(item, advisories, catalog) -> assessment dict

Scoring (sources in docs/METHODOLOGY.md):
    score     = highest CVSS v3.1 base score of the open advisories x 10 (NVD), 0 if none
    decision  = CISA SSVC style decision per advisory, worst one wins
    status    = allowed | blocked | review | unreviewed
        blocked     an open advisory at or above the catalog's block_at_decision,
                    or a version below the approved one. Lifted automatically as soon
                    as a fixed version is installed: no ticket, no admin.
        review      not in the catalog AND a remote access tool (MITRE ATT&CK T1219)
        allowed     in the catalog, version approved, no blocking advisory
        unreviewed  everything else (not in the catalog, nothing known against it)
"""
from __future__ import annotations

import json
import re
from functools import lru_cache

from blindspot.contract import FIXTURES

DECISION_RANK = {"Track": 0, "Track*": 1, "Attend": 2, "Act": 3}


def version_key(text) -> tuple:
    """'24.08.00.0' -> (24, 8, 0, 0). Non-numeric parts are ignored."""
    nums = [int(n) for n in re.findall(r"\d+", str(text or ""))]
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()
    return tuple(nums) or (0,)


def version_lt(a, b) -> bool:
    ka, kb = version_key(a), version_key(b)
    width = max(len(ka), len(kb))
    return ka + (0,) * (width - len(ka)) < kb + (0,) * (width - len(kb))


@lru_cache(maxsize=4)
def _read(path: str) -> str:
    try:
        return open(path, encoding="utf-8").read()
    except OSError:
        return "{}"


def load_catalog(path=None) -> dict:
    data = json.loads(_read(str(path or FIXTURES / "software_catalog.json")))
    data.setdefault("approved", [])
    data.setdefault("remote_access_tools", [])
    data.setdefault("block_at_decision", "Attend")
    return data


def load_advisories(path=None) -> dict:
    data = json.loads(_read(str(path or FIXTURES / "advisories.json")))
    return {"published": data.get("published", []), "incoming": data.get("incoming", [])}


def technical_impact(vector: str) -> str:
    """SSVC 'technical impact': total when the attacker gets full control (C, I and A all High)."""
    v = vector or ""
    return "total" if all(f"{m}:H" in v for m in ("C", "I", "A")) else "partial"


def ssvc_decision(advisory: dict, mission: str = "support") -> str:
    """Decision adapted from CISA SSVC (simplified; see docs/METHODOLOGY.md).

    Act     active exploitation (CISA KEV) and total technical impact
    Attend  active exploitation with partial impact, or a public PoC that is
            automatable with total impact, or active exploitation of a mission-essential product
    Track*  public PoC, or total technical impact without known exploitation
    Track   everything else
    """
    exploitation = advisory.get("exploitation") or ("active" if advisory.get("kev") else "none")
    impact = technical_impact(advisory.get("vector", ""))
    automatable = advisory.get("automatable") == "yes"
    if exploitation == "active":
        return "Act" if impact == "total" or mission == "essential" else "Attend"
    if exploitation == "poc" and automatable and impact == "total":
        return "Attend"
    if exploitation == "poc" or impact == "total":
        return "Track*"
    return "Track"


def _matches(pattern: str, name: str) -> bool:
    try:
        return bool(re.search(pattern, name or "", re.I))
    except re.error:
        return False


def describe_range(r: dict) -> str:
    """{'start_incl': '4.0', 'end_excl': '24.09'} -> '>= 4.0 and < 24.09'."""
    if "exact" in r:
        return f"= {r['exact']}"
    parts = [f"{op} {r[k]}" for k, op in (("start_incl", ">="), ("start_excl", ">"),
                                          ("end_incl", "<="), ("end_excl", "<")) if k in r]
    return " and ".join(parts) or "all versions"


def matching_range(version: str, ranges: list[dict]) -> dict | None:
    for r in ranges:
        if in_ranges(version, [r])[0]:
            return r
    return None


def in_ranges(version: str, ranges: list[dict]) -> tuple[bool, str | None]:
    """NVD-style ranges (start/end, including/excluding, or one exact version).
    Returns (affected, fixed version of the matching range)."""
    for r in ranges:
        if "exact" in r:
            if not version_lt(version, r["exact"]) and not version_lt(r["exact"], version):
                return True, None
            continue
        if not any(k in r for k in ("start_incl", "start_excl", "end_incl", "end_excl")):
            # NVD entry without any version bound ("all versions"): mostly old, unmaintained
            # records. Counting them flags the newest releases as vulnerable, so they are ignored.
            continue
        if "start_incl" in r and version_lt(version, r["start_incl"]):
            continue
        if "start_excl" in r and not version_lt(r["start_excl"], version):
            continue
        if "end_excl" in r and not version_lt(version, r["end_excl"]):
            continue
        if "end_incl" in r and version_lt(r["end_incl"], version):
            continue
        return True, r.get("end_excl")
    return False, None


def match_advisory(advisory: dict, name: str, version: str) -> tuple[bool, str | None]:
    if not _matches(advisory.get("match", ""), name):
        return False, None
    if advisory.get("ranges"):
        return in_ranges(version, advisory["ranges"])
    if advisory.get("introduced") and version_lt(version, advisory["introduced"]):
        return False, None
    if advisory.get("fixed") and not version_lt(version, advisory["fixed"]):
        return False, None
    return True, advisory.get("fixed")


def affects(advisory: dict, name: str, version: str) -> bool:
    return match_advisory(advisory, name, version)[0]


def catalog_entry(name: str, catalog: dict) -> dict | None:
    return next((e for e in catalog["approved"] if _matches(e.get("match", ""), name)), None)


def is_remote_access(name: str, catalog: dict) -> bool:
    return any(tool.lower() in (name or "").lower() for tool in catalog["remote_access_tools"])


def assess(item: dict, advisories: list[dict], catalog: dict) -> dict:
    name, version = item.get("name", ""), item.get("version", "")
    entry = catalog_entry(name, catalog)
    mission = (entry or {}).get("mission", "support")
    block_rank = DECISION_RANK.get(catalog.get("block_at_decision", "Attend"), 2)

    open_vulns = []
    for adv in advisories:
        hit, fixed = match_advisory(adv, name, version)
        if hit:
            rng = matching_range(version, adv["ranges"]) if adv.get("ranges") else None
            affected = describe_range(rng) if rng else (
                f"< {adv['fixed']}" if adv.get("fixed") else "listed versions")
            open_vulns.append({
                "affected": affected,
                "cve": adv["cve"], "title": adv.get("title", ""), "cvss": adv.get("cvss"),
                "vector": adv.get("vector", ""), "kev": bool(adv.get("kev")),
                "exploitation": adv.get("exploitation", "none"), "fixed": fixed,
                "source": adv.get("source", "curated"),
                "decision": ssvc_decision(adv, mission), "references": adv.get("references", []),
            })
    open_vulns.sort(key=lambda v: (DECISION_RANK[v["decision"]], v["cvss"] or 0), reverse=True)

    cvss_max = max((v["cvss"] or 0 for v in open_vulns), default=0)
    decision = open_vulns[0]["decision"] if open_vulns else None
    blocking = [v for v in open_vulns if DECISION_RANK[v["decision"]] >= block_rank]
    # the version that lifts the block, and the version that fixes every known CVE
    fixed_in = max((v["fixed"] for v in (blocking or open_vulns) if v["fixed"]), key=version_key, default=None)
    fixes_all = max((v["fixed"] for v in open_vulns if v["fixed"]), key=version_key, default=None)
    remote = is_remote_access(name, catalog)

    reasons = []
    if decision and DECISION_RANK[decision] >= block_rank:
        status = "blocked"
        top = open_vulns[0]
        reasons.append(f"{top['cve']}{' (actively exploited, CISA KEV)' if top['kev'] else ''}"
                       + (f": blocked until {fixed_in} or later is installed" if fixed_in else ""))
        if fixes_all and fixed_in and version_key(fixes_all) > version_key(fixed_in):
            reasons.append(f"{fixes_all} also fixes the {len(open_vulns) - len(blocking)} lower-priority CVE(s)")
    elif entry and entry.get("approved_version") and version_lt(version, entry["approved_version"]):
        status = "blocked"
        reasons.append(f"Older than the approved version {entry['approved_version']}")
    elif entry:
        status = "allowed"
        reasons.append(f"Approved by {entry.get('approved_by', 'IT')}"
                       + (f" on {entry['approved_at']}" if entry.get("approved_at") else ""))
        if open_vulns:
            reasons.append(f"{len(open_vulns)} lower-priority advisory(ies): update when convenient")
    elif remote:
        status = "review"
        reasons.append("Remote access tool not in the catalog (MITRE ATT&CK T1219)")
    else:
        status = "unreviewed"
        reasons.append("Not in the approved catalog; nothing known against this version")

    return {
        "name": name, "version": version, "publisher": item.get("publisher", ""),
        "score": round(cvss_max * 10), "cvss_max": cvss_max, "decision": decision,
        "status": status, "reasons": reasons, "vulnerabilities": open_vulns[:25],
        "vulnerability_count": len(open_vulns), "fixed_in": fixed_in, "fixes_all": fixes_all,
        "approved": bool(entry), "catalog_name": (entry or {}).get("name"),
        "remote_access": remote, "kev": any(v["kev"] for v in open_vulns),
    }
