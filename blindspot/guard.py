"""
Guard: trust the code, not the extension ID.

Owner: B (diff rules) + D (storage)

Why: an allowlist approves an extension by its ID. When a publisher account is
hijacked, the attacker publishes a new version under the SAME ID and Chrome
auto-updates every machine (Cyberhaven, 24-26 December 2024, version 24.10.4).
The allowlist keeps trusting it.

Guard pins each approved extension to the exact version and content hash that was
reviewed. When a machine reports a different build, the two are compared:

    benign update     no new permissions, sites or servers, risk not higher
                      -> approved automatically, no ticket for IT
    risky update      anything new it can reach, or a higher risk severity
                      -> quarantined until a person approves it
    same version,     the code changed without a version bump (tampering or a
    different hash    sideloaded copy) -> quarantined

Public interface:
    snapshot(result) -> dict          the parts of an analysis that a baseline keeps
    diff(base, new) -> dict           what changed between two snapshots
    verdict(d) -> ("auto-approve" | "quarantine", [reasons])
"""
from __future__ import annotations

from blindspot.analyzer.permissions import is_broad_host, weights

SEVERITY_ORDER = ["Note", "Low", "Medium", "High", "Critical"]
RISKY_PERMISSION_POINTS = 8  # same scale as fixtures/permission_weights.json


def snapshot(result: dict) -> dict:
    rating = result.get("rating") or {}
    return {
        "version": result.get("version", ""),
        "content_hash": result.get("content_hash"),
        "permissions": sorted(set(result.get("permissions", []))),
        "hosts": sorted(set(result.get("host_permissions", []) + result.get("content_script_matches", []))),
        "optional": sorted(set(result.get("optional_permissions", []))),
        "servers": sorted({e["host"] for e in result.get("endpoints", []) if not e.get("known")}),
        "severity": rating.get("raw_severity") or rating.get("severity") or "",
        "score": rating.get("raw_score", result.get("score", 0)),
    }


def _rank(severity: str) -> int:
    return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else -1


def diff(base: dict, new: dict) -> dict:
    def added(key):
        return sorted(set(new.get(key, [])) - set(base.get(key, [])))

    return {
        "from_version": base.get("version"), "to_version": new.get("version"),
        "added_permissions": added("permissions"),
        "removed_permissions": sorted(set(base.get("permissions", [])) - set(new.get("permissions", []))),
        "added_hosts": added("hosts"),
        "added_optional": added("optional"),
        "added_servers": added("servers"),
        "severity_before": base.get("severity"), "severity_after": new.get("severity"),
        "score_before": base.get("score"), "score_after": new.get("score"),
        "same_version_new_code": (base.get("version") == new.get("version")
                                  and bool(base.get("content_hash")) and bool(new.get("content_hash"))
                                  and base["content_hash"] != new["content_hash"]),
    }


def verdict(d: dict) -> tuple[str, list[str]]:
    api_weights = weights()["api"]
    unknown = weights()["unknown_api"]
    reasons = []
    risky_perms = [p for p in d["added_permissions"] if api_weights.get(p, unknown) >= RISKY_PERMISSION_POINTS]
    if risky_perms:
        reasons.append("New permission: " + ", ".join(risky_perms))
    broad = [h for h in d["added_hosts"] if is_broad_host(h)]
    if broad:
        reasons.append("Now asks for access to every website")
    elif d["added_hosts"]:
        reasons.append("Can now reach new sites: " + ", ".join(d["added_hosts"][:4]))
    if d["added_optional"]:
        reasons.append("Can ask for more access later: " + ", ".join(d["added_optional"][:4]))
    if d["added_servers"]:
        reasons.append("Talks to new unrecognised servers: " + ", ".join(d["added_servers"][:4]))
    if _rank(d["severity_after"]) > _rank(d["severity_before"]):
        reasons.append(f"Risk rose from {d['severity_before']} to {d['severity_after']}")
    if d["same_version_new_code"]:
        reasons.append("Code changed without a new version number")
    if reasons:
        return "quarantine", reasons
    minor = [p for p in d["added_permissions"]]
    return "auto-approve", ["No new access, servers or risk" + (f" (minor: {', '.join(minor)})" if minor else "")]
