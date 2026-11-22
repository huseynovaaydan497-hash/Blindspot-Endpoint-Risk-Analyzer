"""
Permission risk -- hackathon requirement 2 ("Flag high-risk or excessive permissions").

Owner: B

Public interface:
    analyze_permissions(info) -> signal_result   (info = output of load_manifest)
    capabilities(info) -> [{"permission", "meaning"}]
    describe(permission) -> str                   (plain-language sentence, also for host patterns)
    is_broad_host(pattern) -> bool
"""
from __future__ import annotations

import json
import re
from functools import lru_cache

from blindspot.contract import FIXTURES, finding, severity_for_points, signal_result

BROAD_HOST_RE = re.compile(r"^(?:\*|https?|wss?|ftp|file)://(?:\*|\*\.\*)?(?:/.*)?$")


@lru_cache(maxsize=1)
def weights() -> dict:
    return json.loads((FIXTURES / "permission_weights.json").read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def glossary() -> dict:
    return json.loads((FIXTURES / "permission_glossary.json").read_text(encoding="utf-8"))


def explain(permission: str) -> str:
    return glossary().get(permission, "No plain-language description yet for this permission.")


def describe(permission: str) -> str:
    """Plain-language meaning of an API permission OR a host pattern."""
    if permission == "<all_urls>" or "://" in permission:
        return explain("@broad_host" if is_broad_host(permission) else "@specific_host")
    return explain(permission)


def capabilities(info: dict) -> list[dict]:
    """Everything the extension may do, each with a plain-language sentence."""
    caps = [{"permission": p, "meaning": describe(p)} for p in info.get("host_permissions", [])]
    caps += [{"permission": f"content script: {m}", "meaning": explain("@content_script_broad")}
             for m in info.get("content_script_matches", []) if is_broad_host(m)]
    caps += [{"permission": p, "meaning": describe(p)} for p in info.get("permissions", [])]
    return caps


def is_broad_host(pattern: str) -> bool:
    """True when a match pattern covers every website."""
    pattern = pattern.strip()
    if pattern in ("<all_urls>", "*"):
        return True
    return bool(BROAD_HOST_RE.match(pattern))


def analyze_permissions(info: dict) -> dict:
    w = weights()
    findings: list[dict] = []
    total = 0.0

    api = set(info.get("permissions", []))
    hosts = info.get("host_permissions", [])
    broad_hosts = [h for h in hosts if is_broad_host(h)]
    specific_hosts = [h for h in hosts if not is_broad_host(h)]
    broad_scripts = [m for m in info.get("content_script_matches", []) if is_broad_host(m)]

    # 1. Host access
    if broad_hosts:
        pts = w["host"]["broad"]
        total += pts
        findings.append(
            finding("permission", "high", "Access to every website", explain("@broad_host"),
                    evidence=", ".join(broad_hosts), points=pts)
        )
    elif specific_hosts:
        pts = min(w["host"]["specific_cap"], w["host"]["specific_each"] * len(specific_hosts))
        total += pts
        findings.append(
            finding("permission", severity_for_points(pts), f"Access to {len(specific_hosts)} specific site(s)",
                    explain("@specific_host"), evidence=", ".join(specific_hosts[:6]), points=pts)
        )

    if broad_scripts and not broad_hosts:
        pts = w["content_script_broad"]
        total += pts
        findings.append(
            finding("permission", "medium", "Runs inside every page", explain("@content_script_broad"),
                    evidence=", ".join(broad_scripts), points=pts)
        )

    # 2. API permissions
    minor: list[str] = []
    for perm in sorted(api):
        pts = w["api"].get(perm, w["unknown_api"])
        total += pts
        if pts >= 4:
            findings.append(
                finding("permission", severity_for_points(pts), f"Permission: {perm}", explain(perm),
                        evidence=perm, points=pts)
            )
        else:
            minor.append(perm)
    if minor:
        findings.append(
            finding("permission", "info", f"{len(minor)} low-impact permission(s)",
                    "These permissions carry little risk on their own.", evidence=", ".join(minor),
                    points=0)
        )

    # 3. Optional permissions: can be requested later, so they count partially
    optional = info.get("optional_permissions", [])
    if optional:
        pts = sum(
            (w["host"]["broad"] if is_broad_host(p) else w["api"].get(p, w["unknown_api"]))
            for p in optional
        ) * w["optional_factor"]
        total += pts
        findings.append(
            finding("permission", severity_for_points(pts), "Can ask for more access later",
                    "Declares optional permissions it can request after installation.",
                    evidence=", ".join(optional), points=pts)
        )

    # 4. Dangerous combinations
    present = set(api) | ({"@broad_host"} if (broad_hosts or broad_scripts) else set())
    for combo in w["combos"]:
        if all(req in present for req in combo["requires"]):
            total += combo["points"]
            findings.append(
                finding("permission", combo["severity"], combo["title"], combo["detail"],
                        evidence=" + ".join(r.lstrip("@").replace("_", " ") for r in combo["requires"]),
                        points=combo["points"])
            )

    # 5. Content Security Policy that allows eval
    if any("unsafe-eval" in csp for csp in info.get("content_security_policy", [])):
        pts = w["csp_unsafe_eval"]
        total += pts
        findings.append(
            finding("permission", "medium", "Security policy allows eval", explain("@csp_unsafe_eval"),
                    evidence="content_security_policy: 'unsafe-eval'", points=pts)
        )

    return signal_result(total, findings)


def high_risk_flags(info: dict) -> list[str]:
    """Short list of the high-risk permissions present (used by the report)."""
    flags = []
    if any(is_broad_host(h) for h in info.get("host_permissions", [])) or any(
        is_broad_host(m) for m in info.get("content_script_matches", [])
    ):
        flags.append("broad host access")
    for perm in ("cookies", "webRequest", "webRequestBlocking", "debugger", "nativeMessaging",
                 "proxy", "management", "clipboardRead", "history", "scripting"):
        if perm in info.get("permissions", []):
            flags.append(perm)
    return flags
