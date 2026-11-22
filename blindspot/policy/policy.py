"""
Policy generator: allow / contain / review / block.

Owners: B + D

Public interface:
    generate_policy(results, block_at=None, review_at=None, default_deny=False,
                    contain=True, protect_all=False, systems=None) -> dict
    render_windows_reg(chrome_policy, browsers=("chrome", "edge")) -> str

Decisions
    quarantine  Guard found a version that differs from the approved build (new access,
                new servers, higher risk). Chrome cannot block a single version, so the
                extension ID is blocked fleet-wide until a person approves the new build.
                With `mirror_url`, approved extensions are also pinned to an internal update
                server (normal_installed + update_url + override_update_url), so a hijacked
                store update never reaches the machines in the first place.
    block    score >= block_at and not approved -> extension is blocked and removed
    contain  can reach a crown-jewel system      -> keeps working everywhere EXCEPT those hosts
    review   score >= review_at                  -> a person should look at it
    allow    everything else, and approved extensions without crown-jewel access

Containment uses the ExtensionSettings field `runtime_blocked_hosts`, which Chrome
and Edge both support: the extension cannot inject scripts, see or change web
requests, or read cookies on those hosts. Host format: no path, e.g. *://*.bank.local
(at most 100 entries per extension).

`protect_all` also puts every crown-jewel host under "*", so extensions that are
installed tomorrow, and that Blindspot has never seen, are kept off them too.

Output `chrome_policy` is the managed-policy format:
  * Linux: /etc/opt/chrome/policies/managed/blindspot.json
  * Windows: the .reg file from render_windows_reg (Chrome and Edge), or Group Policy
"""
from __future__ import annotations

import json

from blindspot.analyzer.exposure import load_crown_jewels
from blindspot.contract import LEVEL_THRESHOLDS, now_iso

MAX_RUNTIME_HOSTS = 100
REG_BASES = {
    "chrome": r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome",
    "edge": r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge",
}


def _hosts_for(systems_hit: list[dict]) -> list[str]:
    hosts = sorted({h for s in systems_hit for h in s["hosts"]})
    return hosts[:MAX_RUNTIME_HOSTS]


def generate_policy(results: list[dict], block_at: int | None = None, review_at: int | None = None,
                    default_deny: bool = False, contain: bool = True, protect_all: bool = False,
                    systems: list[dict] | None = None, mirror_url: str | None = None) -> dict:
    block_at = LEVEL_THRESHOLDS["high"] if block_at is None else block_at
    review_at = LEVEL_THRESHOLDS["medium"] if review_at is None else review_at
    systems = load_crown_jewels() if systems is None else systems

    decisions: dict[str, list] = {"allow": [], "contain": [], "review": [], "block": [], "quarantine": []}
    for r in sorted(results, key=lambda x: x["score"], reverse=True):
        exposed = r.get("exposure") or []
        quarantined = (r.get("guard") or {}).get("quarantined") or []
        if quarantined:
            bucket = "quarantine"
        elif not r.get("known_good") and r["score"] >= block_at:
            bucket = "block"
        elif contain and exposed:
            bucket = "contain"
        elif not r.get("known_good") and r["score"] >= review_at:
            bucket = "review"
        else:
            bucket = "allow"
        reason = r["findings"][0]["title"] if r.get("findings") else ""
        if quarantined:
            reason = f"version {quarantined[0]['version']}: " + "; ".join(quarantined[0]["reasons"])
        decisions[bucket].append({
            "id": r["id"], "name": r["name"], "score": r["score"], "reason": reason,
            "ai": bool((r.get("ai") or {}).get("is_ai")),
            "protected_systems": [e["system"] for e in exposed] if bucket == "contain" else [],
        })

    settings: dict = {}
    if protect_all and systems:
        settings["*"] = {"runtime_blocked_hosts": _hosts_for(systems)}
    for d in decisions["block"]:
        settings[d["id"]] = {
            "installation_mode": "blocked",
            "blocked_install_message": f"Blocked by Blindspot (risk {d['score']}): {d['reason']}"[:200],
        }
    for d in decisions["quarantine"]:
        settings[d["id"]] = {
            "installation_mode": "blocked",
            "blocked_install_message": f"Quarantined by Blindspot Guard: {d['reason']}"[:200],
        }
    if mirror_url:
        for r in results:
            if (r.get("guard") or {}).get("pinned") and r["id"] not in settings:
                settings[r["id"]] = {"installation_mode": "normal_installed",
                                     "update_url": mirror_url.rstrip("/") + f"/{r['id']}/updates.xml",
                                     "override_update_url": True}
    by_id = {r["id"]: r for r in results}
    for d in decisions["contain"]:
        settings[d["id"]] = {"runtime_blocked_hosts": _hosts_for(by_id[d["id"]]["exposure"])}

    chrome_policy: dict = {
        "ExtensionInstallBlocklist": (["*"] if default_deny else [])
        + [d["id"] for bucket in ("block", "quarantine") for d in decisions[bucket]],
        "ExtensionSettings": settings,
    }
    if default_deny:
        # With "*" in the blocklist only allowlisted extensions can be installed.
        chrome_policy["ExtensionInstallAllowlist"] = [
            d["id"] for bucket in ("allow", "contain") for d in decisions[bucket]]

    return {
        "generated_at": now_iso(),
        "mode": "default-deny" if default_deny else "blocklist-only",
        "thresholds": {"block_at": block_at, "review_at": review_at},
        "crown_jewels": [s["name"] for s in systems],
        "decisions": decisions,
        "chrome_policy": chrome_policy,
    }


def _reg_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def render_windows_reg(chrome_policy: dict, browsers=("chrome", "edge")) -> str:
    """Windows registry file for Chrome and Edge (import with `reg import`, as administrator)."""
    lines = ["Windows Registry Editor Version 5.00", ""]
    for browser in browsers:
        base = REG_BASES[browser]
        for key in ("ExtensionInstallBlocklist", "ExtensionInstallAllowlist"):
            values = chrome_policy.get(key)
            if values is None:
                continue
            lines.append(f"[-{base}\\{key}]")
            lines.append(f"[{base}\\{key}]")
            lines.extend(f'"{i}"="{v}"' for i, v in enumerate(values, start=1))
            lines.append("")
        settings = chrome_policy.get("ExtensionSettings")
        if settings:
            compact = json.dumps(settings, separators=(",", ":"))
            lines.append(f"[{base}]")
            lines.append(f'"ExtensionSettings"="{_reg_string(compact)}"')
            lines.append("")
    return "\r\n".join(lines)
