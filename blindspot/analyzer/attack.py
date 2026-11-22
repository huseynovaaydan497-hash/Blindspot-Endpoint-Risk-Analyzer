"""
MITRE ATT&CK mapping: what a hostile version of this extension could do.

Owner: B + C

Public interface:
    techniques(info, findings) -> [{"id", "name", "why"}]

Every extension sits under T1176.001 (Browser Extensions, tactic Persistence).
The mapping table lives in fixtures/attack_mapping.json so it can be reviewed and
extended without touching code.
"""
from __future__ import annotations

import json
from functools import lru_cache

from blindspot.contract import FIXTURES


@lru_cache(maxsize=1)
def mapping() -> dict:
    try:
        return json.loads((FIXTURES / "attack_mapping.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"base": None, "techniques": {}, "permissions": {}, "findings": {}}


def techniques(info: dict, findings: list[dict]) -> list[dict]:
    from blindspot.analyzer.permissions import is_broad_host  # local import avoids a cycle

    m = mapping()
    names = m.get("techniques", {})
    found: dict[str, str] = {}

    observed = list(info.get("permissions", []))
    if any(is_broad_host(p) for p in info.get("host_permissions", []) + info.get("content_script_matches", [])):
        observed.append("@broad_host")
    for perm in observed:
        tid = m.get("permissions", {}).get(perm)
        if tid and tid not in found:
            found[tid] = "access to every website" if perm == "@broad_host" else f"permission {perm}"

    for f in findings:
        if f.get("severity") == "info":
            continue
        for prefix, tid in m.get("findings", {}).items():
            if f["title"].startswith(prefix) and tid not in found:
                found[tid] = f["title"].lower()

    out = [{"id": tid, "name": names.get(tid, tid), "why": why} for tid, why in found.items()]
    out.sort(key=lambda t: t["id"])
    if m.get("base"):
        out.insert(0, {"id": m["base"]["id"], "name": m["base"]["name"], "why": "installed browser extension"})
    return out
