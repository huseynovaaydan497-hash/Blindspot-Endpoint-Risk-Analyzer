"""
Blast radius: which of the organisation's critical systems ("crown jewels")
can an extension read and change?

Owner: B

Public interface:
    load_crown_jewels(path=None) -> list[{"name", "hosts"}]
    exposure(info, systems=None) -> list[{"system", "hosts", "via", "pattern"}]
    host_covers(extension_host, target_host) -> bool

Separate from the risk score on purpose:
    score     = how dangerous the extension is (anywhere)
    exposure  = what it would touch in THIS organisation if it turned malicious
Only access that needs no user action counts (host permissions, content
scripts, optional host permissions). activeTab is excluded: it needs a click.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache

from blindspot.contract import FIXTURES

PATTERN_RE = re.compile(r"^(?P<scheme>\*|[a-z][a-z0-9+.-]*)://(?P<host>[^/]*)(?P<path>/.*)?$", re.I)
WEB_SCHEMES = {"*", "http", "https"}


@lru_cache(maxsize=4)
def _load(path: str) -> tuple:
    try:
        data = json.loads(open(path, encoding="utf-8").read())
    except (OSError, ValueError):
        return ()
    systems = []
    for item in data.get("systems", []):
        hosts = [h for h in item.get("hosts", []) if isinstance(h, str)]
        if item.get("name") and hosts:
            systems.append({"name": str(item["name"]), "hosts": hosts})
    return tuple(systems)


def load_crown_jewels(path=None) -> list[dict]:
    return [dict(s) for s in _load(str(path or FIXTURES / "crown_jewels.json"))]


def _split(pattern: str) -> tuple[str, str] | None:
    """'*://*.bank.local/*' -> ('*', '*.bank.local'). None if not a web pattern."""
    pattern = pattern.strip()
    if pattern == "<all_urls>":
        return "*", "*"
    match = PATTERN_RE.match(pattern)
    if not match:
        return None
    scheme = match.group("scheme").lower()
    if scheme not in WEB_SCHEMES:
        return None
    host = match.group("host").lower().split(":")[0]  # drop a port if present
    return scheme, host


def host_covers(extension_host: str, target_host: str) -> bool:
    """Does an extension's host pattern give access to (part of) the target host pattern?"""
    ext, tgt = extension_host.lower(), target_host.lower()
    if ext in ("*", ""):
        return True
    ext_wild, tgt_wild = ext.startswith("*."), tgt.startswith("*.")
    ext_base = ext[2:] if ext_wild else ext
    tgt_base = tgt[2:] if tgt_wild else tgt
    if ext_wild:
        return tgt_base == ext_base or tgt_base.endswith("." + ext_base)
    # a specific extension host inside a wildcard target zone is partial access, still access
    return ext_base == tgt_base or (tgt_wild and ext_base.endswith("." + tgt_base))


def _covers(ext_pattern: str, target_pattern: str) -> bool:
    ext, tgt = _split(ext_pattern), _split(target_pattern)
    if not ext or not tgt:
        return False
    schemes_ok = ext[0] == "*" or tgt[0] == "*" or ext[0] == tgt[0]
    return schemes_ok and host_covers(ext[1], tgt[1])


def exposure(info: dict, systems: list[dict] | None = None) -> list[dict]:
    systems = load_crown_jewels() if systems is None else systems
    sources = (
        [(p, "host permission") for p in info.get("host_permissions", [])]
        + [(m, "content script") for m in info.get("content_script_matches", [])]
        + [(p, "optional permission") for p in info.get("optional_permissions", [])
           if p == "<all_urls>" or "://" in p]
    )
    hits = []
    for system in systems:
        for pattern, via in sources:
            if any(_covers(pattern, host) for host in system["hosts"]):
                hits.append({"system": system["name"], "hosts": system["hosts"], "via": via, "pattern": pattern})
                break  # first (strongest) way in is enough
    return hits
