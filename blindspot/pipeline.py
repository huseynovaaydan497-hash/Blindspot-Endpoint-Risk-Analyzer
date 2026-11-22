"""
The glue: one extension folder in, one AnalysisResult out.

Owner: D

Public interface:
    analyze_extension(ext_dir, known_good=None, store_cache=None, now=None) -> AnalysisResult
    analyze_tree(root, ...) -> list[AnalysisResult]
    discover_extensions(root) -> list[Path]

Each analyzer runs inside its own try/except. If one module is half-finished
or crashes, its signal is marked unavailable and the rest of the pipeline
still produces a result. This is what keeps the demo alive during integration.
"""
from __future__ import annotations

import json
import re
import traceback
from pathlib import Path

import hashlib
import re as _re

from blindspot.analyzer import attack, codescan, exposure, manifest, network, permissions, reputation, score
from blindspot.contract import (
    FIXTURES,
    RECOMMENDATION,
    SEVERITY_RANK,
    finding,
    now_iso,
    signal_result,
)


def load_known_good(path=None) -> dict:
    path = path or FIXTURES / "known_good.json"
    try:
        return json.loads(Path(path).read_text(encoding="utf-8")).get("extensions", {})
    except (OSError, ValueError):
        return {}


def _version_key(name: str) -> tuple:
    return tuple(int(n) for n in re.findall(r"\d+", name)) or (0,)


def discover_extensions(root) -> list[Path]:
    """Find unpacked extension folders under `root`.

    Accepts a single extension folder, an Extensions/<id>/<version>/ tree, or
    any folder of unpacked extensions. Keeps only the newest version per id.
    """
    root = Path(root)
    if (root / "manifest.json").is_file():
        return [root]
    newest: dict[str, Path] = {}
    for manifest_path in sorted(root.rglob("manifest.json")):
        folder = manifest_path.parent
        # skip manifests nested inside another extension (bundled libraries etc.)
        if any((p / "manifest.json").is_file() for p in folder.parents if p != root and root in p.parents):
            continue
        key = str(folder.parent) if manifest.EXT_ID_RE.match(folder.parent.name) else str(folder)
        if key not in newest or _version_key(folder.name) > _version_key(newest[key].name):
            newest[key] = folder
    return sorted(newest.values())


def _safe(signal: str, fn, *args, **kwargs) -> dict:
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 -- one broken module must not stop the pipeline
        return signal_result(0, [finding(signal, "info", f"{signal} analysis failed",
                                         f"{type(exc).__name__}: {exc}",
                                         evidence=traceback.format_exc(limit=1).strip()[-300:])],
                             available=False)


AI_NAME_RE = _re.compile(r"\b(AI|GPT|ChatGPT|Claude|Gemini|Copilot|LLM|Perplexity)\b")


def _recommend(level: str, is_known_good: bool, exposed: list) -> str:
    """block > contain > review > allow. Approved extensions are never blocked,
    but they are still kept off crown-jewel systems they could reach."""
    if level == "high" and not is_known_good:
        return "block"
    if exposed:
        return "contain"
    if is_known_good:
        return "allow"
    return RECOMMENDATION[level]


def _safe_exposure(info: dict) -> list[dict]:
    try:
        return exposure.exposure(info)
    except Exception:  # noqa: BLE001 -- exposure is informative; never stop the pipeline
        return []


def _correlate(signals: dict) -> None:
    """Cross-signal pattern: code that collects cookies AND a server nobody recognises.

    Each half alone is common (session tools read cookies; many extensions call APIs).
    Together they are the shape of session theft, as in the hijacked Cyberhaven build.
    """
    code, net = signals.get("code", {}), signals.get("network", {})
    if not (code.get("available") and net.get("available")):
        return
    cookie_hits = [f for f in code["findings"] if f["title"].startswith(("Reads all cookies", "Reads page cookies"))]
    unknown = [e["host"] for e in net.get("endpoints", []) if not e.get("known")]
    if cookie_hits and unknown:
        code["findings"].insert(0, finding(
            "code", "critical", "Collects cookies and can send them to an unknown server",
            "Reads login cookies and contains the address of a server nobody recognises: the pattern of "
            "session theft (MITRE ATT&CK T1539 + T1041).",
            evidence=f"{cookie_hits[0]['evidence']} -> {', '.join(unknown[:3])}", points=40))
        code["score"] = min(100, code["score"] + 40)


def _safe_attack(info: dict, findings: list[dict]) -> list[dict]:
    try:
        return attack.techniques(info, findings)
    except Exception:  # noqa: BLE001 -- informative only
        return []


MAX_HASH_BYTES = 50_000_000


def content_hash(ext_dir) -> str | None:
    """SHA-256 over every file of the unpacked extension (relative path + bytes).

    Chrome keeps the extension ID when a new version is published, so the ID alone
    cannot tell an approved build from a hijacked one (Cyberhaven, December 2024).
    This hash identifies the exact code that was reviewed. `_metadata/` is skipped:
    Chrome writes it locally after install.
    """
    root = Path(ext_dir)
    digest = hashlib.sha256()
    total = 0
    try:
        for path in sorted(p for p in root.rglob("*") if p.is_file() and "_metadata" not in p.relative_to(root).parts):
            data = path.read_bytes()
            total += len(data)
            if total > MAX_HASH_BYTES:
                return None
            digest.update(path.relative_to(root).as_posix().encode() + b"\0" + data + b"\0")
    except OSError:
        return None
    return digest.hexdigest()


def _ai_profile(info: dict, network_signal: dict) -> dict:
    """Is this an AI tool, and which AI providers does it talk to?"""
    services = network_signal.get("ai_services", [])
    named = bool(AI_NAME_RE.search(f"{info.get('name', '')} {info.get('description', '')}"))
    return {"is_ai": bool(services) or named, "services": services,
            "evidence": "talks to AI providers" if services else ("name or description" if named else None)}


def analyze_extension(ext_dir, known_good: dict | None = None, store_cache: dict | None = None,
                      now=None, ext_id: str | None = None) -> dict:
    info = manifest.load_manifest(ext_dir)
    if ext_id:  # unpacked extensions live outside Extensions/<id>/, the browser knows their id
        info["id"] = ext_id
    known_good = load_known_good() if known_good is None else known_good

    signals = {
        "permission": _safe("permission", permissions.analyze_permissions, info),
        "code": _safe("code", codescan.scan_code, ext_dir),
        "network": _safe("network", network.extract_endpoints, ext_dir, info),
        "reputation": _safe("reputation", reputation.check_reputation, info["id"], cache=store_cache, now=now),
    }

    _correlate(signals)
    is_known_good = info["id"] in known_good
    exposed = _safe_exposure(info)
    total, level, extra, rating = score.combine(signals, known_good=is_known_good, exposure_count=len(exposed))

    findings = [f for s in signals.values() for f in s["findings"]]
    findings.sort(key=lambda f: (SEVERITY_RANK[f["severity"]], f["points"]), reverse=True)
    if is_known_good and not extra:
        extra = [finding("score", "info", "On the organisation's approved list",
                         "Approved in fixtures/known_good.json, so it is allowed whatever its score.",
                         evidence="known_good.json", points=0)]
    findings = extra + findings  # approval notes first: they explain the final decision

    return {
        "id": info["id"],
        "name": info["name"],
        "version": info["version"],
        "manifest_version": info["manifest_version"],
        "description": info["description"],
        "permissions": info["permissions"],
        "host_permissions": info["host_permissions"],
        "optional_permissions": info["optional_permissions"],
        "content_script_matches": info["content_script_matches"],
        "high_risk_permissions": permissions.high_risk_flags(info),
        "capabilities": permissions.capabilities(info),
        "score": total,
        "level": level,
        "recommendation": _recommend(level, is_known_good, exposed),
        "known_good": is_known_good,
        "signals": {name: {"score": s["score"], "available": s["available"]} for name, s in signals.items()},
        "findings": findings,
        "endpoints": signals["network"].get("endpoints", []),
        "store": signals["reputation"].get("store"),
        "exposure": exposed,
        "ai": _ai_profile(info, signals["network"]),
        "rating": rating,
        "attack": _safe_attack(info, findings),
        "content_hash": content_hash(ext_dir),
        "analyzed_at": now_iso(),
        "path": info["path"],
    }


def analyze_tree(root, known_good: dict | None = None, store_cache: dict | None = None,
                 now=None) -> list[dict]:
    known_good = load_known_good() if known_good is None else known_good
    store_cache = reputation.load_cache() if store_cache is None else store_cache
    results = []
    for ext_dir in discover_extensions(root):
        try:
            results.append(analyze_extension(ext_dir, known_good=known_good, store_cache=store_cache, now=now))
        except manifest.ManifestError:
            continue
    results.sort(key=lambda r: r["score"], reverse=True)
    return results
