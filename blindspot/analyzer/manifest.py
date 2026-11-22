"""
Manifest parsing -- hackathon requirement 1 ("Parse manifests and permissions").

Owner: B

Public interface (do not change the signature, other modules call it):
    load_manifest(ext_dir) -> dict   (shape: docs/API_CONTRACT.md -> ManifestInfo)
"""
from __future__ import annotations

import json
import re
from pathlib import Path

# Chrome extension ids are 32 characters from the alphabet a-p.
EXT_ID_RE = re.compile(r"^[a-p]{32}$")
MSG_RE = re.compile(r"^__MSG_(\w+)__$")


class ManifestError(ValueError):
    """Raised when a folder has no readable manifest.json."""


def strip_json_comments(text: str) -> str:
    """Remove // and /* */ comments that Chrome tolerates in manifest.json.

    String-aware, so URLs such as "https://example.com" are left intact.
    """
    out: list[str] = []
    i, n, in_str = 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j == -1 else j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def read_json(path: Path) -> dict:
    return json.loads(strip_json_comments(path.read_text(encoding="utf-8-sig")))


def is_host_pattern(value: str) -> bool:
    """True for match patterns such as <all_urls> or https://*.example.com/*."""
    return value == "<all_urls>" or "://" in value


def _resolve_message(value, ext_dir: Path, default_locale: str | None):
    """Turn "__MSG_appName__" into the real name from _locales/<locale>/messages.json."""
    if not isinstance(value, str):
        return value
    match = MSG_RE.match(value.strip())
    if not match:
        return value
    key = match.group(1).lower()
    for locale in (default_locale, "en", "en_US", "en_GB"):
        if not locale:
            continue
        path = ext_dir / "_locales" / locale / "messages.json"
        if not path.is_file():
            continue
        try:
            messages = read_json(path)
        except (OSError, ValueError):
            continue
        for name, entry in messages.items():
            if name.lower() == key and isinstance(entry, dict) and "message" in entry:
                return entry["message"]
    return value


def guess_extension_id(ext_dir: Path) -> str:
    """Installed layout is Extensions/<id>/<version>/manifest.json."""
    if EXT_ID_RE.match(ext_dir.parent.name):
        return ext_dir.parent.name
    if EXT_ID_RE.match(ext_dir.name):
        return ext_dir.name
    return ext_dir.name


def _strings(values) -> list[str]:
    return [v for v in (values or []) if isinstance(v, str)]


def _csp_strings(raw: dict) -> list[str]:
    csp = raw.get("content_security_policy")
    if isinstance(csp, str):
        return [csp]
    if isinstance(csp, dict):  # Manifest V3 uses an object
        return [v for v in csp.values() if isinstance(v, str)]
    return []


def load_manifest(ext_dir) -> dict:
    """Parse one unpacked extension folder into a ManifestInfo dict."""
    ext_dir = Path(ext_dir)
    manifest_path = ext_dir / "manifest.json"
    if not manifest_path.is_file():
        raise ManifestError(f"no manifest.json in {ext_dir}")
    try:
        raw = read_json(manifest_path)
    except ValueError as exc:
        raise ManifestError(f"invalid manifest.json in {ext_dir}: {exc}") from exc

    default_locale = raw.get("default_locale")
    permissions = _strings(raw.get("permissions"))
    optional = _strings(raw.get("optional_permissions")) + _strings(raw.get("optional_host_permissions"))

    # Manifest V2 keeps host patterns inside "permissions"; V3 moved them to "host_permissions".
    api_permissions = sorted({p for p in permissions if not is_host_pattern(p)})
    host_permissions = sorted(
        {p for p in permissions if is_host_pattern(p)} | set(_strings(raw.get("host_permissions")))
    )

    content_script_matches = sorted(
        {
            match
            for script in raw.get("content_scripts") or []
            if isinstance(script, dict)
            for match in _strings(script.get("matches"))
        }
    )

    try:
        manifest_version = int(raw.get("manifest_version") or 2)
    except (TypeError, ValueError):
        manifest_version = 2

    return {
        "id": guess_extension_id(ext_dir),
        "name": str(_resolve_message(raw.get("name", ext_dir.name), ext_dir, default_locale)),
        "version": str(raw.get("version", "0")),
        "manifest_version": manifest_version,
        "description": str(_resolve_message(raw.get("description", ""), ext_dir, default_locale)),
        "permissions": api_permissions,
        "host_permissions": host_permissions,
        "optional_permissions": sorted(set(optional)),
        "content_script_matches": content_script_matches,
        "content_security_policy": _csp_strings(raw),
        "externally_connectable": bool(raw.get("externally_connectable")),
        "update_url": raw.get("update_url"),
        "homepage_url": raw.get("homepage_url"),
        "path": str(ext_dir),
    }
