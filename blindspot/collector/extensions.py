"""
Find browser extensions installed on THIS computer.

Owner: A

Public interface:
    find_installed_extensions() -> list[{"browser", "profile", "id", "version_dir"}]
    file_hashes(ext_dir) -> list[{"path", "sha256", "size"}]

Supports Chrome, Edge, Brave and Chromium on Windows, macOS and Linux.
Finds store-installed extensions (Extensions/<id>/<version>/) and unpacked ones
loaded in developer mode (listed in the profile's Preferences / Secure Preferences).
Unpacked extensions skip the store review, so they are reported with source "unpacked".
Firefox (.xpi archives) is a capstone item.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
from pathlib import Path

from blindspot.analyzer.manifest import EXT_ID_RE

BROWSERS = {
    "chrome": {"win": r"Google\Chrome\User Data", "mac": "Google/Chrome", "linux": ".config/google-chrome"},
    "edge": {"win": r"Microsoft\Edge\User Data", "mac": "Microsoft Edge", "linux": ".config/microsoft-edge"},
    "brave": {"win": r"BraveSoftware\Brave-Browser\User Data", "mac": "BraveSoftware/Brave-Browser",
              "linux": ".config/BraveSoftware/Brave-Browser"},
    "chromium": {"win": r"Chromium\User Data", "mac": "Chromium", "linux": ".config/chromium"},
}


def user_data_dirs():
    """Yield (browser, user-data folder) for every supported browser present."""
    system = platform.system()
    home = Path.home()
    for browser, paths in BROWSERS.items():
        if system == "Windows":
            base = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local")) / paths["win"]
        elif system == "Darwin":
            base = home / "Library" / "Application Support" / paths["mac"]
        else:
            base = home / paths["linux"]
        if base.is_dir():
            yield browser, base


def _version_key(name: str) -> tuple:
    return tuple(int(n) for n in re.findall(r"\d+", name)) or (0,)


def find_installed_extensions() -> list[dict]:
    found = []
    for browser, base in user_data_dirs():
        for profile in sorted(p for p in base.iterdir() if p.is_dir()):
            ext_root = profile / "Extensions"
            for id_dir in (sorted(ext_root.iterdir()) if ext_root.is_dir() else []):
                if not (id_dir.is_dir() and EXT_ID_RE.match(id_dir.name)):
                    continue
                versions = [v for v in id_dir.iterdir() if (v / "manifest.json").is_file()]
                if not versions:
                    continue
                newest = max(versions, key=lambda v: _version_key(v.name))
                found.append({"browser": browser, "profile": profile.name, "id": id_dir.name,
                              "version_dir": newest, "source": "store"})
            seen = {f["id"] for f in found if f["browser"] == browser and f["profile"] == profile.name}
            for ext_id, path in _unpacked(profile):
                if ext_id not in seen:
                    found.append({"browser": browser, "profile": profile.name, "id": ext_id,
                                  "version_dir": path, "source": "unpacked"})
    return found


UNPACKED_LOCATIONS = {4, 8}  # Chromium ManifestLocation: 4 UNPACKED (Load unpacked), 8 COMMAND_LINE (--load-extension)


def _unpacked(profile: Path) -> list[tuple[str, Path]]:
    """Unpacked extensions: their folder path is stored in the profile preferences."""
    out = {}
    for name in ("Secure Preferences", "Preferences"):
        try:
            prefs = json.loads((profile / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        settings = ((prefs.get("extensions") or {}).get("settings") or {})
        for ext_id, item in settings.items():
            if not (isinstance(item, dict) and EXT_ID_RE.match(ext_id)):
                continue
            if item.get("location") not in UNPACKED_LOCATIONS or not item.get("path"):
                continue
            path = Path(item["path"])
            if not path.is_absolute():
                path = profile / "Extensions" / path
            if (path / "manifest.json").is_file():
                out[ext_id] = path
    return sorted(out.items())


def file_hashes(ext_dir, limit: int = 500) -> list[dict]:
    """SHA-256 of every file, so a later run can tell exactly what changed in an update."""
    ext_dir = Path(ext_dir)
    out = []
    for path in sorted(p for p in ext_dir.rglob("*") if p.is_file())[:limit]:
        digest = hashlib.sha256()
        try:
            with path.open("rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    digest.update(chunk)
            out.append({"path": path.relative_to(ext_dir).as_posix(), "sha256": digest.hexdigest(),
                        "size": path.stat().st_size})
        except OSError:
            continue
    return out
