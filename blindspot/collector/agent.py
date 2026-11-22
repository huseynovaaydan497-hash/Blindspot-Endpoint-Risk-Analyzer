"""
Endpoint agent: inventory + local analysis + send results to the server.

Owner: A

Design choice (say it on the ethics slide): analysis runs ON the endpoint.
Only results, manifests and file hashes leave the machine -- never browsing
history, cookies, passwords or the extension source code itself.
"""
from __future__ import annotations

import json
import platform
import socket
import urllib.request
import uuid
from pathlib import Path

from blindspot.collector.extensions import file_hashes, find_installed_extensions
from blindspot.collector.software import list_installed_software
from blindspot.contract import now_iso
from blindspot.pipeline import analyze_extension, load_known_good
from blindspot.analyzer.reputation import load_cache


ID_FILE = Path.home() / ".blindspot" / "machine_id"


def stable_machine_id() -> str:
    """Created once and kept in ~/.blindspot/machine_id, so every report from this
    computer lands on the same machine (uuid.getnode() can be random on some systems)."""
    try:
        existing = ID_FILE.read_text(encoding="utf-8").strip()
        if existing:
            return existing
    except OSError:
        pass
    new = str(uuid.uuid4())
    try:
        ID_FILE.parent.mkdir(parents=True, exist_ok=True)
        ID_FILE.write_text(new, encoding="utf-8")
    except OSError:
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, socket.gethostname()))
    return new


def machine_info(machine_id: str | None = None) -> dict:
    hostname = socket.gethostname()
    return {
        "machine_id": machine_id or stable_machine_id(),
        "hostname": hostname,
        "os": platform.platform(),
        "collected_at": now_iso(),
    }


def collect(include_software: bool = True, machine_id: str | None = None) -> dict:
    known_good = load_known_good()
    cache = load_cache()
    extensions = []
    for item in find_installed_extensions():
        try:
            result = analyze_extension(item["version_dir"], known_good=known_good, store_cache=cache,
                                       ext_id=item["id"])
        except Exception:  # noqa: BLE001 -- skip unreadable extensions, keep going
            continue
        result.pop("path", None)  # local path contains the user name; keep it on the machine
        result.update(browser=item["browser"], profile=item["profile"], install_source=item.get("source", "store"),
                      files=file_hashes(item["version_dir"]))
        extensions.append(result)
    return {
        "machine": machine_info(machine_id),
        "extensions": extensions,
        "software": list_installed_software() if include_software else [],
    }


def post(payload: dict, server: str, timeout: int = 30) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(server.rstrip("/") + "/api/v1/inventory", data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 -- server URL is operator-provided
        return json.loads(resp.read().decode("utf-8"))
