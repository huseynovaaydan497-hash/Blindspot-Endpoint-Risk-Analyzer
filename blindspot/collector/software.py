"""
Installed (local) software inventory.

Owner: A

Public interface:
    list_installed_software() -> list[{"name", "version", "publisher", "source"}]

Inventory only for the hackathon; software risk scoring is a capstone item.
Never raises: on any error it returns what it has so far.
"""
from __future__ import annotations

import json
import platform
import plistlib
import subprocess
from pathlib import Path


def list_installed_software() -> list[dict]:
    system = platform.system()
    try:
        if system == "Windows":
            items = _windows()
        elif system == "Darwin":
            items = _macos()
        else:
            items = _linux()
    except Exception:  # noqa: BLE001 -- inventory must never crash the agent
        items = []
    unique = {(i["name"], i["version"]): i for i in items if i.get("name")}
    return sorted(unique.values(), key=lambda i: i["name"].lower())


def _windows() -> list[dict]:
    import winreg  # only exists on Windows

    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    items = []
    for hive, path in roots:
        try:
            key = winreg.OpenKey(hive, path)
        except OSError:
            continue
        for i in range(winreg.QueryInfoKey(key)[0]):
            try:
                sub = winreg.OpenKey(key, winreg.EnumKey(key, i))
            except OSError:
                continue

            def value(name, sub=sub):
                try:
                    return str(winreg.QueryValueEx(sub, name)[0])
                except OSError:
                    return ""

            name = value("DisplayName")
            if name:
                items.append({"name": name, "version": value("DisplayVersion"),
                              "publisher": value("Publisher"), "source": "registry"})
    return items


def _macos() -> list[dict]:
    try:
        out = subprocess.run(["system_profiler", "SPApplicationsDataType", "-json"],
                             capture_output=True, text=True, timeout=90, check=True).stdout
        apps = json.loads(out).get("SPApplicationsDataType", [])
        return [{"name": a.get("_name", ""), "version": a.get("version", ""),
                 "publisher": a.get("obtained_from", ""), "source": "system_profiler"} for a in apps]
    except (OSError, subprocess.SubprocessError, ValueError):
        items = []
        for app in Path("/Applications").glob("*.app"):
            info = app / "Contents" / "Info.plist"
            try:
                data = plistlib.loads(info.read_bytes())
            except (OSError, plistlib.InvalidFileException, ValueError):
                continue
            items.append({"name": data.get("CFBundleName", app.stem),
                          "version": data.get("CFBundleShortVersionString", ""),
                          "publisher": data.get("CFBundleIdentifier", ""), "source": "Info.plist"})
        return items


def _linux() -> list[dict]:
    commands = [
        (["dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Maintainer}\n"], "dpkg"),
        (["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"], "rpm"),
    ]
    for cmd, source in commands:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=True).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        items = []
        for line in out.splitlines():
            parts = (line.split("\t") + ["", "", ""])[:3]
            items.append({"name": parts[0], "version": parts[1], "publisher": parts[2], "source": source})
        return items
    return []
