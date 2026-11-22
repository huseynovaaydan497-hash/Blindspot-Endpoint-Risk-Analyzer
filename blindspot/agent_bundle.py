"""
Agent download: a zip a teammate unpacks and double-clicks to report a computer.

Owner: A + D

Public interface:
    build_agent_zip(server_url) -> bytes
    lan_addresses() -> [str]

The zip holds the `blindspot` package and the fixtures the analyzer reads. The
agent only needs Python 3.10+ and the standard library: no pip install. The
server address is written into the start scripts, so nobody types it.
"""
from __future__ import annotations

import io
import re
import socket
import zipfile

from blindspot.contract import FIXTURES, REPO_ROOT

FOLDER = "blindspot-agent"

# fixtures the agent reads while analysing (no fleet data, no seed files)
AGENT_FIXTURES = (
    "permission_weights.json", "permission_glossary.json", "known_domains.json", "known_good.json",
    "store_cache.json", "crown_jewels.json", "ai_services.json", "attack_mapping.json",
)

WINDOWS_RUN = r"""@echo off
rem Blindspot agent: reports this computer's browser extensions and software once.
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (set PY=py -3) else (set PY=python)
%PY% -m blindspot agent --server {server} %*
echo.
pause
"""

WINDOWS_WATCH = r"""@echo off
rem Blindspot agent: keeps watching and reports again every 10 minutes. Close the window to stop.
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (set PY=py -3) else (set PY=python)
%PY% -m blindspot agent --server {server} --every 10 %*
pause
"""

UNIX_RUN = """#!/bin/sh
# Blindspot agent: reports this computer's browser extensions and software.
# Add --every 10 to keep watching.
cd "$(dirname "$0")"
exec python3 -m blindspot agent --server {server} "$@"
"""

README = """Blindspot agent
===============

Server: {server}

Windows:  double-click run_agent.bat   (once)
          double-click watch_agent.bat (keeps reporting every 10 minutes)
Mac/Linux: sh run_agent.sh

Needs Python 3.10 or newer (python.org). Nothing else to install.

What leaves this computer: extension names, versions, permissions, analysis results
and file hashes, plus the list of installed programs. Never browsing history,
cookies, passwords or the extensions' source code.
"""

SAFE_URL = re.compile(r"^https?://[A-Za-z0-9.\-\[\]:]+/?$")


def _clean(server_url: str) -> str:
    url = (server_url or "").strip().rstrip("/")
    if not SAFE_URL.match(url + "/"):
        raise ValueError("server must look like http://192.168.1.20:8000")
    return url


def build_agent_zip(server_url: str) -> bytes:
    server = _clean(server_url)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        package = REPO_ROOT / "blindspot"
        for path in sorted(package.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            zf.write(path, f"{FOLDER}/{path.relative_to(REPO_ROOT).as_posix()}")
        for name in AGENT_FIXTURES:
            if (FIXTURES / name).is_file():
                zf.write(FIXTURES / name, f"{FOLDER}/fixtures/{name}")
        zf.writestr(f"{FOLDER}/run_agent.bat", WINDOWS_RUN.format(server=server).replace("\n", "\r\n"))
        zf.writestr(f"{FOLDER}/watch_agent.bat", WINDOWS_WATCH.format(server=server).replace("\n", "\r\n"))
        info = zipfile.ZipInfo(f"{FOLDER}/run_agent.sh")
        info.external_attr = 0o755 << 16
        zf.writestr(info, UNIX_RUN.format(server=server))
        zf.writestr(f"{FOLDER}/README.txt", README.format(server=server))
    return buf.getvalue()


def lan_addresses() -> list[str]:
    """This computer's addresses on the local network (no packet is sent)."""
    found = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            found.append(s.getsockname()[0])
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in found and not ip.startswith("127."):
                found.append(ip)
    except OSError:
        pass
    return found
