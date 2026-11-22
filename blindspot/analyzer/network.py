"""
Network endpoint extraction: which servers does the extension talk to?

Owner: C

Public interface:
    extract_endpoints(ext_dir, info=None) -> signal_result with extra keys
        endpoints:   [{"host", "url", "known", "scheme", "ai"}]
        ai_services: [host, ...]   AI providers the code talks to (Shadow AI)
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from blindspot.analyzer.codescan import iter_source_files
from blindspot.contract import FIXTURES, finding, signal_result

URL_RE = re.compile(r"\b(?:https?|wss?)://[^\s'\"`<>()\\{}|^]+", re.I)
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "[::1]"}

POINTS_PER_UNKNOWN = 10
UNKNOWN_CAP = 40
POINTS_IP_LITERAL = 20
POINTS_PLAIN_HTTP = 5
POINTS_AI_WITH_PAGE_ACCESS = 20   # can read pages AND talks to an AI provider
POINTS_AI = 5
MAX_LISTED = 10


@lru_cache(maxsize=1)
def known_domains() -> list[str]:
    data = json.loads((FIXTURES / "known_domains.json").read_text(encoding="utf-8"))
    return [d.lower() for d in data["domains"]]


def is_known(host: str) -> bool:
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in known_domains())


@lru_cache(maxsize=1)
def ai_domains() -> list[str]:
    try:
        data = json.loads((FIXTURES / "ai_services.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [d.lower() for d in data.get("domains", [])]


def is_ai_service(host: str) -> bool:
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in ai_domains())


def _clean(url: str) -> str:
    return url.rstrip(".,;:!?'\")]}")


def extract_endpoints(ext_dir, info: dict | None = None) -> dict:
    ext_dir = Path(ext_dir)
    seen: dict[str, dict] = {}

    candidates: list[str] = []
    for key in ("update_url", "homepage_url"):
        if info and info.get(key):
            candidates.append(str(info[key]))
    for path in iter_source_files(ext_dir):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        candidates.extend(m.group(0) for m in URL_RE.finditer(text))

    for raw in candidates:
        url = _clean(raw)
        try:
            parts = urlsplit(url)
        except ValueError:
            continue
        host = (parts.hostname or "").lower()
        if not host or "*" in host or "$" in host:
            continue
        if "." not in host and host not in LOCAL_HOSTS:
            continue
        if host in seen:
            continue
        ai = is_ai_service(host)
        seen[host] = {"host": host, "url": url[:200], "scheme": parts.scheme.lower(),
                      "known": ai or is_known(host) or host in LOCAL_HOSTS, "ai": ai}

    endpoints = sorted(seen.values(), key=lambda e: (e["known"], e["host"]))
    unknown = [e for e in endpoints if not e["known"]]

    findings = []
    total = 0.0
    if unknown:
        pts = min(UNKNOWN_CAP, POINTS_PER_UNKNOWN * len(unknown))
        total += pts
        listed = ", ".join(e["host"] for e in unknown[:MAX_LISTED])
        more = f" and {len(unknown) - MAX_LISTED} more" if len(unknown) > MAX_LISTED else ""
        findings.append(
            finding("network", "high" if len(unknown) >= 3 else "medium",
                    f"Talks to {len(unknown)} unrecognised server(s)",
                    "Its code contains addresses of servers that are not on the known-services list.",
                    evidence=listed + more, points=pts)
        )

    ip_hosts = [e for e in unknown if IPV4_RE.match(e["host"])]
    if ip_hosts:
        pts = POINTS_IP_LITERAL
        total += pts
        findings.append(
            finding("network", "high", "Connects to raw IP addresses",
                    "Uses bare IP addresses instead of domain names, common for throwaway infrastructure.",
                    evidence=", ".join(e["host"] for e in ip_hosts[:MAX_LISTED]), points=pts)
        )

    plain = [e for e in unknown if e["scheme"] in ("http", "ws") and e["host"] not in LOCAL_HOSTS]
    if plain:
        pts = POINTS_PLAIN_HTTP
        total += pts
        findings.append(
            finding("network", "low", "Unencrypted connections",
                    "Sends data over plain HTTP, which anyone on the network can read.",
                    evidence=", ".join(e["url"] for e in plain[:3]), points=pts)
        )

    ai_hosts = [e["host"] for e in endpoints if e["ai"]]
    if ai_hosts:
        from blindspot.analyzer.permissions import is_broad_host  # local import avoids a cycle
        page_access = bool(info) and any(
            is_broad_host(p) for p in info.get("host_permissions", []) + info.get("content_script_matches", []))
        pts = POINTS_AI_WITH_PAGE_ACCESS if page_access else POINTS_AI
        total += pts
        findings.append(
            finding("network", "high" if page_access else "low",
                    "Can send page content to AI services" if page_access else "Talks to AI services",
                    ("Reads every website you open and contains addresses of AI providers, so page content "
                     "such as customer data can leave the organisation." if page_access else
                     "Contains addresses of AI providers."),
                    evidence=", ".join(ai_hosts[:MAX_LISTED]), points=pts)
        )

    return signal_result(total, findings, endpoints=endpoints, ai_services=ai_hosts)
