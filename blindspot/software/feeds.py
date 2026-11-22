"""
Live vulnerability data: NIST NVD (which versions a CVE affects, CVSS) and
CISA KEV (which CVEs are exploited in the wild).

Owner: C

Public interface:
    load_watchlist(path=None) -> [{"name", "match", "cpe": ["vendor:product", ...]}]
    fetch_nvd(cpe, api_key=None, get=http_get) -> [advisory]
    fetch_kev(get=http_get) -> {"CVE-...": "date added"}
    parse_nvd(pages, entry) -> [advisory]
    in_ranges (re-exported from assess)

NVD API 2.0: https://nvd.nist.gov/developers/vulnerabilities
    GET /rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:<vendor>:<product>
    returns every CVE whose configuration names that product, with the affected
    version ranges (versionStart/EndIncluding/Excluding). Without an API key NVD
    allows 5 requests per 30 seconds, so requests are spaced 6.5 s apart; with a
    free key (https://nvd.nist.gov/developers/request-an-api-key) 0.7 s.
CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from functools import lru_cache

from blindspot.contract import FIXTURES
from blindspot.software.assess import in_ranges  # noqa: F401 -- re-exported

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
PAGE = 2000
PARSER_VERSION = "2"  # bump when parse_nvd changes: cached NVD data is fetched again
USER_AGENT = "Blindspot/0.4 (endpoint extension and software risk; hackathon project)"


class FeedError(RuntimeError):
    """A feed could not be fetched or understood."""


@lru_cache(maxsize=2)
def load_watchlist(path: str | None = None) -> tuple[dict, ...]:
    try:
        data = json.loads(open(path or FIXTURES / "software_watchlist.json", encoding="utf-8").read())
    except (OSError, ValueError):
        return ()
    out = []
    for p in data.get("products", []):
        try:
            re.compile(p["match"])
        except (re.error, KeyError):
            continue
        out.append({"name": p["name"], "match": p["match"], "cpe": list(p.get("cpe", []))})
    return tuple(out)


def http_get(url: str, headers: dict | None = None, timeout: int = 60) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 -- fixed https hosts
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"vulnerabilities": [], "totalResults": 0}  # NVD: unknown product, nothing to report
        if exc.code in (403, 429, 503):
            raise FeedError(f"NVD rate limit or outage (HTTP {exc.code}). It retries on the next check.") from exc
        raise FeedError(f"HTTP {exc.code} from {urllib.parse.urlsplit(url).netloc}") from exc
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise FeedError(f"Cannot reach {urllib.parse.urlsplit(url).netloc}: {getattr(exc, 'reason', exc)}") from exc


def cpe_fields(criteria: str) -> list[str]:
    """Split a CPE 2.3 string on ':' that is not escaped with a backslash."""
    return re.split(r"(?<!\\):", criteria)


def parse_nvd(pages: list[dict], entry: dict) -> list[dict]:
    wanted = {c.lower() for c in entry["cpe"]}
    out = []
    for page in pages:
        for item in page.get("vulnerabilities", []):
            cve = item.get("cve") or {}
            if cve.get("vulnStatus") == "Rejected":
                continue
            ranges = []
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    if node.get("negate"):
                        continue
                    for m in node.get("cpeMatch", []):
                        if not m.get("vulnerable"):
                            continue
                        f = cpe_fields(m.get("criteria", ""))
                        if len(f) < 6 or f[2] != "a" or f"{f[3]}:{f[4]}".lower() not in wanted:
                            continue
                        r = {k: m[src] for k, src in (("start_incl", "versionStartIncluding"),
                                                      ("start_excl", "versionStartExcluding"),
                                                      ("end_incl", "versionEndIncluding"),
                                                      ("end_excl", "versionEndExcluding")) if m.get(src)}
                        if f[5] not in ("*", "-", ""):
                            r["exact"] = f[5].replace("\\", "")
                        ranges.append(r)
            if not ranges:
                continue
            metrics = cve.get("metrics", {})
            score, vector = None, ""
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
                rows = metrics.get(key) or []
                row = next((r for r in rows if r.get("type") == "Primary"), rows[0] if rows else None)
                if row:
                    score = row.get("cvssData", {}).get("baseScore")
                    vector = row.get("cvssData", {}).get("vectorString", "")
                    break
            desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
            title = summary(desc)
            out.append({
                "cve": cve.get("id", ""), "title": title, "product": entry["name"], "match": entry["match"],
                "ranges": ranges, "cvss": score, "vector": vector,
                "published": (cve.get("published") or "")[:10], "exploitation": "none", "automatable": "no",
                "kev": False, "source": "nvd",
                "references": [f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}"],
            })
    return out


BOILERPLATE = re.compile(r"^[\w\s.+\-()]{1,60}\b(is|are) (an?|the) [^.]{0,120}$", re.I)


def summary(description: str, limit: int = 180) -> str:
    """First informative sentence. GitHub-sourced CVEs often open with a product blurb
    ("7-Zip is a file archiver with a high compression ratio."); skip it."""
    sentences = [x.strip() for x in re.split(r"(?<=[.!?])\s+", description or "") if x.strip()]
    while len(sentences) > 1 and BOILERPLATE.match(sentences[0].rstrip(".")):
        sentences.pop(0)
    text = sentences[0] if sentences else ""
    return text if len(text) <= limit else text[:limit].rsplit(" ", 1)[0] + "…"


def fetch_nvd(cpe: str, entry: dict, api_key: str | None = None, get=http_get, sleep=time.sleep) -> list[dict]:
    headers = {"apiKey": api_key} if api_key else {}
    pages, start = [], 0
    while True:
        query = urllib.parse.urlencode({"virtualMatchString": f"cpe:2.3:a:{cpe}",
                                        "resultsPerPage": PAGE, "startIndex": start})
        page = get(f"{NVD_URL}?{query}", headers)
        pages.append(page)
        start += page.get("resultsPerPage", PAGE) or PAGE
        if start >= page.get("totalResults", 0):
            break
        sleep(0.7 if api_key else 6.5)
    return parse_nvd(pages, dict(entry, cpe=[cpe]))


def fetch_kev(get=http_get) -> dict[str, str]:
    data = get(KEV_URL)
    return {v["cveID"]: v.get("dateAdded", "") for v in data.get("vulnerabilities", []) if v.get("cveID")}
