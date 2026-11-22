"""
Static code analysis of the extension's JavaScript and HTML.

Owner: C

Public interface:
    scan_code(ext_dir) -> signal_result
    iter_source_files(ext_dir) -> iterator of Path    (network.py reuses it)

Each rule counts once per extension (first match is shown as evidence), so a
large bundle does not inflate the score just by being large. Matches inside
files that look like third-party libraries (jquery, vendor, ...) count half.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

from blindspot.contract import finding, signal_result

SOURCE_SUFFIXES = {".js", ".mjs", ".cjs", ".html", ".htm"}
MAX_FILE_BYTES = 3_000_000
MAX_FILES = 400
VENDOR_RE = re.compile(r"(jquery|lodash|underscore|react|vue|angular|bootstrap|vendor|polyfill|\.min\.js$)", re.I)

# (rule id, pattern, severity, points, title, plain-language detail)
RULES = [
    ("eval", r"\beval\s*\(", "high", 20, "Runs text as code (eval)",
     "Turns text into running code at runtime, so it can execute code nobody reviewed."),
    ("new-function", r"\bnew\s+Function\s*\(", "high", 20, "Builds code at runtime (new Function)",
     "Creates functions from text at runtime, a common way to hide behaviour."),
    ("obfuscator", r"\b_0x[0-9a-f]{4,6}\b", "high", 20, "Obfuscated code",
     "Uses naming typical of code obfuscators, which hides what the code does."),
    ("cookie-dump", r"chrome\.cookies\.getAll\s*\(", "high", 15, "Reads all cookies",
     "Calls the API that returns every cookie it has access to."),
    ("ext-management", r"chrome\.management\.(?:setEnabled|uninstall)\b", "high", 15,
     "Disables or removes other extensions", "Can switch off other extensions, including security tools."),
    ("proxy-set", r"chrome\.proxy\.settings\.set\b", "high", 15, "Changes the proxy",
     "Can route browser traffic through another server."),
    ("string-timer", r"\bset(?:Timeout|Interval)\s*\(\s*['\"`]", "medium", 10, "Timer runs a string as code",
     "Passes text to a timer, which runs it as code like eval."),
    ("script-inject", r"createElement\(\s*['\"]script['\"]\s*\)", "medium", 10, "Injects script elements",
     "Adds new script tags to pages, which can load code from elsewhere."),
    ("document-cookie", r"\bdocument\.cookie\b", "medium", 8, "Reads page cookies",
     "Reads the cookies of the page it runs on."),
    ("keylogger", r"addEventListener\(\s*['\"]key(?:down|up|press)['\"]", "medium", 8, "Listens to keystrokes",
     "Watches what you type on pages."),
    ("execute-script", r"chrome\.(?:scripting|tabs)\.executeScript\s*\(", "low", 5, "Injects code into tabs",
     "Runs its own code inside open tabs."),
    ("atob", r"\batob\s*\(", "low", 5, "Decodes hidden data (base64)",
     "Decodes base64 text at runtime; often harmless, sometimes used to hide strings."),
    ("fromcharcode", r"String\.fromCharCode\s*\(", "low", 4, "Builds strings from character codes",
     "Assembles text from numbers, a light obfuscation technique."),
    ("wasm", r"WebAssembly\.(?:instantiate|compile)\b", "low", 5, "Runs WebAssembly",
     "Runs compiled binary code that is hard to review."),
]
COMPILED = [(rid, re.compile(rx), sev, pts, title, detail) for rid, rx, sev, pts, title, detail in RULES]

LONG_BASE64_RE = re.compile(r"['\"`]([A-Za-z0-9+/]{200,}={0,2})['\"`]")
HEX_ESCAPES_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")
# Key- or token-like literals only (base64 / url-safe alphabet). Matching any long
# literal also matched minified code BETWEEN two strings, which is not random data.
SECRET_LIKE_RE = re.compile(r"['\"`]([A-Za-z0-9+/=_\-]{40,})['\"`]")
ENTROPY_THRESHOLD = 4.5


def iter_source_files(ext_dir):
    ext_dir = Path(ext_dir)
    count = 0
    for path in sorted(ext_dir.rglob("*")):
        if count >= MAX_FILES:
            return
        if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES and "_metadata" not in path.parts:
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            count += 1
            yield path


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _evidence(ext_dir: Path, path: Path, text: str, index: int) -> str:
    line_no = text.count("\n", 0, index) + 1
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    line = text[start: end if end != -1 else len(text)].strip()
    if len(line) > 120:
        offset = max(0, index - start - 40)
        line = "..." + line[offset: offset + 110] + "..."
    return f"{path.relative_to(ext_dir).as_posix()}:{line_no}: {line}"


def scan_code(ext_dir) -> dict:
    ext_dir = Path(ext_dir)
    hits: dict[str, dict] = {}
    files_scanned = 0

    def record(rule_id, severity, points, title, detail, path, text, index):
        vendor = bool(VENDOR_RE.search(path.name))
        pts = points * (0.5 if vendor else 1)
        if rule_id in hits:
            hits[rule_id]["count"] += 1
            # prefer evidence from first-party code
            if hits[rule_id]["vendor"] and not vendor:
                hits[rule_id].update(points=points, vendor=False,
                                     evidence=_evidence(ext_dir, path, text, index))
            return
        hits[rule_id] = {
            "severity": severity, "points": pts, "title": title,
            "detail": detail + (" (Found in a third-party library file.)" if vendor else ""),
            "evidence": _evidence(ext_dir, path, text, index), "count": 1, "vendor": vendor,
        }

    for path in iter_source_files(ext_dir):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files_scanned += 1

        for rule_id, rx, severity, points, title, detail in COMPILED:
            for match in rx.finditer(text):
                record(rule_id, severity, points, title, detail, path, text, match.start())

        for match in LONG_BASE64_RE.finditer(text):
            record("long-base64", "medium", 10, "Large hidden data block",
                   "Contains a long base64 block, which can hide code or addresses.", path, text, match.start())
        for match in HEX_ESCAPES_RE.finditer(text):
            if len(set(match.group(0).lower().split("\\x"))) <= 3:  # e.g. \x00\x00\x00 padding
                continue
            record("hex-escapes", "medium", 8, "Hex-escaped strings",
                   "Writes text as hex escapes, a common way to hide strings.", path, text, match.start())
        for match in SECRET_LIKE_RE.finditer(text):
            body = match.group(1)
            if shannon_entropy(body) >= ENTROPY_THRESHOLD:
                record("high-entropy", "medium", 8, "Random-looking string",
                       "Contains a long high-entropy string such as a key or encrypted payload.",
                       path, text, match.start())

    findings = []
    total = 0.0
    for hit in sorted(hits.values(), key=lambda h: -h["points"]):
        total += hit["points"]
        count = f" ({hit['count']} occurrences)" if hit["count"] > 1 else ""
        findings.append(
            finding("code", hit["severity"], hit["title"] + count, hit["detail"],
                    evidence=hit["evidence"], points=hit["points"])
        )

    return signal_result(total, findings, files_scanned=files_scanned)
