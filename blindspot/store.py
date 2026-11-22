"""
Fleet storage (SQLite, standard library only).

Owner: D

The backend API and the fixture generator both use this class, so
fixtures/seed.json always has exactly the same shape as the live API.

Guard runs inside ingest(): every time an agent reports, each extension is
checked against its approved baseline (blindspot/guard.py), so drift is caught
the moment a machine auto-updates, not when someone opens the dashboard.
"""
from __future__ import annotations

import functools
import json
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from collections import Counter

from blindspot import alerts as alerting
from blindspot import guard
from blindspot.contract import level_for, now_iso
from blindspot.software import feeds
from blindspot.software.assess import assess, load_advisories, load_catalog, version_key

SCHEMA = """
CREATE TABLE IF NOT EXISTS machines (
    machine_id TEXT PRIMARY KEY, hostname TEXT, os TEXT, collected_at TEXT
);
CREATE TABLE IF NOT EXISTS installs (
    machine_id TEXT, ext_id TEXT, version TEXT, browser TEXT, profile TEXT,
    PRIMARY KEY (machine_id, ext_id, browser, profile)
);
CREATE TABLE IF NOT EXISTS analyses (
    ext_id TEXT, version TEXT, score INTEGER, level TEXT, result_json TEXT, analyzed_at TEXT,
    PRIMARY KEY (ext_id, version)
);
CREATE TABLE IF NOT EXISTS software (
    machine_id TEXT, name TEXT, version TEXT, publisher TEXT, source TEXT,
    PRIMARY KEY (machine_id, name, version)
);
CREATE TABLE IF NOT EXISTS approved_versions (
    ext_id TEXT, version TEXT, content_hash TEXT, snapshot_json TEXT, approved_at TEXT, how TEXT,
    PRIMARY KEY (ext_id, version)
);
CREATE TABLE IF NOT EXISTS quarantine (
    ext_id TEXT, version TEXT, name TEXT, diff_json TEXT, reasons_json TEXT, at TEXT, status TEXT,
    PRIMARY KEY (ext_id, version)
);
CREATE TABLE IF NOT EXISTS advisories (
    cve TEXT PRIMARY KEY, advisory_json TEXT, added_at TEXT, source TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, kind TEXT, level TEXT, subject TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS feed_cache (key TEXT PRIMARY KEY, fetched_at TEXT, data_json TEXT);
CREATE TABLE IF NOT EXISTS catalog_entries (name TEXT PRIMARY KEY, entry_json TEXT, added_at TEXT);
"""


def _locked(method):
    """One SQLite connection is shared by the API's worker threads. sqlite3 does not
    make concurrent use of one connection safe, so every public method holds the
    (re-entrant) lock: the dashboard fires several requests at once."""
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapper


class PayloadError(ValueError):
    """The agent payload does not match the contract."""


def _short(h: str | None) -> str:
    return (h or "")[:12]


class Store:
    def __init__(self, path: str = "blindspot.db", advisories: dict | None = None, catalog: dict | None = None):
        self._lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.catalog = catalog or load_catalog()  # base catalog (file); UI approvals live in catalog_entries
        self.watchlist = feeds.load_watchlist()
        self._gen = 0              # bumped whenever vulnerability data or the catalog changes
        self._sw_cache: dict = {}  # (gen, name, version) -> assessment
        self._nvd_cache: tuple | None = None
        self.feed_state = {"running": False, "progress": "", "error": None, "last_run": None}
        self._feed = advisories or load_advisories()
        if not self._meta("advisories_seeded"):
            self.reset_advisories(log=False)
        if self._meta("feed_parser") != feeds.PARSER_VERSION:
            with self._lock, self.db:
                self.db.execute("DELETE FROM feed_cache WHERE key LIKE 'nvd:%'")  # fetched again by the watcher
                self._set_meta("feed_parser", feeds.PARSER_VERSION)
        # Where alerts go. Replaced in tests; by default sends to Telegram if configured.
        self.alert_sink = self._send_alerts

    # ------------------------------------------------------------ alerts

    ALERT_KINDS = ("quarantine", "advisory", "high_risk")

    def _set_meta(self, key: str, value: str | None) -> None:
        if value is None:
            self.db.execute("DELETE FROM meta WHERE key = ?", (key,))
        else:
            self.db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, value))

    @_locked
    def alert_settings(self, reveal: bool = False) -> dict:
        token = self._meta("telegram_token") or ""
        kinds = json.loads(self._meta("alert_kinds") or json.dumps(list(self.ALERT_KINDS)))
        return {
            "telegram": {"configured": bool(token and self._meta("telegram_chat")),
                         "token": token if reveal else (token[:6] + "…" + token[-4:] if token else ""),
                         "chat_id": self._meta("telegram_chat") or "",
                         "chat_name": self._meta("telegram_chat_name") or ""},
            "dashboard_url": self._meta("dashboard_url") or "",
            "kinds": kinds,
        }

    def save_alert_settings(self, token: str | None = None, chat_id: str | None = None,
                            chat_name: str | None = None, dashboard_url: str | None = None,
                            kinds: list[str] | None = None) -> dict:
        with self._lock, self.db:
            if token is not None:
                self._set_meta("telegram_token", token.strip() or None)
            if chat_id is not None:
                self._set_meta("telegram_chat", str(chat_id).strip() or None)
            if chat_name is not None:
                self._set_meta("telegram_chat_name", chat_name.strip() or None)
            if dashboard_url is not None:
                self._set_meta("dashboard_url", dashboard_url.strip() or None)
            if kinds is not None:
                self._set_meta("alert_kinds", json.dumps([k for k in kinds if k in self.ALERT_KINDS]))
        return self.alert_settings()

    @_locked
    def telegram_config(self) -> alerting.TelegramConfig | None:
        s = self.alert_settings(reveal=True)
        if not s["telegram"]["configured"]:
            return None
        return alerting.TelegramConfig(s["telegram"]["token"], s["telegram"]["chat_id"], s["dashboard_url"])

    def _send_alerts(self, batch: list[dict]) -> None:
        def failed(message: str) -> None:
            with self._lock, self.db:
                self._event("alert-failed", "info", "Telegram", message)
        def sent(count: int) -> None:
            with self._lock, self.db:
                self._event("alert-sent", "info", "Telegram",
                            f"Sent {count} alert(s) to {self._meta('telegram_chat_name') or 'the chat'}.")
        alerting.dispatch_async(self.telegram_config(), batch, on_error=failed, on_sent=sent)

    def _flush_alerts(self, batch: list[dict]) -> None:
        kinds = set(self.alert_settings()["kinds"])
        batch = [a for a in batch if a["kind"] in kinds]
        if batch:
            self.alert_sink(batch)

    # ------------------------------------------------------------ helpers

    def _meta(self, key: str) -> str | None:
        row = self.db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def _event(self, kind: str, level: str, subject: str, detail: str) -> None:
        self.db.execute("INSERT INTO events (at, kind, level, subject, detail) VALUES (?, ?, ?, ?, ?)",
                        (now_iso(), kind, level, subject, detail))

    def _analysis(self, ext_id: str, version: str) -> dict | None:
        row = self.db.execute("SELECT result_json FROM analyses WHERE ext_id = ? AND version = ?",
                              (ext_id, version)).fetchone()
        return json.loads(row["result_json"]) if row else None

    # ------------------------------------------------------------ write

    def ingest(self, payload: dict) -> dict:
        machine = payload.get("machine") or {}
        extensions = payload.get("extensions")
        if not machine.get("machine_id") or not isinstance(extensions, list):
            raise PayloadError("payload needs machine.machine_id and an extensions list")
        mid = str(machine["machine_id"])
        hostname = machine.get("hostname", mid)
        guard_hits = []
        batch: list[dict] = []
        with self._lock, self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO machines VALUES (?, ?, ?, ?)",
                (mid, hostname, machine.get("os", ""), machine.get("collected_at", "")),
            )
            # a new report replaces everything previously known about this machine
            had_software = {(r["name"], r["version"]) for r in
                            self.db.execute("SELECT name, version FROM software WHERE machine_id = ?", (mid,))}
            self.db.execute("DELETE FROM installs WHERE machine_id = ?", (mid,))
            self.db.execute("DELETE FROM software WHERE machine_id = ?", (mid,))
            for ext in extensions:
                if not ext.get("id"):
                    continue
                self.db.execute(
                    "INSERT OR REPLACE INTO installs VALUES (?, ?, ?, ?, ?)",
                    (mid, ext["id"], ext.get("version", ""), ext.get("browser", "chrome"),
                     ext.get("profile", "Default")),
                )
                stored = {k: v for k, v in ext.items() if k not in ("browser", "profile", "files", "path")}
                previous = self._analysis(ext["id"], ext.get("version", ""))
                batch.extend(self._risk_rise(previous, stored, hostname))
                self.db.execute(
                    "INSERT OR REPLACE INTO analyses VALUES (?, ?, ?, ?, ?, ?)",
                    (ext["id"], ext.get("version", ""), int(ext.get("score", 0)), ext.get("level", "low"),
                     json.dumps(stored), ext.get("analyzed_at", "")),
                )
                hit = self._guard_check(stored, hostname)
                if hit:
                    guard_hits.append(hit)
                    batch.extend(self._alerts_for(hit, stored, hostname))
            new_pins = [h for h in guard_hits if h["action"] == "pinned"]
            if new_pins:
                self._event("baseline", "info", hostname,
                            f"First report: {len(new_pins)} extension build(s) pinned. Guard now compares every update with them.")
            for item in payload.get("software") or []:
                if item.get("name"):
                    self.db.execute(
                        "INSERT OR REPLACE INTO software VALUES (?, ?, ?, ?, ?)",
                        (mid, item["name"], item.get("version", ""), item.get("publisher", ""),
                         item.get("source", "")),
                    )
        batch.extend(self._blocked_installs(payload.get("software") or [], had_software, hostname))
        self._flush_alerts(batch)
        return {"machine_id": mid, "extensions": len(extensions),
                "software": len(payload.get("software") or []), "guard": guard_hits}

    def _blocked_installs(self, software: list[dict], had: set, hostname: str) -> list[dict]:
        """A computer now has a software version that is blocked (a vulnerable install)."""
        with self._lock:
            curated, catalog = self.advisories(), self.current_catalog()
            hits = []
            for item in software:
                if not item.get("name") or (item["name"], item.get("version", "")) in had:
                    continue
                a = self._assess({"name": item["name"], "version": item.get("version", ""),
                                  "publisher": item.get("publisher", "")}, curated, catalog)
                if a["status"] == "blocked":
                    hits.append(a)
            if not hits:
                return []
            with self.db:
                for a in hits:
                    self._event("blocked-install", "high", f"{a['name']} {a['version']}",
                                f"Installed on {hostname} but blocked. {a['reasons'][0]}.")
        return [{"kind": "advisory", "subject": f"{a['name']} {a['version']} on {hostname}",
                 "detail": f"Blocked version installed. {a['reasons'][0]}."} for a in hits]

    def _risk_rise(self, previous: dict | None, ext: dict, hostname: str) -> list[dict]:
        """Same build, new verdict: e.g. the store removed it, or a detection rule improved."""
        if not previous:
            return []
        before = guard.snapshot(previous)["severity"]
        after = guard.snapshot(ext)["severity"]
        if after in ("High", "Critical") and guard._rank(after) > guard._rank(before):
            top = next((f["title"] for f in ext.get("findings", []) if f.get("severity") != "info"), "")
            self._event("risk-up", "high", ext.get("name", ext["id"]),
                        f"Same version {ext.get('version')}, risk rose from {before} to {after} on {hostname}. {top}.")
            return [{"kind": "high_risk", "subject": f"{ext.get('name', ext['id'])} ({after}, {ext.get('score', '')})",
                     "detail": f"on {hostname}. Risk rose from {before} to {after} without an update. {top}."}]
        return []

    @staticmethod
    def _alerts_for(hit: dict, ext: dict, hostname: str) -> list[dict]:
        name = ext.get("name", ext["id"])
        if hit["action"] == "quarantined" and hit.get("reasons"):
            return [{"kind": "quarantine", "subject": f"{name} {hit['version']}",
                     "detail": f"on {hostname}. " + "; ".join(hit["reasons"]) + ". Same extension ID, new code."}]
        rating = ext.get("rating") or {}
        severity = rating.get("raw_severity") or rating.get("severity") or ""
        if hit["action"] == "pinned" and severity in ("High", "Critical") and not ext.get("known_good"):
            top = next((f["title"] for f in ext.get("findings", []) if f.get("severity") != "info"), "")
            return [{"kind": "high_risk", "subject": f"{name} ({severity}, {ext.get('score', '')})",
                     "detail": f"on {hostname}. {top}."}]
        return []

    def _guard_check(self, ext: dict, hostname: str) -> dict | None:
        """Compare one reported extension with its approved baseline. Runs inside ingest's transaction."""
        ext_id, version = ext["id"], ext.get("version", "")
        approved = self.db.execute("SELECT * FROM approved_versions WHERE ext_id = ?", (ext_id,)).fetchall()
        if not approved:
            # Every extension is pinned the first time it is seen, so every later update is
            # compared with it. Approved-list extensions are marked as such.
            if ext.get("known_good"):
                self._approve(ext, "approved list (first seen)")
                self._event("baseline", "info", ext.get("name", ext_id),
                            f"On the approved list. Pinned to version {version}, code hash {_short(ext.get('content_hash'))}.")
            else:
                self._approve(ext, "first seen")
            return {"ext_id": ext_id, "action": "pinned", "version": version}

        same = next((r for r in approved if r["version"] == version), None)
        if same and (not same["content_hash"] or not ext.get("content_hash")
                     or same["content_hash"] == ext.get("content_hash")):
            return None
        if self.db.execute("SELECT 1 FROM quarantine WHERE ext_id = ? AND version = ? AND status = 'quarantined'",
                           (ext_id, version)).fetchone():
            return {"ext_id": ext_id, "action": "quarantined", "version": version}

        baseline = same or max(approved, key=lambda r: (version_key(r["version"]), r["approved_at"]))
        base_snap = json.loads(baseline["snapshot_json"])
        d = guard.diff(base_snap, guard.snapshot(ext))
        decision, reasons = guard.verdict(d)
        name = ext.get("name", ext_id)
        if decision == "auto-approve":
            self._approve(ext, "automatic: benign update")
            self._event("auto-approved", "info", name,
                        f"{d['from_version']} -> {d['to_version']} on {hostname}. {reasons[0]}.")
            return {"ext_id": ext_id, "action": "auto-approved", "version": version}
        self.db.execute(
            "INSERT OR REPLACE INTO quarantine VALUES (?, ?, ?, ?, ?, ?, 'quarantined')",
            (ext_id, version, name, json.dumps(d), json.dumps(reasons), now_iso()),
        )
        self._event("quarantined", "high", name,
                    f"{d['from_version']} -> {d['to_version']} on {hostname}. " + "; ".join(reasons) + ".")
        return {"ext_id": ext_id, "action": "quarantined", "version": version, "reasons": reasons}

    def _approve(self, ext: dict, how: str) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO approved_versions VALUES (?, ?, ?, ?, ?, ?)",
            (ext["id"], ext.get("version", ""), ext.get("content_hash"), json.dumps(guard.snapshot(ext)),
             now_iso(), how),
        )

    def approve_extension(self, ext_id: str, version: str | None = None, by: str = "admin") -> dict:
        """A person approves (pins) a version. Releases it from quarantine."""
        with self._lock, self.db:
            if version is None:
                row = self.db.execute("SELECT version FROM installs WHERE ext_id = ?", (ext_id,)).fetchall()
                if not row:
                    raise KeyError(ext_id)
                version = max((r["version"] for r in row), key=version_key)
            ext = self._analysis(ext_id, version)
            if ext is None:
                raise KeyError(f"{ext_id} {version}")
            self._approve(ext, f"approved by {by}")
            released = self.db.execute(
                "UPDATE quarantine SET status = 'released' WHERE ext_id = ? AND version = ? AND status = 'quarantined'",
                (ext_id, version)).rowcount
            self._event("approved", "info", ext.get("name", ext_id),
                        f"Version {version} approved by {by}" + (" and released from quarantine." if released else "."))
        return {"ext_id": ext_id, "version": version, "released": bool(released)}

    def clear(self) -> dict:
        """Forget every machine, extension, approval and event. The advisory feed stays."""
        with self._lock, self.db:
            counts = {t: self.db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("machines", "analyses")}
            for table in ("machines", "installs", "analyses", "software", "approved_versions", "quarantine", "events"):
                self.db.execute(f"DELETE FROM {table}")  # noqa: S608 -- fixed table names
            self._event("cleared", "info", "All data", "Fleet data cleared from the dashboard.")
        return counts

    # ------------------------------------------------------------ advisories

    @_locked
    def advisories(self) -> list[dict]:
        rows = self.db.execute("SELECT advisory_json, added_at, source FROM advisories ORDER BY added_at").fetchall()
        return [dict(json.loads(r["advisory_json"]), added_at=r["added_at"], source=r["source"]) for r in rows]

    def reset_advisories(self, log: bool = True) -> dict:
        with self._lock, self.db:
            self.db.execute("DELETE FROM advisories")
            for adv in self._feed["published"]:
                self.db.execute("INSERT OR REPLACE INTO advisories VALUES (?, ?, ?, ?)",
                                (adv["cve"], json.dumps(adv), now_iso(), "feed"))
            self.db.execute("INSERT OR REPLACE INTO meta VALUES ('advisories_seeded', '1')")
            if hasattr(self, "_sw_cache"):
                self._bump()
            if log:
                self._event("feed", "info", "Advisory feed", "Reset to the initial advisories.")
        return {"advisories": len(self._feed["published"])}

    def sync_advisories(self) -> dict:
        """Pull new advisories from the feed. Re-evaluates every installed program at once."""
        before = {(s["name"], s["version"]): s["status"] for s in self.software()}
        added = []
        with self._lock, self.db:
            for adv in self._feed["incoming"]:
                if not self.db.execute("SELECT 1 FROM advisories WHERE cve = ?", (adv["cve"],)).fetchone():
                    self.db.execute("INSERT INTO advisories VALUES (?, ?, ?, ?)",
                                    (adv["cve"], json.dumps(adv), now_iso(), "feed"))
                    added.append(adv)
        alerts: list[dict] = []
        self._bump()
        newly_blocked = [s for s in self.software()
                         if s["status"] == "blocked" and before.get((s["name"], s["version"])) != "blocked"]
        with self._lock, self.db:
            for adv in added:
                hits = [s for s in newly_blocked if any(v["cve"] == adv["cve"] for v in s["vulnerabilities"])]
                machines = sum(s["machines"] for s in hits)
                kev = " Actively exploited (CISA KEV)." if adv.get("kev") else ""
                if hits:
                    detail = (f"{adv['product']}: {', '.join(s['version'] for s in hits)} blocked on {machines} "
                              f"machine(s) until {adv.get('fixed')} or later.{kev}")
                else:
                    detail = f"{adv['product']}: no installed version affected.{kev}"
                self._event("advisory", "high" if hits else "info", adv["cve"], detail)
                if hits:
                    alerts.append({"kind": "advisory", "subject": adv["cve"], "detail": detail})
        self._flush_alerts(alerts)
        return {"added": [a["cve"] for a in added], "newly_blocked": len(newly_blocked)}

    # ------------------------------------------------------------ read

    def _quarantined(self) -> dict[tuple, dict]:
        rows = self.db.execute("SELECT * FROM quarantine WHERE status = 'quarantined'").fetchall()
        return {(r["ext_id"], r["version"]): {"reasons": json.loads(r["reasons_json"]),
                                              "diff": json.loads(r["diff_json"]), "at": r["at"]} for r in rows}

    def _latest_results(self) -> dict[str, dict]:
        """One analysis per installed extension id: the newest installed version.
        Adds the Guard state (pinned / quarantined) to each."""
        rows = self.db.execute(
            """SELECT a.ext_id, a.version, a.result_json FROM analyses a
               JOIN (SELECT DISTINCT ext_id, version FROM installs) i
                 ON i.ext_id = a.ext_id AND i.version = a.version"""
        ).fetchall()
        by_id: dict[str, list] = {}
        for row in rows:
            by_id.setdefault(row["ext_id"], []).append(row)
        quarantined = self._quarantined()
        pinned = {r["ext_id"] for r in self.db.execute("SELECT DISTINCT ext_id FROM approved_versions")}
        out = {}
        for ext_id, versions in by_id.items():
            versions.sort(key=lambda r: version_key(r["version"]))
            result = json.loads(versions[-1]["result_json"])
            result["installed_versions"] = [r["version"] for r in versions]
            q = [dict(quarantined[(ext_id, r["version"])], version=r["version"])
                 for r in versions if (ext_id, r["version"]) in quarantined]
            result["guard"] = {"pinned": ext_id in pinned, "quarantined": q}
            if q:
                result["recommendation"] = "quarantine"
                rating = result.get("rating") or {}
                if rating.get("capped") and any(x["version"] == result["version"] for x in q):
                    # the approved-ID cap does not apply to a build nobody approved
                    result["score"] = rating.get("raw_score", result["score"])
                    result["level"] = level_for(result["score"])
                    result["rating"] = dict(rating, severity=rating.get("raw_severity"), capped=False,
                                            uncapped_by_guard=True)
            out[ext_id] = result
        return out

    def _install_rows(self):
        return self.db.execute(
            """SELECT i.*, m.hostname FROM installs i JOIN machines m ON m.machine_id = i.machine_id
               ORDER BY m.hostname"""
        ).fetchall()

    @_locked
    def results(self) -> list[dict]:
        return sorted(self._latest_results().values(), key=lambda r: r["score"], reverse=True)

    @staticmethod
    def _row(ext_id: str, r: dict, machines: list) -> dict:
        rating = r.get("rating") or {}
        return {
            "id": ext_id, "name": r["name"], "version": r["version"], "score": r["score"],
            "level": r["level"], "severity": rating.get("severity", r["level"].title()),
            "recommendation": r["recommendation"], "known_good": r.get("known_good", False),
            "installs": len(machines), "machines": machines,
            "high_risk_permissions": r.get("high_risk_permissions", []), "signals": r["signals"],
            "top_finding": next((f["title"] for f in r.get("findings", []) if f["signal"] != "score"),
                                r["findings"][0]["title"] if r.get("findings") else ""),
            "ai": bool((r.get("ai") or {}).get("is_ai")),
            "exposure": [e["system"] for e in r.get("exposure", [])],
            "versions": r.get("installed_versions", [r["version"]]),
            "quarantined": bool((r.get("guard") or {}).get("quarantined")),
            "pinned": bool((r.get("guard") or {}).get("pinned")),
        }

    @_locked
    def extensions(self) -> list[dict]:
        results = self._latest_results()
        machines: dict[str, set] = {}
        for row in self._install_rows():
            machines.setdefault(row["ext_id"], set()).add(row["hostname"])
        out = [self._row(ext_id, r, sorted(machines.get(ext_id, ()))) for ext_id, r in results.items()]
        return sorted(out, key=lambda e: (not e["quarantined"], -e["score"], e["name"].lower()))

    @_locked
    def extension(self, ext_id: str) -> dict | None:
        result = self._latest_results().get(ext_id)
        if result is None:
            return None
        result["installs"] = [
            {"machine_id": row["machine_id"], "hostname": row["hostname"], "browser": row["browser"],
             "profile": row["profile"], "version": row["version"]}
            for row in self._install_rows() if row["ext_id"] == ext_id
        ]
        return result

    @_locked
    def machines(self) -> list[dict]:
        results = self._latest_results()
        quarantined = self._quarantined()
        per_machine: dict[str, list] = {}
        q_machine: Counter = Counter()
        for row in self._install_rows():
            per_machine.setdefault(row["machine_id"], []).append(row["ext_id"])
            if (row["ext_id"], row["version"]) in quarantined:
                q_machine[row["machine_id"]] += 1
        blocked_sw = Counter(r["machine_id"] for r in self._software_rows() if r["status"] == "blocked")
        out = []
        for row in self.db.execute("SELECT * FROM machines ORDER BY hostname").fetchall():
            ids = per_machine.get(row["machine_id"], [])
            out.append({
                "machine_id": row["machine_id"], "hostname": row["hostname"], "os": row["os"],
                "collected_at": row["collected_at"], "extensions": len(ids),
                "high_risk": sum(1 for i in ids if results.get(i, {}).get("level") == "high"),
                "quarantined": q_machine.get(row["machine_id"], 0),
                "software": self.db.execute("SELECT COUNT(*) FROM software WHERE machine_id = ?",
                                            (row["machine_id"],)).fetchone()[0],
                "software_blocked": blocked_sw.get(row["machine_id"], 0),
            })
        return out

    @_locked
    def machine(self, machine_id: str) -> dict | None:
        row = self.db.execute("SELECT * FROM machines WHERE machine_id = ? OR hostname = ?",
                              (machine_id, machine_id)).fetchone()
        if row is None:
            return None
        mid = row["machine_id"]
        results = self._latest_results()
        quarantined = self._quarantined()
        exts = []
        for inst in self.db.execute("SELECT * FROM installs WHERE machine_id = ?", (mid,)).fetchall():
            r = self._analysis(inst["ext_id"], inst["version"]) or results.get(inst["ext_id"])
            if not r:
                continue
            latest = results.get(inst["ext_id"], r)
            item = self._row(inst["ext_id"], dict(r, guard=latest.get("guard"),
                                                  installed_versions=latest.get("installed_versions")), [])
            item.update(version=inst["version"], browser=inst["browser"], profile=inst["profile"],
                        quarantined=(inst["ext_id"], inst["version"]) in quarantined)
            if item["quarantined"]:
                item["recommendation"] = "quarantine"
            item.pop("installs"); item.pop("machines")
            exts.append(item)
        exts.sort(key=lambda e: (not e["quarantined"], -e["score"], e["name"].lower()))
        software = [s for s in self._software_rows() if s["machine_id"] == mid]
        software.sort(key=lambda s: (["blocked", "review", "unreviewed", "allowed"].index(s["status"]),
                                     s["name"].lower()))
        return {"machine_id": mid, "hostname": row["hostname"], "os": row["os"],
                "collected_at": row["collected_at"], "extensions": exts,
                "software": [{k: v for k, v in s.items() if k != "machine_id"} for s in software]}

    # ------------------------------------------------------------ software

    def _bump(self) -> None:
        self._gen += 1
        self._sw_cache.clear()
        self._nvd_cache = None

    def _watch_for(self, name: str) -> list[dict]:
        return [w for w in self.watchlist if re.search(w["match"], name or "", re.I)]

    def _nvd_by_watch(self) -> dict[str, list[dict]]:
        """NVD advisories per watch-list product, with CISA KEV applied. Cached per data generation."""
        if self._nvd_cache and self._nvd_cache[0] == self._gen:
            return self._nvd_cache[1]
        kev_row = self.db.execute("SELECT data_json FROM feed_cache WHERE key = 'kev'").fetchone()
        kev = json.loads(kev_row["data_json"]) if kev_row else {}
        by_watch: dict[str, dict] = {}
        for row in self.db.execute("SELECT key, data_json FROM feed_cache WHERE key LIKE 'nvd:%'").fetchall():
            for adv in json.loads(row["data_json"]):
                bucket = by_watch.setdefault(adv["product"], {})
                if adv["cve"] in bucket:
                    bucket[adv["cve"]]["ranges"] = bucket[adv["cve"]]["ranges"] + adv["ranges"]
                    continue
                if adv["cve"] in kev:
                    adv = dict(adv, kev=True, exploitation="active", kev_added=kev[adv["cve"]])
                bucket[adv["cve"]] = adv
        result = {k: list(v.values()) for k, v in by_watch.items()}
        self._nvd_cache = (self._gen, result)
        return result

    def _advisories_for(self, name: str, curated: list[dict]) -> list[dict]:
        nvd = self._nvd_by_watch()
        live = [a for w in self._watch_for(name) for a in nvd.get(w["name"], [])]
        seen = {a["cve"] for a in live}
        return live + [a for a in curated if a["cve"] not in seen]

    def _assess(self, item: dict, curated: list[dict], catalog: dict) -> dict:
        key = (self._gen, item["name"], item["version"])
        if key not in self._sw_cache:
            a = assess(item, self._advisories_for(item["name"], curated), catalog)
            a["tracked"] = [w["name"] for w in self._watch_for(item["name"])]
            self._sw_cache[key] = a
        return self._sw_cache[key]

    def _software_rows(self) -> list[dict]:
        curated = self.advisories()
        catalog = self.current_catalog()
        out = []
        for row in self.db.execute("SELECT * FROM software").fetchall():
            a = self._assess(dict(row), curated, catalog)
            out.append(dict(a, machine_id=row["machine_id"], publisher=row["publisher"]))
        return out

    # ------------------------------------------------------------ catalog (approved software)

    @_locked
    def current_catalog(self) -> dict:
        entries = {e["name"]: e for e in self.catalog.get("approved", [])}
        for row in self.db.execute("SELECT entry_json FROM catalog_entries").fetchall():
            e = json.loads(row["entry_json"])
            entries[e["name"]] = e
        return dict(self.catalog, approved=list(entries.values()))

    @staticmethod
    def product_name(display_name: str) -> str:
        """'7-Zip 24.08 (x64)' -> '7-Zip'; 'Notepad++ (64-bit x64)' -> 'Notepad++'."""
        name = re.sub(r"\s*\((x64|x86|64-bit|32-bit|arm64|64-bit x64|x64 [a-z-]+)\)", "", display_name or "", flags=re.I)
        name = re.sub(r"\s+v?\d+(\.\d+)+.*$", "", name)
        name = re.sub(r"\s+-\s*$", "", name).strip()
        return name or (display_name or "").strip()

    @_locked
    def approve_software(self, name: str, version: str, by: str = "admin", publisher: str = "") -> dict:
        base = self.product_name(name)
        entry = {"name": base, "match": "^" + re.escape(base) + r"(?!\w)", "publisher": publisher,
                 "approved_version": version, "approved_by": by,
                 "approved_at": datetime.now(timezone.utc).date().isoformat(), "mission": "support",
                 "signer": None, "product": None}
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO catalog_entries VALUES (?, ?, ?)",
                            (base, json.dumps(entry), now_iso()))
            self._event("software-approved", "info", base, f"Version {version} approved by {by}. "
                        "Blindspot blocks it automatically if an advisory hits it later.")
        self._bump()
        return entry

    @_locked
    def unapprove_software(self, name: str) -> bool:
        with self.db:
            removed = self.db.execute("DELETE FROM catalog_entries WHERE name = ?", (name,)).rowcount
            if removed:
                self._event("software-removed", "info", name, "Removed from the approved catalog.")
        self._bump()
        return bool(removed)

    # ------------------------------------------------------------ live vulnerability feeds

    NVD_MAX_AGE = timedelta(hours=6)
    KEV_MAX_AGE = timedelta(hours=24)

    def _fresh(self, key: str, max_age: timedelta) -> bool:
        row = self.db.execute("SELECT fetched_at FROM feed_cache WHERE key = ?", (key,)).fetchone()
        if not row:
            return False
        try:
            return datetime.now(timezone.utc) - datetime.fromisoformat(row["fetched_at"]) < max_age
        except ValueError:
            return False

    @_locked
    def feed_targets(self) -> list[dict]:
        """Watch-list products that are installed somewhere or approved in the catalog."""
        names = [r["name"] for r in self.db.execute("SELECT DISTINCT name FROM software")]
        names += [e["name"] for e in self.current_catalog()["approved"]]
        return [w for w in self.watchlist if any(re.search(w["match"], n or "", re.I) for n in names)]

    @_locked
    def feeds_due(self) -> bool:
        return not self._fresh("kev", self.KEV_MAX_AGE) or self.feeds_missing()

    @_locked
    def feeds_missing(self) -> bool:
        return any(not self._fresh(f"nvd:{c}", self.NVD_MAX_AGE) for w in self.feed_targets() for c in w["cpe"])

    def refresh_feeds(self, force: bool = False, get=None, sleep=time.sleep) -> dict:
        """Fetch CISA KEV and NVD for installed watch-list products; block and alert on new hits.
        Network calls run outside the lock, so the dashboard stays responsive."""
        get = get or feeds.http_get
        with self._lock:
            if self.feed_state["running"]:
                return self.feed_status()
            self.feed_state.update(running=True, error=None, progress="starting")
            before = {(s["name"], s["version"]): s["status"] for s in self.software()}
            targets = self.feed_targets()
            api_key = self._meta("nvd_api_key")
        errors, fetched = [], 0
        try:
            if force or not self._fresh_locked("kev", self.KEV_MAX_AGE):
                self.feed_state["progress"] = "CISA KEV"
                try:
                    kev = feeds.fetch_kev(get=get)
                    self._cache_put("kev", kev)
                except feeds.FeedError as exc:
                    errors.append(f"CISA KEV: {exc}")
            jobs = [(w, c) for w in targets for c in w["cpe"]
                    if force or not self._fresh_locked(f"nvd:{c}", self.NVD_MAX_AGE)]
            for i, (watch, cpe) in enumerate(jobs, 1):
                self.feed_state["progress"] = f"NVD {i}/{len(jobs)}: {watch['name']}"
                if fetched:
                    sleep(0.7 if api_key else 6.5)
                try:
                    self._cache_put(f"nvd:{cpe}", feeds.fetch_nvd(cpe, watch, api_key=api_key, get=get, sleep=sleep))
                    fetched += 1
                except feeds.FeedError as exc:
                    errors.append(f"{watch['name']}: {exc}")
                    if "rate limit" in str(exc) or "Cannot reach" in str(exc):
                        break  # no point asking for the next product now; the watcher retries later
        finally:
            with self._lock:
                self._bump()
                after = self.software()
                newly = [s for s in after if s["status"] == "blocked"
                         and before.get((s["name"], s["version"])) not in (None, "blocked")]
                alerts = []
                with self.db:
                    for s in newly:
                        reason = s["reasons"][0] if s["reasons"] else "new advisory"
                        detail = f"{s['name']} {s['version']} on {s['machines']} machine(s). {reason}."
                        self._event("advisory", "high", s["vulnerabilities"][0]["cve"] if s["vulnerabilities"] else s["name"], detail)
                        alerts.append({"kind": "advisory", "subject": f"{s['name']} {s['version']}", "detail": detail})
                    self._set_meta("feeds_checked_at", now_iso())
                self.feed_state.update(running=False, progress="", last_run=now_iso(),
                                       error="; ".join(errors[:3]) or None)
            self._flush_alerts(alerts)
        return self.feed_status()

    def _fresh_locked(self, key: str, max_age: timedelta) -> bool:
        with self._lock:
            return self._fresh(key, max_age)

    def _cache_put(self, key: str, data) -> None:
        with self._lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO feed_cache VALUES (?, ?, ?)",
                            (key, datetime.now(timezone.utc).isoformat(timespec="seconds"), json.dumps(data)))

    @_locked
    def feed_status(self) -> dict:
        kev = self.db.execute("SELECT fetched_at, data_json FROM feed_cache WHERE key = 'kev'").fetchone()
        nvd = self.db.execute("SELECT COUNT(*) AS n, MIN(fetched_at) AS oldest FROM feed_cache WHERE key LIKE 'nvd:%'").fetchone()
        targets = self.feed_targets()
        return {
            **self.feed_state,
            "kev": {"count": len(json.loads(kev["data_json"])) if kev else 0, "fetched_at": kev["fetched_at"] if kev else None},
            "nvd": {"products": nvd["n"], "oldest": nvd["oldest"],
                    "tracked": [w["name"] for w in targets], "watchlist_size": len(self.watchlist)},
            "checked_at": self._meta("feeds_checked_at"),
            "api_key": bool(self._meta("nvd_api_key")),
        }

    @_locked
    def set_nvd_key(self, key: str) -> dict:
        with self.db:
            self._set_meta("nvd_api_key", key.strip() or None)
        return {"api_key": bool(key.strip())}

    @_locked
    def software(self) -> list[dict]:
        hosts = {r["machine_id"]: r["hostname"] for r in self.db.execute("SELECT machine_id, hostname FROM machines")}
        grouped: dict[tuple, dict] = {}
        for s in self._software_rows():
            key = (s["name"], s["version"], s["publisher"])
            entry = grouped.setdefault(key, dict({k: v for k, v in s.items() if k != "machine_id"},
                                                 machines=0, hostnames=[]))
            entry["machines"] += 1
            entry["hostnames"].append(hosts.get(s["machine_id"], s["machine_id"]))
        order = {"blocked": 0, "review": 1, "unreviewed": 2, "allowed": 3}
        return sorted(grouped.values(), key=lambda s: (order[s["status"]], -s["score"], s["name"].lower()))

    # ------------------------------------------------------------ guard

    @_locked
    def guard(self) -> dict:
        results = self._latest_results()
        installs = Counter()
        for row in self._install_rows():
            installs[(row["ext_id"], row["version"])] += 1
        approved: dict[str, list] = {}
        for r in self.db.execute("SELECT * FROM approved_versions ORDER BY approved_at").fetchall():
            approved.setdefault(r["ext_id"], []).append(r)

        ext_rows = []
        for ext_id, r in sorted(results.items(), key=lambda kv: kv[1]["name"].lower()):
            versions = approved.get(ext_id, [])
            baseline = max(versions, key=lambda v: version_key(v["version"])) if versions else None
            q = r["guard"]["quarantined"]
            state = "quarantined" if q else ("pinned" if baseline else "not pinned")
            ext_rows.append({
                "id": ext_id, "name": r["name"], "state": state,
                "baseline_version": baseline["version"] if baseline else None,
                "baseline_hash": _short(baseline["content_hash"]) if baseline else None,
                "approved_how": baseline["how"] if baseline else None,
                "approved_versions": [v["version"] for v in versions],
                "installed": [{"version": v, "machines": installs[(ext_id, v)],
                               "quarantined": any(x["version"] == v for x in q)}
                              for v in r["installed_versions"]],
                "quarantine": q, "score": r["score"], "severity": (r.get("rating") or {}).get("severity"),
            })
        ext_rows.sort(key=lambda e: ({"quarantined": 0, "pinned": 1, "not pinned": 2}[e["state"]], e["name"].lower()))

        sw = self.software()
        catalog = []
        catalog_now = self.current_catalog()
        for entry in catalog_now["approved"]:
            hits = [s for s in sw if s.get("catalog_name") == entry["name"]]
            open_cves = sorted({v["cve"] for s in hits for v in s["vulnerabilities"]})
            blocked = [s for s in hits if s["status"] == "blocked"]
            catalog.append({
                "name": entry["name"], "publisher": entry.get("publisher", ""),
                "approved_version": entry.get("approved_version"), "approved_by": entry.get("approved_by"),
                "approved_at": entry.get("approved_at"), "note": entry.get("note", ""),
                "state": "blocked" if blocked else "allowed",
                "allowed_from": max([entry.get("approved_version") or "0"]
                                    + [s["fixed_in"] for s in blocked if s.get("fixed_in")], key=version_key),
                "installed": [{"version": s["version"], "machines": s["machines"], "status": s["status"],
                               "reasons": s["reasons"], "decision": s["decision"]} for s in hits],
                "open_cves": open_cves,
            })
        unapproved = [s for s in sw if not s["approved"] and s["status"] in ("blocked", "review")]

        events = [dict(r) for r in self.db.execute("SELECT * FROM events ORDER BY id DESC LIMIT 60").fetchall()]
        return {
            "extensions": ext_rows, "catalog": catalog, "unapproved": unapproved,
            "advisories": self.advisories(),
            "pending_advisories": [a["cve"] for a in self._feed["incoming"]
                                   if a["cve"] not in {x["cve"] for x in self.advisories()}],
            "events": events,
            "block_at_decision": catalog_now.get("block_at_decision"),
        }

    # ------------------------------------------------------------ crown jewels, summary

    @_locked
    def exposure(self, systems: list[dict] | None = None) -> list[dict]:
        """Per crown-jewel system: which extensions on which machines can read it.
        Checked per installed version: an old build may not reach what a new one does."""
        from blindspot.analyzer.exposure import load_crown_jewels
        systems = load_crown_jewels() if systems is None else systems
        rows = {e["id"]: e for e in self.extensions()}
        reach: dict[str, dict[str, set]] = {}  # system -> ext_id -> hostnames
        for inst in self._install_rows():
            analysis = self._analysis(inst["ext_id"], inst["version"]) or {}
            for hit in analysis.get("exposure", []):
                reach.setdefault(hit["system"], {}).setdefault(inst["ext_id"], set()).add(inst["hostname"])
        out = []
        for system in systems:
            hits = reach.get(system["name"], {})
            exts = [dict({k: rows[i][k] for k in ("id", "name", "score", "level", "recommendation", "ai")},
                         installs=len(hosts), machines=sorted(hosts))
                    for i, hosts in hits.items() if i in rows]
            exts.sort(key=lambda e: -e["score"])
            machines = sorted({m for e in exts for m in e["machines"]})
            out.append({
                "system": system["name"], "hosts": system["hosts"], "extensions": exts,
                "extension_count": len(exts), "machine_count": len(machines), "machines": machines,
                "ai_count": sum(1 for e in exts if e["ai"]),
            })
        return out

    @_locked
    def summary(self) -> dict:
        exts = self.extensions()
        levels = Counter(e["level"] for e in exts)
        recs = Counter(e["recommendation"] for e in exts)
        machines = self.db.execute("SELECT COUNT(*), MAX(collected_at) FROM machines").fetchone()
        installs = self.db.execute("SELECT COUNT(*) FROM installs").fetchone()[0]
        sw = self.software()
        sw_status = Counter(s["status"] for s in sw)
        return {
            "machines": machines[0], "last_seen": machines[1], "extensions_installed": installs,
            "unique_extensions": len(exts),
            "by_level": {lvl: levels.get(lvl, 0) for lvl in ("high", "medium", "low")},
            "by_recommendation": {k: recs.get(k, 0) for k in ("quarantine", "block", "contain", "review", "allow")},
            "installs_at_high_risk": sum(e["installs"] for e in exts if e["level"] == "high"),
            "software_titles": len({s["name"] for s in sw}),
            "software_by_status": {k: sw_status.get(k, 0) for k in ("blocked", "review", "unreviewed", "allowed")},
            "software_kev": sum(1 for s in sw if s["kev"]),
            "ai_extensions": sum(1 for e in exts if e["ai"]),
            "crown_jewel_exposed": sum(1 for e in exts if e["exposure"]),
            "machines_with_crown_jewel_exposure": len({m for e in exts if e["exposure"] for m in e["machines"]}),
            "quarantined": sum(1 for e in exts if e["quarantined"]),
        }

