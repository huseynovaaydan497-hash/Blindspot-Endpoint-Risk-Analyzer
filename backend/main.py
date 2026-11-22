"""
Blindspot API server.

Owner: D

Run:
    uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

Then open http://localhost:8000 for the dashboard and
http://localhost:8000/docs for the interactive API documentation.
"""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles

from blindspot import __version__
from blindspot import alerts as alerting
from blindspot.agent_bundle import build_agent_zip, lan_addresses
from blindspot.policy.policy import generate_policy, render_windows_reg
from blindspot.policy.software_policy import generate_software_policy, render_applocker
from blindspot.report.report import build_report, render_html
from blindspot.store import PayloadError, Store

ROOT = Path(__file__).resolve().parent.parent
store = Store(os.environ.get("BLINDSPOT_DB", str(ROOT / "blindspot.db")))

app = FastAPI(title="Blindspot API", version=__version__,
              description="Endpoint browser-extension inventory, risk scoring and policy generation.")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/api/v1/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


FEEDS_ON = os.environ.get("BLINDSPOT_FEEDS", "on") != "off"


def _refresh_in_background(force: bool = False) -> None:
    if not FEEDS_ON or store.feed_state["running"]:
        return

    def run():
        try:
            store.refresh_feeds(force=force)
        except Exception as exc:  # noqa: BLE001 -- the dashboard must keep running
            print(f"[blindspot] vulnerability feed refresh failed: {exc}")
    threading.Thread(target=run, daemon=True).start()


def _feed_watcher() -> None:
    """Keeps NVD / CISA KEV data fresh: checks every minute, fetches only what is stale
    (NVD per product every 6 hours, KEV daily). New hits block software and send alerts."""
    time.sleep(10)
    while True:
        try:
            if store.feeds_due():
                store.refresh_feeds()
        except Exception as exc:  # noqa: BLE001
            print(f"[blindspot] vulnerability feed refresh failed: {exc}")
        time.sleep(60)


if FEEDS_ON:
    threading.Thread(target=_feed_watcher, daemon=True, name="blindspot-feeds").start()


@app.post("/api/v1/inventory")
def ingest(payload: dict = Body(...)) -> dict:
    """Agents send their inventory + analysis results here."""
    try:
        result = store.ingest(payload)
    except PayloadError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if payload.get("software") and store.feeds_missing():
        _refresh_in_background()  # new programs: look them up in NVD now, not in an hour
    return result


@app.get("/api/v1/fleet/summary")
def fleet_summary() -> dict:
    return store.summary()


@app.get("/api/v1/extensions")
def list_extensions() -> list[dict]:
    return store.extensions()


@app.get("/api/v1/extensions/{ext_id}")
def get_extension(ext_id: str) -> dict:
    result = store.extension(ext_id)
    if result is None:
        raise HTTPException(status_code=404, detail="extension not found")
    return result


@app.get("/api/v1/machines")
def list_machines() -> list[dict]:
    return store.machines()


@app.get("/api/v1/machines/{machine_id}")
def get_machine(machine_id: str) -> dict:
    """One machine: its extensions (with the version installed there) and its software."""
    result = store.machine(machine_id)
    if result is None:
        raise HTTPException(status_code=404, detail="machine not found")
    return result


@app.get("/api/v1/software")
def list_software() -> list[dict]:
    return store.software()


@app.get("/api/v1/report.json")
def report_json() -> dict:
    return build_report(store.results(), scope={"machines": store.summary()["machines"]})


@app.get("/api/v1/report.html", response_class=HTMLResponse)
def report_html() -> str:
    return render_html(build_report(store.results(), scope={"machines": store.summary()["machines"]}))


@app.get("/api/v1/exposure")
def crown_jewel_exposure() -> list[dict]:
    """Per critical system: which extensions on which machines can read it."""
    return store.exposure()


@app.get("/api/v1/policy.json")
def policy_json(default_deny: bool = False, protect_all: bool = False, contain: bool = True,
                block_at: int | None = None, review_at: int | None = None) -> dict:
    return generate_policy(store.results(), block_at=block_at, review_at=review_at, default_deny=default_deny,
                           contain=contain, protect_all=protect_all)


@app.get("/api/v1/policy.reg", response_class=PlainTextResponse)
def policy_reg(default_deny: bool = False, protect_all: bool = False) -> str:
    policy = generate_policy(store.results(), default_deny=default_deny, protect_all=protect_all)
    return render_windows_reg(policy["chrome_policy"])


# ---------------------------------------------------------------- Guard

@app.get("/api/v1/guard")
def guard_state() -> dict:
    """Pinned extensions, quarantine, the software catalog and the event log."""
    return store.guard()


@app.post("/api/v1/guard/extensions/{ext_id}/approve")
def approve_extension(ext_id: str, version: str | None = None, by: str = "admin") -> dict:
    """Approve (pin) a version. Releases it from quarantine. Without `version`: newest installed."""
    try:
        return store.approve_extension(ext_id, version, by=by)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"not installed: {exc}") from exc


@app.post("/api/v1/guard/advisories/sync")
def sync_advisories() -> dict:
    """Pull new advisories from the feed and re-evaluate every installed program."""
    return store.sync_advisories()


@app.post("/api/v1/guard/advisories/reset")
def reset_advisories() -> dict:
    """Demo helper: go back to the initial advisories."""
    return store.reset_advisories()


@app.get("/api/v1/software-policy.json")
def software_policy_json() -> dict:
    return generate_software_policy(store.software(), store.current_catalog())


@app.get("/api/v1/software-policy.xml")
def software_policy_xml(enforce: bool = False) -> Response:
    xml = render_applocker(generate_software_policy(store.software(), store.current_catalog()), enforce=enforce)
    return Response(content=xml, media_type="application/xml")


# ---------------------------------------------------------------- adding computers, admin

@app.get("/api/v1/server-info")
def server_info(request: Request) -> dict:
    """Addresses teammates can use to reach this server (for the agent download)."""
    port = request.url.port or (443 if request.url.scheme == "https" else 80)
    return {"version": __version__, "port": port, "lan_addresses": lan_addresses(),
            "suggested": [f"http://{ip}:{port}" for ip in lan_addresses()]}


@app.get("/api/v1/agent.zip")
def agent_zip(request: Request, server: str | None = None) -> Response:
    """Ready-to-run agent with this server's address inside run_agent.bat / watch_agent.bat."""
    target = server or str(request.base_url)
    try:
        data = build_agent_zip(target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return Response(content=data, media_type="application/zip",
                    headers={"Content-Disposition": 'attachment; filename="blindspot-agent.zip"'})


@app.post("/api/v1/admin/clear")
def clear_data() -> dict:
    """Remove every machine and extension (for example test data). Agents fill it again."""
    return store.clear()


# ---------------------------------------------------------------- software: live CVE data, catalog

@app.get("/api/v1/software/feeds")
def feed_status() -> dict:
    """NVD / CISA KEV status: what is tracked, when it was fetched, whether a check is running."""
    return store.feed_status()


@app.post("/api/v1/software/feeds/refresh")
def refresh_feeds() -> dict:
    """Check NVD and CISA KEV now (runs in the background; poll /software/feeds)."""
    if not FEEDS_ON:
        raise HTTPException(status_code=409, detail="Feeds are switched off (BLINDSPOT_FEEDS=off).")
    _refresh_in_background(force=True)
    return dict(store.feed_status(), running=True)


@app.post("/api/v1/software/approve")
def approve_software(body: dict = Body(...)) -> dict:
    """Add this program version to the approved catalog."""
    if not body.get("name") or not body.get("version"):
        raise HTTPException(status_code=422, detail="name and version are required")
    return store.approve_software(body["name"], body["version"], by=body.get("by", "admin"),
                                  publisher=body.get("publisher", ""))


@app.post("/api/v1/software/unapprove")
def unapprove_software(body: dict = Body(...)) -> dict:
    return {"removed": store.unapprove_software(body.get("name", ""))}


@app.post("/api/v1/settings/nvd-key")
def nvd_key(body: dict = Body(...)) -> dict:
    """Optional free NVD API key: checks run about 10 times faster."""
    return store.set_nvd_key(str(body.get("key", "")))


# ---------------------------------------------------------------- alerts (Telegram)

@app.get("/api/v1/alerts")
def alert_settings() -> dict:
    """Current alert settings. The bot token is masked."""
    return store.alert_settings()


@app.post("/api/v1/alerts/telegram/find-chats")
def find_chats(body: dict = Body(...)) -> list[dict]:
    """Chats that have messaged the bot: send the bot any message first."""
    token = str(body.get("token") or store.alert_settings(reveal=True)["telegram"]["token"]).strip()
    if not token:
        raise HTTPException(status_code=422, detail="Paste the bot token from @BotFather first.")
    try:
        return alerting.find_chats(token)
    except alerting.AlertError as exc:
        print(f"[blindspot] Find my chat failed: {exc}")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/api/v1/alerts/telegram")
def save_telegram(body: dict = Body(...)) -> dict:
    """Save token / chat / dashboard address / alert kinds. Omitted keys stay as they are."""
    return store.save_alert_settings(token=body.get("token"), chat_id=body.get("chat_id"),
                                     chat_name=body.get("chat_name"), dashboard_url=body.get("dashboard_url"),
                                     kinds=body.get("kinds"))


@app.post("/api/v1/alerts/telegram/disable")
def disable_telegram() -> dict:
    return store.save_alert_settings(token="", chat_id="", chat_name="")


@app.post("/api/v1/alerts/test")
def test_alert() -> dict:
    """Send a test message now and report Telegram's answer."""
    config = store.telegram_config()
    if config is None:
        raise HTTPException(status_code=422, detail="Telegram is not set up yet.")
    try:
        alerting.send_telegram(config, alerting.format_alerts(
            [{"kind": "test", "subject": "Blindspot is connected",
              "detail": "You will get a message here when an extension is quarantined, a CVE blocks software, "
                        "or a high-risk extension appears."}], config.dashboard_url))
    except alerting.AlertError as exc:
        print(f"[blindspot] Test alert failed: {exc}")
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"sent": True}


# The dashboard. Mounted last so it never shadows the API routes.
app.mount("/", StaticFiles(directory=ROOT / "frontend", html=True), name="frontend")
