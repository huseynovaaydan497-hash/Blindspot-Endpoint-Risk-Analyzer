"""
Alerts: tell a person the moment something needs action. Telegram for now.

Owner: D

Public interface:
    TelegramConfig(token, chat_id, dashboard_url)
    send_telegram(config, text) -> None            (raises AlertError)
    find_chats(token) -> [{"chat_id", "name"}]      (chats that messaged the bot)
    format_alerts(alerts, dashboard_url) -> str      (one message for one batch)

What triggers an alert (see Store.ingest / Store.sync_advisories):
    quarantine   Guard quarantined a new build of an extension
    advisory     a new CVE blocked an installed software version
    high_risk    an extension rated High or Critical was seen for the first time

Setup, once: talk to @BotFather in Telegram, /newbot, copy the token. Send any
message to the new bot, then press "Find my chat" in the dashboard.
The token is stored only in this server's local database.
"""
from __future__ import annotations

import json
import ssl
import sys
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from html import escape

API = "https://api.telegram.org/bot{token}/{method}"
TIMEOUT = 15
KIND_TITLE = {
    "quarantine": "Extension quarantined",
    "advisory": "Software blocked by a new CVE",
    "high_risk": "High-risk extension found",
    "test": "Test alert",
}


class AlertError(RuntimeError):
    """Telegram rejected the request or could not be reached."""


@dataclass
class TelegramConfig:
    token: str
    chat_id: str
    dashboard_url: str = ""


def _call(token: str, method: str, payload: dict | None = None) -> dict:
    url = API.format(token=token, method=method)
    data = json.dumps(payload or {}).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 -- fixed https host
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("description", str(exc))
        except (ValueError, OSError):
            detail = str(exc)
        if exc.code in (401, 404):
            raise AlertError("Telegram does not accept this bot token. Copy it again from @BotFather "
                             "(the whole line, like 123456789:AAE...).") from exc
        if exc.code == 409:
            raise AlertError("WEBHOOK_CONFLICT") from exc
        raise AlertError(f"Telegram: {detail}") from exc
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, ssl.SSLError) or "CERTIFICATE" in str(reason).upper():
            raise AlertError("The HTTPS certificate check for api.telegram.org failed. This network inspects "
                             "HTTPS traffic (common on university or company Wi-Fi). Connect this computer to a "
                             "phone hotspot and try again.") from exc
        raise AlertError(f"Cannot reach api.telegram.org ({reason}). This network may block Telegram: "
                         "try a phone hotspot.") from exc
    except (TimeoutError, OSError) as exc:
        raise AlertError(f"Cannot reach api.telegram.org ({exc}). This network may block Telegram: "
                         "try a phone hotspot.") from exc
    if not body.get("ok"):
        raise AlertError(f"Telegram: {body.get('description', 'request failed')}")
    return body


def send_telegram(config: TelegramConfig, text: str) -> None:
    _call(config.token, "sendMessage", {
        "chat_id": config.chat_id, "text": text[:4000], "parse_mode": "HTML",
        "disable_web_page_preview": True,
    })


def find_chats(token: str) -> list[dict]:
    """Chats that have sent the bot a message recently (getUpdates)."""
    try:
        body = _call(token, "getUpdates", {"limit": 50})
    except AlertError as exc:
        if str(exc) != "WEBHOOK_CONFLICT":
            raise
        # the bot has a webhook set elsewhere; getUpdates only works without one
        _call(token, "deleteWebhook", {})
        body = _call(token, "getUpdates", {"limit": 50})
    chats: dict[str, str] = {}
    for update in body.get("result", []):
        msg = update.get("message") or update.get("channel_post") or update.get("my_chat_member") or {}
        chat = msg.get("chat") or {}
        if "id" in chat:
            name = chat.get("title") or " ".join(x for x in (chat.get("first_name"), chat.get("last_name")) if x) \
                or chat.get("username") or str(chat["id"])
            chats[str(chat["id"])] = name
    return [{"chat_id": cid, "name": name} for cid, name in chats.items()]


def format_alerts(alerts: list[dict], dashboard_url: str = "") -> str:
    """One Telegram message (HTML) for a batch of alerts from one report."""
    lines = []
    for kind in ("quarantine", "advisory", "high_risk", "test"):
        group = [a for a in alerts if a["kind"] == kind]
        if not group:
            continue
        lines.append(f"<b>Blindspot: {escape(KIND_TITLE[kind])}</b>")
        for a in group[:10]:
            lines.append(f"• <b>{escape(a['subject'])}</b>\n{escape(a['detail'])}")
        if len(group) > 10:
            lines.append(f"…and {len(group) - 10} more")
        lines.append("")
    if dashboard_url:
        anchor = "#guard" if any(a["kind"] in ("quarantine", "advisory") for a in alerts) else "#extensions"
        lines.append(f'<a href="{escape(dashboard_url.rstrip("/") + "/" + anchor)}">Open the dashboard</a>')
    return "\n".join(lines).strip()


def dispatch_async(config: TelegramConfig | None, alerts: list[dict], on_error=None, on_sent=None) -> None:
    """Send without making the agent wait. Errors go to on_error(message)."""
    if not config or not alerts:
        return

    def run():
        try:
            send_telegram(config, format_alerts(alerts, config.dashboard_url))
            if on_sent:
                on_sent(len(alerts))
        except AlertError as exc:
            print(f"[blindspot] Telegram alert not sent: {exc}", file=sys.stderr)
            if on_error:
                on_error(str(exc))

    threading.Thread(target=run, daemon=True).start()
