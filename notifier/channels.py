"""
Sending a message to each kind of channel. Every sender raises SendError
when the message didn't get through. Error text never includes a secret: a
webhook URL carries its own token, so it's never quoted.
"""

from __future__ import annotations

import json
import smtplib
import ssl
import urllib.error
import urllib.request
from email.message import EmailMessage
from typing import Any, Callable

TIMEOUT = 10.0
USER_AGENT = "SentinelAI-notifier"

# ntfy priorities run 1 (min) to 5 (max); 5 makes a phone ring through do-not-disturb on Android.
NTFY_PRIORITY = {"high": 5, "medium": 4, "low": 3}
NTFY_TAGS = {"high": ["rotating_light"], "medium": ["warning"], "low": []}


class SendError(Exception):
    pass


def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str] | None = None) -> None:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT, **(headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            response.read(1024)
    except urllib.error.HTTPError as e:
        detail = e.read(200).decode(errors="replace").strip()
        raise SendError(f"HTTP {e.code}" + (f": {detail}" if detail else "")) from None
    except (urllib.error.URLError, OSError) as e:
        reason = getattr(e, "reason", e)
        raise SendError(f"couldn't connect: {reason}") from None


def send_ntfy(settings: dict[str, Any], message: dict[str, str]) -> None:
    payload: dict[str, Any] = {
        "topic": settings["topic"],
        "title": message["title"],
        "message": message["body"],
        "priority": NTFY_PRIORITY.get(message["severity"], 3),
        "tags": NTFY_TAGS.get(message["severity"], []),
    }
    if message.get("url"):
        payload["click"] = message["url"]
    headers = {"Authorization": f"Bearer {settings['token']}"} if settings.get("token") else {}
    # ntfy takes JSON at the server's root URL, which allows any text in titles.
    _post_json(settings["server"] + "/", payload, headers)


def _text(message: dict[str, str]) -> str:
    return message["body"] + (f"\n{message['url']}" if message.get("url") else "")


def _slack_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def send_webhook(settings: dict[str, Any], message: dict[str, str]) -> None:
    fmt = settings["format"]
    if fmt == "discord":
        # No @everyone or @role pings from a device name.
        payload: dict[str, Any] = {
            "content": f"**{message['title']}**\n{_text(message)}",
            "allowed_mentions": {"parse": []},
        }
    elif fmt == "slack":
        payload = {"text": _slack_escape(f"*{message['title']}*\n{_text(message)}")}
    elif fmt == "telegram":
        # Plain text: no parse_mode, so names can't inject formatting.
        payload = {
            "chat_id": settings["telegram_chat_id"],
            "text": f"{message['title']}\n{_text(message)}",
            "disable_web_page_preview": True,
        }
    else:
        payload = {k: message.get(k, "") for k in ("title", "body", "severity", "url")}
    _post_json(settings["url"], payload)


def send_email(settings: dict[str, Any], message: dict[str, str]) -> None:
    mail = EmailMessage()
    mail["Subject"] = f"[SentinelAI] {message['title']}"
    mail["From"] = settings["from"]
    mail["To"] = settings["to"]
    mail.set_content(_text(message) + "\n")
    try:
        if int(settings["port"]) == 465:
            server: smtplib.SMTP = smtplib.SMTP_SSL(
                settings["host"], 465, timeout=TIMEOUT, context=ssl.create_default_context()
            )
        else:
            server = smtplib.SMTP(settings["host"], int(settings["port"]), timeout=TIMEOUT)
        with server:
            if settings.get("starttls") and int(settings["port"]) != 465:
                server.starttls(context=ssl.create_default_context())
            if settings.get("username"):
                server.login(settings["username"], settings.get("password", ""))
            server.send_message(mail)
    except smtplib.SMTPAuthenticationError:
        raise SendError("the mail server refused the username or SMTP_PASSWORD") from None
    except (smtplib.SMTPException, OSError) as e:
        raise SendError(f"email failed: {e.__class__.__name__}: {e}") from None


SENDERS: dict[str, Callable[[dict[str, Any], dict[str, str]], None]] = {
    "ntfy": send_ntfy,
    "email": send_email,
    "webhook": send_webhook,
}
