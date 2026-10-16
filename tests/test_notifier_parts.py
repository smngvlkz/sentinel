"""Notification settings, message text and the channel senders."""

import datetime as dt
import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from zoneinfo import ZoneInfo

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from common.threats import SEVERITY, THREATS, at_least, threat_info
from notifier import channels, config, messages
from notifier.channels import SendError

ROOT = os.path.join(os.path.dirname(__file__), "..")
UTC = dt.timezone.utc
JHB = ZoneInfo("Africa/Johannesburg")


def write(tmp_path, text):
    p = tmp_path / "notifications.toml"
    p.write_text(text)
    return str(p)


class TestConfig:
    def test_shipped_file_loads_and_is_off(self):
        s = config.load(os.path.join(ROOT, "config", "notifications.toml"), env={})
        assert not s.enabled and s.channels == {} and s.min_severity == "high"

    def test_missing_file_means_defaults(self, tmp_path):
        s = config.load(str(tmp_path / "nope.toml"), env={})
        assert not s.enabled and s.max_per_hour == 10

    def test_full_setup(self, tmp_path):
        path = write(tmp_path, """
[notifications]
enabled = true
min_severity = "medium"
dashboard_url = "http://100.101.102.103:3001/"
timezone = "Africa/Johannesburg"
[quiet_hours]
enabled = true
start = "22:30"
end = "06:00"
[ntfy]
enabled = true
[email]
enabled = true
host = "smtp.example.com"
username = "me"
from = "sentinel@example.com"
to = "me@example.com"
[webhook]
enabled = true
format = "discord"
""")
        env = {"NTFY_TOPIC": "sentinel-x1", "SMTP_PASSWORD": "pw", "WEBHOOK_URL": "https://discord.example/api/webhooks/1/abc"}
        s = config.load(path, env=env)
        assert s.enabled and s.min_severity == "medium"
        assert s.dashboard_url == "http://100.101.102.103:3001"  # trailing slash dropped
        assert s.zone == JHB and s.quiet.start == dt.time(22, 30)
        assert set(s.channels) == {"ntfy", "email", "webhook"}
        assert s.channels["ntfy"]["topic"] == "sentinel-x1" and s.channels["email"]["password"] == "pw"

    @pytest.mark.parametrize("text, env, error", [
        ('[notifications]\nmin_severity = "urgent"', {}, "min_severity"),
        ("[notifications]\nmax_per_hour = 0", {}, "max_per_hour"),
        ("[notifications]\nrepeat_minutes = -5", {}, "repeat_minutes"),
        ('[notifications]\ntimezone = "Mars/Base"', {}, "time zone"),
        ('[notifications]\ndashboard_url = "100.1.2.3:3001"', {}, "dashboard_url"),
        ('[quiet_hours]\nenabled = true\nstart = "10pm"', {}, "quiet_hours.start"),
        ('[quiet_hours]\nenabled = true\nstart = "07:00"\nend = "07:00"', {}, "same time"),
        ("[notifications]\nenabled = true", {}, "no channel"),
        ("[ntfy]\nenabled = true", {}, "NTFY_TOPIC"),
        ('[email]\nenabled = true\nhost = "h"', {}, "from, to"),
        ('[email]\nenabled = true\nhost = "h"\nfrom = "a"\nto = "b"\nusername = "u"', {}, "SMTP_PASSWORD"),
        ("[webhook]\nenabled = true", {}, "WEBHOOK_URL"),
        ('[webhook]\nenabled = true\nformat = "teams"', {"WEBHOOK_URL": "https://x"}, "webhook.format"),
        ('[webhook]\nenabled = true\nformat = "telegram"', {"WEBHOOK_URL": "https://x"}, "telegram_chat_id"),
        ("[notifications]\nenabeld = true", {}, "unknown setting"),
        ("[sms]\nenabled = true", {}, "unknown section"),
        ("[notifications\n", {}, "valid TOML"),
    ])
    def test_settings_that_cant_work_say_why(self, tmp_path, text, env, error):
        with pytest.raises(config.ConfigError, match=error):
            config.load(write(tmp_path, text), env=env)


class TestThreats:
    def test_names_and_headlines_match_the_dashboard(self):
        ts = open(os.path.join(ROOT, "dashboard", "src", "lib", "threats.ts")).read()
        found = re.findall(
            r'\n  ([A-Z_]+): \{\n    name: "([^"]+)",\n    severity: "(\w+)",\n    headline: \(([^)]*)\) => `([^`]+)`', ts
        )
        assert {t for t, *_ in found} == set(THREATS)
        for threat, name, severity, _args, headline in found:
            info = THREATS[threat]
            assert (info.name, info.severity) == (name, severity)
            py = headline.replace("${src}", "{src}").replace("${dst}", "{dst}")
            assert info.headline == py, threat

    def test_unknown_type_is_low_with_a_readable_name(self):
        info = threat_info("NEW_THING")
        assert info.severity == "low" and info.name == "New thing"
        assert info.headline.format(src="a", dst="b") == "a triggered a NEW_THING alert against b"

    def test_severity_order(self):
        assert at_least("high", "medium") and at_least("medium", "medium") and not at_least("low", "medium")
        assert SEVERITY["SYN_FLOOD"] == "high"


ALERT = {
    "id": 42,
    "timestamp": dt.datetime(2026, 10, 16, 12, 3, 9, tzinfo=UTC),
    "threat_type": "SYN_FLOOD",
    "source_ip": "203.0.113.9",
    "destination_ip": "192.168.1.20",
    "source_name": "scanner.example",
    "destination_name": None,
    "source_device": None,
    "destination_device": "Front door camera",
}


class TestMessages:
    def test_device_names_and_learned_hostnames(self):
        m = messages.for_alert(ALERT, "http://dash", JHB)
        assert m["title"] == "Connection flood"
        assert m["body"].startswith(
            "scanner.example (203.0.113.9) flooded Front door camera with connection requests."
        )
        assert "High severity, at 14:03:09." in m["body"]  # local time
        assert m["url"] == "http://dash/?alert=42" and m["severity"] == "high"
        # Repeats are matched on addresses, not names.
        assert m["repeat_key"] == "SYN_FLOOD|203.0.113.9 flooded 192.168.1.20 with connection requests"

    def test_ips_only(self):
        m = messages.for_alert(ALERT, "", JHB, ips_only=True)
        assert m["body"].startswith("203.0.113.9 flooded 192.168.1.20 ")
        assert "Front door camera" not in m["body"] and "scanner" not in m["body"]
        assert m["url"] == ""

    def test_display_name(self):
        assert messages.display_name("10.0.0.1", "NAS", "nas.lan", False) == "NAS"
        assert messages.display_name("10.0.0.1", None, "nas.lan", False) == "nas.lan (10.0.0.1)"
        assert messages.display_name("10.0.0.1", None, None, False) == "10.0.0.1"
        assert messages.display_name(None, None, None, False) == "?"

    def test_digest(self):
        alerts = [dict(ALERT, id=i, threat_type=t, timestamp=ALERT["timestamp"] + dt.timedelta(minutes=i))
                  for i, t in enumerate(["PORT_SCAN", "SYN_FLOOD", "PORT_SCAN", "ANOMALY", "PORT_SCAN"])]
        m = messages.digest(alerts, "http://dash", JHB)
        assert m["title"] == "5 alerts held back"
        assert m["body"].splitlines() == [
            "1 × Connection flood (high)",
            "3 × Port scan",
            "1 × Unusual traffic",
            "Between 14:03–14:07.",
        ]
        assert m["severity"] == "high" and m["url"] == "http://dash/"

    def test_digest_over_days(self):
        alerts = [ALERT, dict(ALERT, id=43, timestamp=ALERT["timestamp"] + dt.timedelta(days=1))]
        assert messages.digest(alerts, "", JHB)["body"].endswith("Between 16 Oct 14:03 – 17 Oct 14:03.")

    def test_naive_database_times_are_utc(self):
        m = messages.for_alert(dict(ALERT, timestamp=dt.datetime(2026, 10, 16, 12, 3, 9)), "", JHB)
        assert "14:03:09" in m["body"]


class Recorder(BaseHTTPRequestHandler):
    received: list = []
    status = 200

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        Recorder.received.append((self.path, dict(self.headers), json.loads(body)))
        self.send_response(Recorder.status)
        self.end_headers()
        self.wfile.write(b"nope" if Recorder.status >= 400 else b"{}")

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    Recorder.received = []
    Recorder.status = 200
    httpd = HTTPServer(("127.0.0.1", 0), Recorder)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()


MSG = {"title": "Connection flood", "body": "a flooded b.", "severity": "high", "url": "http://dash/?alert=1"}


class TestChannels:
    def test_ntfy(self, server):
        channels.send_ntfy({"server": server, "topic": "sentinel-x1", "token": "tk"}, MSG)
        path, headers, body = Recorder.received[0]
        assert path == "/"
        assert body == {"topic": "sentinel-x1", "title": "Connection flood", "message": "a flooded b.",
                        "priority": 5, "tags": ["rotating_light"], "click": "http://dash/?alert=1"}
        assert headers["Authorization"] == "Bearer tk"

    def test_ntfy_without_link_or_token(self, server):
        channels.send_ntfy({"server": server, "topic": "t", "token": ""}, dict(MSG, url="", severity="medium"))
        _, headers, body = Recorder.received[0]
        assert "click" not in body and body["priority"] == 4 and "Authorization" not in headers

    @pytest.mark.parametrize("fmt, check", [
        ("discord", lambda b: b["content"].startswith("**Connection flood**\na flooded b.")
                              and b["allowed_mentions"] == {"parse": []}),
        ("slack", lambda b: b["text"] == "*Connection flood*\na flooded b.\nhttp://dash/?alert=1"),
        ("telegram", lambda b: b["chat_id"] == "99" and "parse_mode" not in b and b["text"].startswith("Connection flood\n")),
        ("json", lambda b: b == MSG),
    ])
    def test_webhook_formats(self, server, fmt, check):
        channels.send_webhook({"url": server + "/hook", "format": fmt, "telegram_chat_id": "99"}, MSG)
        assert check(Recorder.received[0][2])

    def test_slack_text_is_escaped(self, server):
        channels.send_webhook({"url": server, "format": "slack", "telegram_chat_id": ""},
                              dict(MSG, body="<!channel> & co", url=""))
        assert Recorder.received[0][2]["text"] == "*Connection flood*\n&lt;!channel&gt; &amp; co"

    def test_http_error_is_a_send_error_without_the_url(self, server):
        Recorder.status = 404
        url = server + "/api/webhooks/123/secret-token"
        with pytest.raises(SendError) as e:
            channels.send_webhook({"url": url, "format": "json", "telegram_chat_id": ""}, MSG)
        assert "HTTP 404" in str(e.value) and "secret-token" not in str(e.value)

    def test_unreachable_server(self):
        with pytest.raises(SendError, match="couldn't connect"):
            channels.send_ntfy({"server": "http://127.0.0.1:9", "topic": "t", "token": ""}, MSG)

    def test_email(self, monkeypatch):
        sent = {}

        class FakeSMTP:
            def __init__(self, host, port, timeout):
                sent["server"] = (host, port)

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

            def starttls(self, context):
                sent["tls"] = True

            def login(self, user, password):
                sent["login"] = (user, password)

            def send_message(self, mail):
                sent["mail"] = mail

        monkeypatch.setattr(channels.smtplib, "SMTP", FakeSMTP)
        settings = {"host": "smtp.example.com", "port": 587, "starttls": True, "username": "me",
                    "password": "pw", "from": "s@example.com", "to": "me@example.com"}
        channels.send_email(settings, MSG)
        mail = sent["mail"]
        assert sent["server"] == ("smtp.example.com", 587) and sent["tls"] and sent["login"] == ("me", "pw")
        assert mail["Subject"] == "[SentinelAI] Connection flood" and mail["To"] == "me@example.com"
        assert "a flooded b.\nhttp://dash/?alert=1" in mail.get_content()

    def test_email_wrong_password(self, monkeypatch):
        import smtplib

        class Refusing:
            def __init__(self, *a, **k):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

            def starttls(self, context):
                pass

            def login(self, user, password):
                raise smtplib.SMTPAuthenticationError(535, b"bad")

        monkeypatch.setattr(channels.smtplib, "SMTP", Refusing)
        with pytest.raises(SendError, match="SMTP_PASSWORD"):
            channels.send_email({"host": "h", "port": 587, "starttls": True, "username": "u", "password": "p",
                                 "from": "a@x", "to": "b@x"}, MSG)
