# Security policy

SentinelAI handles network traffic metadata and runs packet capture as root,
so security reports are taken seriously.

## Reporting a vulnerability

**Please don't open a public issue.** Report it privately through GitHub:

1. Go to the repository's **Security** tab.
2. Select **Report a vulnerability**.

Include what you found, how to reproduce it, and the version or commit
you tested. You'll get an acknowledgement within 7 days and a plan for a fix
once the report is confirmed. Reporters are credited in the release notes
unless they'd rather not be.

## Supported versions

Only the latest release receives security fixes.

## Security model

Things to know before deploying:

- **The API has no authentication.** Every port is bound to `127.0.0.1` by
  default. Don't expose the API or dashboard to a network you don't trust; use
  an SSH tunnel for remote access.
- **The one write endpoint (`POST /alerts/review`) refuses cross-site
  requests.** It rejects any browser `Origin` not in `CORS_ORIGINS` and any
  body that isn't JSON, so a web page you visit can't mark your alerts as
  reviewed behind your back.
- **Packet capture runs as root** because it reads raw sockets. It only parses
  packet headers and never stores payloads.
- **The anomaly model is loaded with `joblib`**, which can execute code. Only
  load model files you trained yourself.
- **The default database password is `changeme`.** Set `POSTGRES_PASSWORD`
  in `.env` if anything else can reach your machine.
