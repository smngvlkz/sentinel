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

- **The dashboard is open until you set a password.** Every port is bound to
  `127.0.0.1` by default, so only this machine can reach it. Once a password
  is set (`make password`), every API request needs a login. Letting other
  devices open the dashboard (`DASHBOARD_BIND`) needs a password: the API
  refuses to start that way without one, and the API's own port stays on
  this machine. For access away from home, use Tailscale (README "Opening the
  dashboard from other devices"), not port forwarding.
- **Endpoints that change data refuse cross-site requests.** Marking alerts
  reviewed, naming devices, and logging in or changing the password reject
  any browser `Origin` that isn't the dashboard's own address or in
  `CORS_ORIGINS`, and any body that isn't JSON, so a web page you visit can't
  act on your dashboard behind your back.
- **Packet capture runs as root** because it reads raw sockets. By default it
  only parses packet headers and never stores payloads. Optional name
  context (`PAYLOAD_INSPECTION` plus `[names]` in config) additionally reads
  DNS answers, cleartext HTTP `Host` headers and the TLS server name (SNI)
  in memory so alerts can show a hostname next to an IP; those names are
  stored on alerts only, and names are chosen by whoever sent the traffic.
- **The anomaly model is loaded with `joblib`**, which can execute code. Only
  load model files you trained yourself.
- **The default database password is `changeme`.** Set `POSTGRES_PASSWORD`
  in `.env` if anything else can reach your machine.
