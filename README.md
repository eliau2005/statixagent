# StatixAgent

Self-hosted, featherweight monitoring for VPS servers and home laptops. One
static Go binary per machine, one private Telegram bot per machine — no
central server, no third party in your data path.

Each install is fully isolated: the agent samples the system, watches sshd,
and pushes alerts to *your* bot. Everything after installation happens in
Telegram.

## What it watches

- **Core system** — CPU (total + per-core + load), RAM/swap, disk space per
  mount, disk I/O rates, network rates and lifetime totals per interface,
  uptime, process count, open file descriptors.
- **Thermal** — temperatures (thermal zones + hwmon), fan speeds,
  throttling detection.
- **Battery & power** — charge, health vs. design capacity, wattage draw,
  time-to-empty, and an **immediate alert when the power cord is pulled**.
- **Services** — systemd units, named processes, TCP ports, HTTP
  healthchecks, Docker containers (status, per-container CPU/RAM,
  restart-loop detection), SSL certificate expiry.
- **SSH security** — real-time alert on every login (geo-located, root
  logins escalated), live session listing, login/fail history,
  brute-force detection, `authorized_keys` change alerts.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/eliau2005/statixagent/main/install.sh | sudo bash
```

The one-time TUI wizard asks for your bot token (from
[@BotFather](https://t.me/BotFather)) and chat ID, lets you toggle monitor
categories and thresholds, then writes `/etc/statix-agent/config.toml`
(0600), installs `/usr/local/bin/statix-agent`, and enables the hardened
systemd service (`Restart=always`).

## Bot commands

| Command | Result |
| --- | --- |
| `/status` | full snapshot: CPU, RAM, disks, net, temps, battery, uptime |
| `/cpu` `/mem` `/disk` `/net` `/temp` `/battery` | one metric in detail, with usage sparklines |
| `/top` | heaviest processes by CPU and memory |
| `/digest` | the day's recap — also auto-sent every morning |
| `/services` | systemd units, processes, ports, healthchecks |
| `/http` | endpoint checks · `/http add <url> [status]` · `/http remove <url>` |
| `/docker` | containers with CPU/RAM and restart counts |
| `/ssh` | live sessions with disconnect buttons · `/ssh history` · `/ssh fails` |
| `/ssl` | certificate expiry · `/ssl add <host>` · `/ssl remove <host>` |
| `/firewall` | open/close SSH port 22 via ufw |
| `/watching` | everything watched, managed with buttons |
| `/settings` | alert thresholds and digest schedule, tuned with buttons |
| `/update` | check for a new release · `/update confirm` installs it |
| `/clear_chat` | delete recent messages |

Alerts (thresholds, power loss, SSH logins, brute force, key changes, cert
expiry, host reboots) arrive as push messages — no need to ask — and carry
buttons for the next step.

## Self-update

Updates come from GitHub Releases and are verified with SHA256 **and** an
ed25519 signature before an atomic swap; a crash-looping update rolls back
automatically. Automatic checking is off by default. See
[SECURITY.md](SECURITY.md).

## Development

Targets Linux; develops and tests anywhere (every parser is pure and
fixture-tested — the suite runs on Windows/macOS too).

```sh
go test ./...   # 15 packages
make build      # cross-compile linux binaries into bin/
make dist       # all release artifacts + checksums
```

Docs: [mvp.md](mvp.md) (spec) · [docs/BUILD_PLAN.md](docs/BUILD_PLAN.md)
(phase tracker) · [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (design).

Releasing: generate a signing key once with `go run ./tools/sign keygen`,
store the private half as the `STATIX_SIGNING_KEY` repo secret, then push a
`v*` tag — CI builds, signs, and publishes the release.
