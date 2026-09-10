# StatixAgent

[![CI](https://github.com/eliau2005/statixagent/actions/workflows/ci.yml/badge.svg)](https://github.com/eliau2005/statixagent/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](go.mod)
[![Platform](https://img.shields.io/badge/platform-Linux%20amd64%20%7C%20arm64-333)](#supported-platforms)
[![Status](https://img.shields.io/badge/status-early%20open--source%20(v0.x)-orange)](#project-status)

**Monitor a Linux server or laptop from your phone, with nothing running in the middle.**

StatixAgent is a single static Go binary that watches one machine and talks to
*your own* private Telegram bot. It samples the system, watches sshd, and pushes
alerts straight to your chat. There is no central server, no dashboard to host,
and no third party in your data path — the agent talks only to Telegram's Bot
API and to GitHub Releases when you ask it to update.

Everything after installation happens in Telegram: type `/status` for a live
dashboard, get a push message the moment someone logs in over SSH or the power
cord is pulled, and tap buttons to drill in.

```
curl -fsSL https://raw.githubusercontent.com/eliau2005/statixagent/main/install.sh | sudo bash
```

> **Project status:** early open-source release (v0.x). The core is built,
> tested, and running; the project is now opened to the community. See
> [Project status](#project-status) and [ROADMAP.md](ROADMAP.md).

---

## Why StatixAgent?

Most monitoring stacks assume you are running a fleet and want a time-series
database, a query language, and a dashboard. For a single VPS or a home laptop,
that is a lot of moving parts to install, secure, and keep alive — often heavier
than the thing you are trying to watch.

StatixAgent takes the opposite trade-off:

| | Prometheus / Grafana-style | StatixAgent |
| --- | --- | --- |
| Components to run | exporter + TSDB + dashboard + alertmanager | one binary |
| Where your data goes | scraped into a central store | stays on the machine; only alerts you request leave |
| How you interact | a web UI you host and secure | a private Telegram bot you already carry |
| Footprint | designed for fleets | designed for one box (`MemoryMax=128M`) |
| Setup | compose files, config, reverse proxy | one command, a one-time TUI wizard |

It is deliberately **not** a fleet tool. Each install is fully isolated: one
agent, one bot, one chat. That buys simplicity and a small attack surface, at
the cost of cross-server correlation (see [Trade-offs](#trade-offs)).

Reach for StatixAgent when you want to *know your one box is okay* — and hear
about it the moment it is not — without standing up an observability stack.

## What it can do

### Watches

- **Core system** — CPU (total, per-core, load average), RAM and swap, disk
  space per mount, disk I/O rates, network rates and lifetime totals per
  interface, uptime, process count, open file descriptors.
- **Thermal** — temperatures (thermal zones + hwmon), fan speeds, and
  throttling detection. Temperature alerts only fire once the threshold is held
  for several consecutive samples, so a CPU touching 90 °C for a moment
  mid-boost stays quiet.
- **Battery & power** *(laptops / physical machines)* — charge, health vs.
  design capacity, wattage draw, estimated time-to-empty, and an **immediate
  alert when the power cord is pulled**.
- **Workloads** — systemd units, named processes, TCP ports, HTTP
  healthchecks, and Docker containers (status, per-container CPU/RAM, and
  restart-loop detection).
- **Reachability** — SSL/TLS certificate expiry for hosts you name, and TCP
  connect latency from the server's own vantage point (`/ping`).

### Security monitoring

SSH visibility is a first-class feature, not an afterthought:

- Real-time alert on **every** SSH login, with geo-IP of the source; successful
  **root** logins are escalated.
- Live session listing (user, source IP, duration, TTY).
- Login and failure history, kept in memory.
- **Brute-force detection** — a sliding-window counter per source IP with a
  threshold alert and quiet-period dedupe during an ongoing attack.
- **`authorized_keys` change alerts** — the agent hashes root's and every home
  user's key files and alerts when one changes.

### Alerts and remediation

Alerts arrive as push messages — you never have to ask for them:

- Threshold crossings (CPU, RAM, disk, temperature, low battery).
- Power loss, host reboot, new SSH login, brute-force burst, key-file change,
  certificate expiry, and container down / restart-loop events.

Each alert carries **one-tap action buttons** for the obvious next step
(jump to the relevant metric view, list SSH sessions, open the firewall
control) and a 🔕 button to snooze *that* alert for an hour while you handle it.

Remediation is intentionally minimal and always gated behind an explicit
confirmation:

- **SSH session disconnect** buttons in `/ssh`.
- **`/firewall`** — open or close SSH port 22 via `ufw`, behind a mandatory
  confirmation screen. Hosts without `ufw` get a plain "cannot manage the
  firewall here" and no buttons, never a guess about what is open.

## Telegram commands

Commands are registered for autocomplete, and every metric view carries an
inline keyboard so you can navigate by tapping instead of typing.

| Command | Result |
| --- | --- |
| `/status` | full snapshot: CPU, RAM, disks, net, temps, battery, uptime |
| `/cpu` `/mem` `/disk` `/net` `/temp` `/battery` | one metric in detail, with sparkline trends on `/cpu` and `/mem` |
| `/top` | heaviest processes by CPU and memory |
| `/digest` | the day's recap — also auto-sent every morning |
| `/services` | systemd units, processes, ports, healthchecks |
| `/http` | endpoint checks (redirects are reported, not followed) · `/http add <url> [status]` · `/http remove <url>` |
| `/ping <host[:port]>` | TCP connect latency from the server |
| `/docker` | containers with CPU/RAM and restart counts |
| `/ssh` | live sessions with disconnect buttons · `/ssh history` · `/ssh fails` |
| `/ssl` | certificate expiry · `/ssl add <host>` · `/ssl remove <host>` |
| `/firewall` | open/close SSH port 22 via `ufw` (says it cannot manage the firewall where `ufw` is absent) |
| `/watching` | everything watched, managed with buttons |
| `/settings` | alert thresholds and digest schedule, tuned with buttons |
| `/services_scan` `/ports_scan` | discover candidates to watch |
| `/update` | check for a new release · `/update_confirm` installs it |
| `/clear_chat` | delete recent messages |
| `/help` | grouped command reference |

The Live button animates the latest regular sampler snapshot. It does not take
extra samples, evaluate alert thresholds, or add points to metric trends, so
opening the view cannot change monitoring behavior.

Commands are accepted **only** from the single chat ID in the config; updates
from any other chat are dropped before parsing.

## Self-update

The agent can update itself from GitHub Releases, and the verification is not
optional:

1. Fetch the release's `checksums.txt` and its detached `checksums.txt.sig`.
2. Verify the signature against an **ed25519 public key compiled into the
   binary** at release time. If the build carries no key, or the signature does
   not verify, the update **aborts** — there is no "skip verification" path.
3. Verify the downloaded binary's **SHA256** against the signed checksum.
4. Swap atomically (`rename`), keeping the previous binary as `.prev`.
5. A crash-loop guard at startup restores `.prev` automatically if the new
   binary keeps dying, and consumes it so versions cannot ping-pong.

Automatic update checks are **off by default** and opt-in at install time.
Full details are in [SECURITY.md](SECURITY.md).

## Security model

- The bot token lives in `/etc/statix-agent/config.toml`, written atomically
  with `0600` permissions.
- Commands are accepted only from the configured chat ID; state-changing
  actions (`/update_confirm`, `/firewall`) require an explicit confirmation.
- The systemd unit ships hardened: `NoNewPrivileges`, `ProtectSystem=full`,
  `ProtectHome=read-only`, `PrivateTmp`, a narrow `ReadWritePaths`, and
  `MemoryMax=128M`.
- Updates are verified with ed25519 **and** SHA256 before an atomic swap, with
  automatic rollback.

See [SECURITY.md](SECURITY.md) for the full threat model, the privilege model,
and the distinction between what is implemented today and future hardening.

## Installation

```sh
curl -fsSL https://raw.githubusercontent.com/eliau2005/statixagent/main/install.sh | sudo bash
```

The one-time TUI wizard asks for your bot token (from
[@BotFather](https://t.me/BotFather)) and chat ID, lets you toggle monitor
categories and thresholds, then:

- writes `/etc/statix-agent/config.toml` (`0600`),
- installs `/usr/local/bin/statix-agent`,
- and enables the hardened systemd service (`Restart=always`).

The TUI runs **only** at install time. Everything afterward is done through the
bot. Piping a script to `sudo bash` runs it as root — you are encouraged to read
[`install.sh`](install.sh) first; it is short.

## Supported platforms

The agent runs on **Linux** and is released for:

- `linux/amd64`
- `linux/arm64`

It reads `/proc`, `/sys`, the auth log (`journalctl` / `/var/log/auth.log`),
utmp (with a `loginctl` fallback for utmp-less distros such as Ubuntu 24.10+),
and the Docker Engine socket when present.

### Optional dependencies

None of these are installed by the agent, and each one degrades to a stated
behaviour rather than an error when it is absent:

| Tool | Used by | Without it |
| --- | --- | --- |
| `ufw` | `/firewall` | The view says it cannot manage this host's firewall, names the likely backends (`firewalld`, `nftables`, `iptables`) instead of claiming the host is open, and offers no rule-changing buttons. `ufw` is absent from Alpine, Arch, Debian netinst/cloud images and containers, and is EPEL-only on the RHEL family. |
| Docker Engine socket | `/docker` | The container view and container alerts are disabled. |
| `journalctl` | SSH auth-log watching | Falls back to `tail -F /var/log/auth.log`. |

Development and the full test suite run on any OS (Linux, macOS, Windows) —
every parser is a pure function tested against fixtures.

## Development

Requires Go 1.25+.

```sh
go test ./...   # full suite (14 packages), green on any OS
go vet ./...
make build      # cross-compile linux amd64 binaries into bin/
make dist        # all release artifacts + checksums
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, code-quality expectations,
and how to structure a change, and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
for the design.

### Releasing

Generate a signing key once with `go run ./tools/sign keygen`, store the private
half as the `STATIX_SIGNING_KEY` repository secret, then push a `v*` tag — CI
builds, signs, and publishes the release.

## Project status

**Early open-source release (v0.x).** The MVP described in [mvp.md](mvp.md) is
built and covered by tests, and the project has iterated through several UX
rounds (inline keyboards, live mode, button-driven watch management, alert
action buttons, trends, and a first remediation action). It is a working
project with a strong foundation, now opened to the community.

It is **not** yet declared production-ready: it has not been through broad
real-world deployment across many distros, and there is no published security
audit. Treat v0.x accordingly, and please report what breaks.

### Trade-offs

The decentralized design has deliberate costs:

- **No cross-server correlation** — the same IP attacking several of your
  servers is not seen as one pattern.
- **No aggregated view** — an "all servers" query means asking each bot.
- **History is in memory** — a restart loses SSH/alert history; there is no
  database, by design.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for what is done, what is stabilizing, and what is
planned. Everything beyond the current release is clearly marked as future work
and is not a commitment.

## Contributing

Contributions are welcome — this is exactly the stage where they have the most
impact. Good first areas include Linux distro compatibility, hardware/sensor
coverage, SSH/security detection, tests, and documentation. Start with
[CONTRIBUTING.md](CONTRIBUTING.md).

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Report privately
via a [GitHub Security Advisory](https://github.com/eliau2005/statixagent/security/advisories/new).
See [SECURITY.md](SECURITY.md) for the disclosure process.

## License

StatixAgent is released under the [MIT License](LICENSE). By contributing, you
agree that your contributions are licensed under the same terms.

## Contributors

Thanks to everyone who has contributed to StatixAgent:

<a href="https://github.com/eliau2005/statixagent/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=eliau2005/statixagent" alt="Contributors" />
</a>
