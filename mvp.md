# StatixAgent — Product Spec (MVP)

> This is the original product specification and vision for StatixAgent, kept as
> a reference for *why* the project is shaped the way it is. It is a spec, not a
> status report: the authoritative description of what is implemented today is
> the [README](README.md), the current design is in
> [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), and forward-looking work is in
> [ROADMAP.md](ROADMAP.md). Where this document sketches commands or scope, the
> current implementation is the source of truth; notes below flag the places
> where the project has since moved past the original scope.

## 1. Vision

A self-hosted monitoring tool for VPS servers and home laptops. Each server gets a fully independent, isolated unit: an agent that collects metrics and a private Telegram bot through which you monitor it and receive alerts. Installation happens with a single command that launches a graphical-textual TUI for all configuration.

Guiding principle: **simplicity, isolation, and a featherweight footprint.** No central server, no external dependencies, and no data passing through any third party of yours.

## 2. Architecture

- **Fully decentralized** — a single, self-contained install per server. No aggregator, no single point of failure.
- **A separate Telegram bot per server** — each agent has its own token and chat.
- **Language: Go** — a single static binary, no runtime or dependencies. Minimal resource usage, suited to running continuously.
- **Runs as a systemd service** with `Restart=always` — starts automatically with the server and recovers from crashes.
- **Concurrent internal model** (goroutines): a metrics-sampling loop, a bot-command listener, and an SSH-log watcher run in parallel inside one lightweight process.

**Two deliberate trade-offs that follow from the decentralized choice:**

- No cross-server correlation (the same IP attacking all your servers won't be seen as one pattern).
- An "all servers" status query requires contacting each bot separately.

Both are an acceptable price for the isolation and simplicity.

## 3. What the Tool Monitors

### Core system *(enabled by default)*

CPU (total, per-core, load average), memory (RAM, swap), disk (per-mount, IOPS, read/write, low-space warning), network (up/down rate per-interface, total traffic — important for VPS bandwidth caps). Also: uptime, process count, open file descriptors.

### Thermal & hardware *(laptops / physical machines)*

CPU/GPU temperature, fan speed, thermal-throttling detection.

### Battery & power *(the standout feature for home laptops)*

Battery percentage, plugged-in / unplugged state, **immediate alert on power loss**, battery health (current vs. design capacity), wattage draw, estimated time until shutdown.

### Services & processes *(enabled by default)*

Docker (container status, per-container CPU/RAM, restart-loop detection), selected systemd services, specific processes (node/nginx/postgres), port checks, HTTP healthchecks against endpoints.

### Network & reachability

Heartbeat (a silent agent → the server may be down/off), latency, expiring SSL certificates.

### SSH & security monitoring *(killer feature)*

- **Live sessions:** who is currently connected (user, source IP, duration, TTY), geo-IP of the source, **real-time alert on every new login**.
- **History:** full login log (who / when / from where / how long), logout events, statistics on connection hours and known IPs.
- **Failed attempts:** failed logins (user + IP + frequency), **brute-force detection with immediate alert**, login attempts with a nonexistent user, **strong alert on a successful root login**, changes to `authorized_keys`, and distinguishing key-based from password-based auth.

**Sources:** `/proc`, `/sys/class/thermal`, `/sys/class/power_supply`, `lm-sensors`, the Docker API, `journalctl _COMM=sshd` / `/var/log/auth.log`, and `who` / `w` / `last` / `lastb`.

## 4. Installation Flow (TUI)

A single command (`curl ... | bash`) downloads the binary and launches a one-time TUI wizard that performs:

1. **Telegram bot setup** — enter the token and chat ID (with guidance on how to obtain them).
2. **Choose what to monitor** — toggles per category, with defaults pre-selected.
3. **Set alert thresholds** (CPU %, disk %, temperature, battery).
4. **Select specific services / processes / ports** to monitor.
5. **Configure auto-update** — **disabled by default**.
6. **Create and start the systemd service.**

The TUI runs **at install time only**. Everything afterward is done through the bot.

## 5. Self-Update

- **Checks against GitHub Releases** (already on the network whitelist).
- **Atomic, safe process:** download to a temporary file → verify SHA256 + signature → atomic swap (`rename`) → restart via systemd → **automatic rollback** if the new version enters a crash-loop.
- **Automatic:** periodic check, **disabled by default** (opt-in during install).
- **Manual from the bot:** `/update` shows whether a new version exists; `/update confirm` performs it — **requires explicit confirmation** as a state-changing action.

## 6. Bot Commands (Sketch)

- `/status` — full server snapshot.
- `/cpu` `/mem` `/disk` `/net` `/temp` `/battery` — a specific metric.
- `/services` `/docker` — service and container status.
- `/ssh` — live sessions; `/ssh history` — history; `/ssh fails` — failed attempts.
- `/update` / `/update confirm` — update.
- All alerts arrive automatically (push) — no need to ask.

## 7. Security Notes

- The bot token sits in a config file on the server — store it with restrictive permissions (`chmod 600`), and consider encryption at rest.
- Update integrity is critical: whoever controls the update source controls the server, so signature verification on the downloaded binary is non-negotiable for auto-update.
- Bot-triggered state changes (e.g. updates, and any future "kill session" / "block IP" actions) must always require explicit confirmation.

## 8. Explicitly Out of MVP Scope

- A central aggregator or unified cross-server dashboard.
- A live TUI dashboard (htop-style) — the TUI is installer-only for now.
- Cross-server brute-force correlation.
- Bot-triggered remediation actions (disconnect session / block IP) — originally
  a candidate for a later version. **Update:** confirmation-gated remediation has
  since begun — `/firewall` (open/close SSH port 22 via `ufw`) and SSH session
  disconnect are now implemented. Further remediation is tracked in
  [ROADMAP.md](ROADMAP.md).
