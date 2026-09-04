# Architecture

This document is for contributors who want to understand the codebase before
opening a pull request. It explains how the pieces fit together, why the code is
structured the way it is, and where to look for a given concern.

For *what* StatixAgent does, see the [README](../README.md). For the original
product spec, see [mvp.md](../mvp.md).

## The one-sentence model

One static Go binary runs as a systemd service on one machine, samples the
system and watches sshd through a handful of goroutines, and exposes a private
Telegram bot as its entire user interface — no central server, no database, no
third-party data path.

## Process model

`statix-agent` is a single process. Inside it, long-lived goroutines share
in-memory state and communicate over channels:

```
statix-agent (single process, systemd-managed, Restart=always)
│
├─ sampler        — ticks every sample_interval; builds a Snapshot from collectors
├─ ssh-watch      — tails the auth log (journalctl / auth.log), emits security events
├─ keys-watch     — polls authorized_keys hashes, emits change events
├─ alert engine   — evaluates snapshots + events against rules; dedupes; pushes
├─ bot listener   — Telegram getUpdates long-poll; routes commands; replies
└─ update loop    — (opt-in) periodic GitHub Releases check + verified self-swap
```

A `context.Context` derived from `SIGINT`/`SIGTERM` threads through every
goroutine, so a shutdown signal cancels the whole tree gracefully. Each
goroutine runs inside a **panic-recovering wrapper** — one failing subsystem
logs and restarts rather than taking the agent down.

The entry point is `cmd/statix-agent/main_linux.go`; the orchestration lives in
`internal/agent`. A non-Linux stub (`main_other.go`) exists only so the module
compiles and tests run on any OS.

## Package layout & responsibilities

```
cmd/
  statix-agent/      daemon entry point (linux build wires real OS sources)
  statix-install/    one-time TUI installer (Bubble Tea)
internal/
  config/            TOML config: schema, defaults, load, validate, save (0600)
  procfs/            pure parsers for /proc files (io.Reader → structs)
  sysfs/             pure parsers for /sys (thermal, hwmon, power_supply)
  collect/           Collector model, Snapshot, delta/rate math, top processes
  services/          systemd units, process presence, TCP port + HTTP checks
  dockermon/         Docker Engine API over the unix socket (no SDK)
  netcheck/          TLS certificate expiry + TCP connect latency
  sshwatch/          auth-log parser, brute-force detector, utmp/loginctl
                     sessions, authorized_keys watcher, geo-IP cache
  alert/             threshold rules, hysteresis, sustain, cooldown, snooze
  telegram/          minimal Bot API client (send, getUpdates, keyboards, ...)
  bot/               command router + message/keyboard formatting
  agent/             the daemon: wires all of the above into goroutines
  install/           config write, binary install, systemd unit creation
tools/
  sign/              release signing helper (ed25519 keygen / sign / pubkey)
deploy/
  statix-agent.service   the hardened systemd unit template
```

The dependency direction is one-way: `agent` and the `cmd` packages depend on
the leaf packages (`procfs`, `collect`, `alert`, …); the leaves depend on
nothing internal. This keeps the leaves pure and trivially testable.

## OS abstraction strategy

The agent targets Linux, but development and CI must run on any OS. The rule
that makes this work:

> **Parsers are pure; only a thin linux layer touches the real OS.**

- Everything that reads `/proc`, `/sys`, auth logs, utmp, or Docker JSON is a
  function over `io.Reader` / `[]byte` / `fs.FS`, unit-tested with fixtures.
- The linux files (guarded by `//go:build linux`) only *open* real paths and
  hand the reader to a pure parser. Syscall-only pieces (e.g. `statfs` for disk
  usage) live behind a small linux shim, with the platform-neutral logic
  (mount filtering, octal unescape) split out and tested separately.
- External commands and sockets sit behind interfaces — `services.Runner` for
  `systemctl`/`ufw`, the Docker socket client, and the Telegram `Sender` /
  `Updates` interfaces — each with a fake for tests.

The concrete expression of this is the `agent.Sources` struct: a bag of
function fields and interfaces for every OS-dependent reading. The linux entry
point fills it with real implementations; tests fill it with fakes. A `nil`
field simply disables that subsystem (no Docker socket → no `/docker`).

## Data flow

```
/proc, /sys ──► procfs/sysfs parsers ──► collect.Snapshot ──┐
journald/auth.log ──► sshwatch events ─────────────────────┼──► alert engine ──► telegram push
docker.sock ──► dockermon ──────────────────────────────────┘
                                          ▲
user command ──► telegram getUpdates ──► bot router ── reads latest Snapshot / history
```

The sampler computes rates by keeping the *previous* raw sample and diffing
against it (CPU %, network B/s, disk IOPS), with counter-reset safety. The bot
answers queries from the most recent `Snapshot` plus in-memory ring buffers
(SSH events, alert history, and a short trend ring for sparklines).

## Telegram control plane

The bot is the entire UI. Two layers:

- `internal/telegram` — a minimal Bot API client: `sendMessage` (with
  4096-char splitting), `getUpdates` long-poll, inline keyboards,
  `editMessageText` for in-place view morphing, `answerCallbackQuery`,
  `deleteMessages`, and `setMyCommands` for autocomplete.
- `internal/bot` — a `Router` that enforces the single-chat allowlist and maps
  command names to `Handler`s, plus formatters that render state into HTML
  `<pre>` dashboard cards with bars, dividers, and emoji status.

Command *handlers* are registered in `internal/agent` (`buildRouter` in
`agent.go`, watch-management handlers in `watch.go`), because they need access
to live agent state. Inline-keyboard callbacks carry the target command as a
single token in their callback data and are dispatched through the same router
(after the same chat check), so a tapped button and a typed command run
identical code.

## Alert engine

`internal/alert` turns a stream of snapshots and events into a controlled
stream of messages:

- **Threshold rules** with **hysteresis** — fire once on crossing, clear on
  recovery past a margin — so a metric hovering at the line cannot spam.
- **Sustain** — a rule can require the violation to hold for N consecutive
  samples before firing (used so a brief thermal spike stays quiet).
- **Cooldown** — a minimum gap between two fires of the same key.
- **Snooze** — a key can be silenced until a time (the 🔕 button); a violation
  still present when the snooze lifts fires fresh.
- **Event alerts** — power loss, reboot, new SSH login, brute-force burst,
  key change, cert expiry, container down / restart-loop — which have no
  threshold and use the cooldown/dedupe machinery only.

## Update pipeline

`internal/update` implements the verified self-update (see
[SECURITY.md](../SECURITY.md) for the trust model):

```
Check  ──► GitHub Releases "latest" ──► compare versions
Apply  ──► download checksums.txt + .sig
        ──► verify ed25519 signature (key compiled into the binary)
        ──► download binary, verify SHA256 against signed checksums
        ──► SwapBinary: temp write → atomic rename, keep <bin>.prev
        ──► systemctl restart
Startup──► RollbackGuard: too many starts in the window → restore .prev, exit
```

`SwapBinary` and `RollbackGuard` are pure filesystem logic and fully unit-tested
(tampered binary, wrong-key signature, swap, rollback, version compare).

## Persistence model

There is **no database**. This is a deliberate consequence of the featherweight
goal:

- **Config** (`/etc/statix-agent/config.toml`) is the only durable state the
  agent writes deliberately. Runtime changes to the watch list (`/watching`,
  `*_add`/`*_remove`, `/settings`) are persisted back to it.
- **History** (SSH events, alerts, trend samples) lives in in-memory ring
  buffers and is lost on restart.
- **Update state** is a small start-count file next to the config, used only by
  the rollback guard.

If you are tempted to add a datastore, weigh it against this goal first — see
[ROADMAP.md](../ROADMAP.md).

## Privilege model

The agent runs as root under systemd. It needs privilege to read the auth log,
utmp, and other users' `authorized_keys`, and to manage its own service and
firewall rules. The blast radius is contained by the systemd hardening in
`deploy/statix-agent.service` (read-only filesystem except a narrow
`ReadWritePaths`, `NoNewPrivileges`, `MemoryMax`, …) rather than by dropping
privilege inside the process. Reducing this is a known future direction; see
[SECURITY.md](../SECURITY.md#future-hardening-opportunities).

## Testing architecture

- Leaf packages are tested with **fixtures**: recorded `/proc` and `/sys`
  files, auth-log excerpts, Docker API JSON, and utmp blobs, driven through the
  pure parsers with `fstest.MapFS` or `io.Reader`.
- `internal/agent` is tested by constructing an `Agent` with a fully **faked**
  `Sources`, a fake Telegram `Sender`/`Updates`, and driving commands and
  events through it — so the orchestration is exercised on any OS.
- `internal/install` uses a prefix-relative filesystem and a fake command
  runner, so installing the systemd unit is unit-tested without touching the
  host.

Run it all with `go test ./...` (green on Linux, macOS, and Windows). See
[CONTRIBUTING.md](../CONTRIBUTING.md) for expectations on new code.
