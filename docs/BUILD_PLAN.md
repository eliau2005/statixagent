# Build Plan — engineering record

This is the phase-by-phase record of how StatixAgent's current feature set was
built, derived from [mvp.md](../mvp.md). It is kept as a historical engineering
tracker: it documents the order in which things were implemented and the
decisions taken along the way. **For forward-looking work — what's planned and
where contributions are wanted — see [ROADMAP.md](../ROADMAP.md).**

Each phase ended in a green test suite and a commit. The target platform is
Linux (amd64/arm64); development and CI run on any OS. Everything that parses
text (`/proc` formats, logs, config) is platform-neutral and unit-tested with
fixtures; everything that touches the live OS sits behind an interface and
`//go:build linux` (see [ARCHITECTURE.md](ARCHITECTURE.md)).

## Status legend

- [ ] not started  · [~] in progress  · [x] done

All items below are complete; the checkboxes are preserved as the historical
record of the build.

## Phase 0 — Foundation

- [x] Git repo, MVP spec committed
- [x] Build plan + architecture docs
- [x] Go module `github.com/eliau2005/statixagent`, repo layout, Makefile, lint config
- [x] `internal/config`: TOML config schema (bot token, chat ID, enabled monitors,
      thresholds, services/ports/endpoints lists, auto-update flag), load/validate/save,
      0600 permission enforcement on save. Unit tests.

## Phase 1 — Metric collection (read side)

- [x] `internal/procfs`: parsers for `/proc/stat` (CPU), `/proc/meminfo`, `/proc/loadavg`,
      `/proc/uptime`, `/proc/net/dev`, `/proc/diskstats`, `/proc/sys/fs/file-nr`,
      process count from `/proc/[pid]`. Pure functions over `io.Reader` — fixture tests.
- [x] `internal/collect`: snapshot model (`Snapshot` struct with CPU/mem/disk/net/uptime
      sections). Delta-based rate computation (CPU %, net B/s, disk IOPS) between
      consecutive samples, counter-reset safety, partition filtering. Unit tests.
- [x] `internal/sysfs` (thermal): `/sys/class/thermal` + `/sys/class/hwmon` parsing
      (temp, fans), throttle detection. fstest.MapFS fixture tests.
- [x] `internal/sysfs` (power): `/sys/class/power_supply` parsing — battery %, AC online,
      health (full vs design), wattage, time-to-empty estimate. Fixture tests.
- [x] Disk usage per mount (statfs) behind `//go:build linux`; mount filtering logic
      (skip pseudo-FS, dedupe bind mounts, octal unescape) is platform-neutral and tested.

## Phase 2 — Services, Docker, reachability

- [x] `internal/services`: systemd unit status via `systemctl show` invocation (interface
      + fake for tests), specific-process presence via /proc scan, TCP port checks,
      HTTP healthchecks with timeout + expected-status.
- [x] `internal/dockermon`: Docker Engine API over unix socket (no SDK dependency —
      plain HTTP client): container list, per-container stats, restart-loop detection
      (restart count delta). Fixture tests against recorded API JSON.
- [x] `internal/netcheck`: SSL certificate expiry checks (+ TCP latency helper).

## Phase 3 — SSH & security monitoring

- [x] `internal/sshwatch`: auth-log line parser (sshd journald/auth.log formats):
      accepted logins (user, IP, method key/password), failed attempts, invalid users,
      root logins, disconnects. Pure parser + fixture tests. Event ring buffer (History).
- [x] Brute-force detector: sliding-window counter per IP with threshold alert and
      quiet-period dedupe during ongoing attacks. Unit tests.
- [x] Live sessions via utmp parsing (`/var/run/utmp`) — binary format reader, fixture test.
- [x] `authorized_keys` change watcher (hash polling). Unit tests with temp dirs.
- [x] Geo-IP: offline-friendly — ip-api.com lookup with cache, private-IP short-circuit,
      graceful no-network fallback.

## Phase 4 — Alert engine

- [x] `internal/alert`: threshold rules (CPU %, mem %, disk %, temp, battery %),
      hysteresis (fire once, clear on recovery), cooldown/dedupe, severity levels.
      Power-loss and new-SSH-login as event alerts (no threshold). Unit tests.

## Phase 5 — Telegram bot

- [x] `internal/telegram`: minimal Bot API client (sendMessage, getUpdates long-poll,
      4096-char message splitting) — no third-party SDK.
- [x] `internal/bot`: command router with chat-ID allowlist + formatters for status,
      cpu/mem/disk/net/temp/battery, services, docker, ssh sessions/history/fails,
      and push alerts. HTML-escaped, emoji-status, usage bars. Unit tests.
- [x] Push alerts wired from the alert engine to the bot sender (Phase 6 wiring).

## Phase 6 — Agent daemon

- [x] `cmd/statix-agent` + `internal/agent`: main loop — goroutines for sampler, bot
      listener, ssh watcher (journalctl/auth.log tail with auto-restart), keys watcher;
      graceful shutdown on SIGTERM; panic-safe goroutine wrapper; platform-neutral
      orchestrator with injected Sources, tested with fakes.
- [x] systemd unit file template (`Restart=always`, hardening directives).

## Phase 7 — Installer TUI

- [x] `cmd/statix-install` with Bubble Tea: token/chat-ID entry (with guidance),
      monitor toggles, thresholds, service/port selection, auto-update opt-in;
      `internal/install` writes config (0600), installs binary, creates+starts the
      systemd unit (prefix-relative + fake runner → fully unit-tested).
- [x] `install.sh` one-liner entry script (arch detection, checksum verify, run TUI).

## Phase 8 — Self-update

- [x] `internal/update`: GitHub Releases check, download to temp, SHA256 + ed25519
      signature verify (mandatory — refuses without embedded key), atomic rename with
      .prev rollback copy, systemd restart, crash-loop RollbackGuard. Unit tests for
      version compare, tampered binary, wrong-key signature, swap, rollback.
- [x] Bot `/update` + `/update confirm` integration (wired in main_linux.go; key and
      version stamped via -ldflags at release time). Auto-update loop when opted in.

## Phase 9 — Hardening & release

- [x] End-to-end smoke build for linux/amd64 + linux/arm64.
- [x] README with install instructions; SECURITY.md notes from MVP §7.
- [x] GitHub Actions CI + release workflow (build, checksum, ed25519 sign via
      tools/sign, publish). Makefile mirrors release builds locally.

**All MVP phases complete — the MVP is built.** The sections below record the
UX and feature iterations that shipped on top of it. Directions beyond what is
recorded here live in [ROADMAP.md](../ROADMAP.md); out-of-scope items are noted
in [mvp.md](../mvp.md) §8.

## Post-MVP fixes (v0.2.0)

- [x] `/ssh` on utmp-less distros (Ubuntu 24.10+): fall back to systemd-logind via
      `loginctl` (`internal/sshwatch/loginctl.go`), keeping utmp as the primary source.
- [x] Telegram redesign — dashboard cards: aligned `<pre>` layouts with bars and
      dividers for every command, paths inside pre so Telegram stops rendering mounts
      like `/boot` as bot commands, junk/duplicate temperature sensors filtered,
      zero-traffic interfaces hidden from `/status`, alerts as severity banners with
      `<blockquote>`, grouped `/help`.

## v0.3.0 — bot command upgrades

- [x] `/update_confirm` as a tappable single-token command (legacy `/update confirm`
      still accepted). Command menu registered via setMyCommands for autocomplete.
- [x] `/clear_chat`: blind ID-range sweep (anchor message − 300) via the
      `deleteMessages` API; undeletable/older-than-48h IDs are skipped by Telegram.
- [x] Runtime watch management, persisted to config: `/services_scan` (running units
      via systemctl) + `/services_add|remove`, `/ports_scan` (LISTEN ports from
      `/proc/net/tcp{,6}`) + `/ports_add|remove`, `/procs_add|remove`.

## v0.4.0 — inline keyboards (UX loop, iteration 1)

- [x] Telegram client: callback_query updates, inline keyboards on send,
      editMessageText (in-place view morphing, "not modified" tolerated),
      answerCallbackQuery.
- [x] Navigation keyboard on every metric view (status/cpu/mem/disk/net/temp/
      battery/services/docker/ssh) — buttons swap the SAME message between views,
      the active view is highlighted, 🔄 re-renders. Update offers carry
      ⬇️ Install now / Later buttons; foreign-chat callbacks fully ignored.

## v0.5.0 — live mode (UX loop, iteration 2)

- [x] ▶️ Live button on the nav keyboard: re-samples and re-renders the status card
      in place every 3s until ⏹ Stop is tapped (with a 1h safety ceiling), showing
      a spinner frame (◐◓◑◒) and elapsed duration, ⏹ Stop ends early, nav keyboard
      restored at the end. One session at a time; bound to the agent context so
      shutdown cancels it.

## v0.6.0 — button-driven watch management (UX loop, iteration 3)

- [x] `/watching` hub: everything watched with a 🗑 button per item; scan views carry
      ➕ buttons per candidate (services 2/row, ports 3/row, capped at 12 with typed
      fallback); footer row links Watching ↔ scan views. All edits in place, all
      changes persisted to config; typed commands still work.

## v0.7.0 — alert action buttons (UX loop, iteration 4)

- [x] Every push alert carries one-tap context actions: SSH/brute/keys alerts get
      👥 Sessions · 🚫 Fails · 🕐 History; threshold alerts get their metric view +
      Status. The alert message morphs into the chosen view in place. Startup hello
      carries 📊 Status / 👁 Watching quick buttons.

## v0.8.0 — trends & settings (UX loop, iteration 5)

- [x] Sparkline trends (▁▂▃▄▅▆▇█) on /cpu and /mem from a 40-point ring of samples
      (~10 min at the default interval).
- [x] ⚙️ /settings: every alert threshold tunable with ➖/➕ buttons (step 5, clamped
      ranges), persisted to config and effective immediately in the alert engine.
      Nav keyboard gained a 👁 Watching / ⚙️ Settings row.

## v0.9.0 — 🛡 firewall control (first remediation action)

- [x] /firewall: open/close SSH port 22 via ufw with a mandatory confirmation screen
      (MVP §7), state parsed from `ufw status` (open/closed/unmanaged/inactive),
      opposite rule removed before applying so ufw rule ordering can't mask the
      change. SSH alerts link to it (🛡 button). Unit sandbox carves out
      -/etc/ufw and -/lib/ufw.

## Out of scope (per MVP §8)

Central aggregator, live TUI dashboard, and cross-server correlation remain out
of scope. Remediation actions were originally out of scope but have since begun,
confirmation-gated, with `/firewall` and SSH session disconnect (v0.9.0);
further remediation is tracked in [ROADMAP.md](../ROADMAP.md).
