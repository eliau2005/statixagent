# StatixAgent — Build Plan

Derived from [mvp.md](../mvp.md). Each phase ends in a green test suite and a commit.
Development happens on Windows; the target platform is Linux (amd64/arm64). Everything
that parses text (`/proc` formats, logs, config) is platform-neutral and unit-tested with
fixtures; everything that touches the live OS sits behind an interface and `//go:build linux`.

## Status legend

- [ ] not started  · [~] in progress  · [x] done

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

**All phases complete — the MVP is built.** Future work beyond the MVP lives in
mvp.md §8 (out of scope) and would start with bot-triggered remediation actions.

## Post-MVP fixes (v0.2.0)

- [x] `/ssh` on utmp-less distros (Ubuntu 24.10+): fall back to systemd-logind via
      `loginctl` (`internal/sshwatch/loginctl.go`), keeping utmp as the primary source.
- [x] Telegram redesign — dashboard cards: aligned `<pre>` layouts with bars and
      dividers for every command, paths inside pre so Telegram stops rendering mounts
      like `/boot` as bot commands, junk/duplicate temperature sensors filtered,
      zero-traffic interfaces hidden from `/status`, alerts as severity banners with
      `<blockquote>`, grouped `/help`.

## Out of scope (per MVP §8)

Central aggregator, live TUI dashboard, cross-server correlation, remediation actions.
