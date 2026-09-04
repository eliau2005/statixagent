# Roadmap

This is the public roadmap for StatixAgent. It reflects the state of the
repository today and the directions the project is likely to take. Anything in
**Planned** or **Long-term** is a *direction*, not a commitment or a schedule.

For the engineering history — the phase-by-phase record of how the current
feature set was built — see [docs/BUILD_PLAN.md](docs/BUILD_PLAN.md).

## Where the project is

**Early open-source release (v0.x).** The MVP is built and covered by tests, and
several rounds of UX work have shipped on top of it. It is a working project
with a strong foundation, now opened to the community. It is not yet declared
production-ready (no broad multi-distro field testing, no security audit).

## Completed

- **Licensed** — StatixAgent is released under the [MIT License](LICENSE).

The MVP and the UX iterations on top of it are done and tested:

- **Core metrics** — CPU (total, per-core, load), memory/swap, disk space per
  mount, disk I/O rates, network rates and lifetime totals, uptime, process
  count, open file descriptors.
- **Thermal & power** — temperatures (thermal zones + hwmon), fans, throttling
  detection; battery charge/health/wattage/time-to-empty and an immediate
  power-loss alert.
- **Workloads** — systemd units, named processes, TCP ports, HTTP healthchecks,
  Docker containers (status, per-container CPU/RAM, restart-loop detection).
- **Reachability** — TLS certificate expiry checks and `/ping` TCP latency.
- **SSH & security** — per-login alerts with geo-IP and root escalation, live
  sessions (utmp with a `loginctl` fallback), login/failure history,
  brute-force detection, and `authorized_keys` change alerts.
- **Alert engine** — thresholds with hysteresis, sustained-sample requirement,
  cooldown/dedupe, snooze, and event alerts (power, reboot, container, SSH).
- **Telegram control plane** — full command set, inline keyboards on every
  view, in-place message morphing, alert action buttons, live mode, sparkline
  trends, button-driven watch management, `/settings`, and a daily digest.
- **First remediation actions** — SSH session disconnect and `/firewall`
  (open/close port 22 via `ufw`), both behind confirmation.
- **Self-update** — GitHub Releases, mandatory ed25519 + SHA256 verification,
  atomic swap, and crash-loop rollback.
- **Installer** — one-line `install.sh` and a one-time Bubble Tea TUI wizard;
  hardened systemd unit.
- **CI/CD** — test + vet + cross-compile on every push/PR; tag-driven signed
  releases for `linux/amd64` and `linux/arm64`.

## In progress / stabilization

The pieces that exist but most need real-world exposure and polish:

- **Multi-distro validation.** The parsers are fixture-tested, but the more
  distros they meet in the wild, the more confident the release can be —
  especially SSH auth-log formats, utmp/`loginctl` behavior, and sensor layouts.
- **Hardware coverage.** Thermal and power-supply sysfs layouts vary widely
  across laptops and boards; edge cases surface as new hardware is tried.
- **Documentation.** Keeping the docs in lockstep with the code as the project
  opens up.

## Planned

Reasonable next steps consistent with the current MVP and architecture. These
are *future work* and not yet implemented:

- **More remediation actions** (all confirmation-gated), building on the
  `/firewall` and SSH-disconnect pattern — for example blocking a source IP
  during a brute-force burst.
- **Broader packaging** for the supported architectures and easier upgrades.
- **Configurable geo-IP / privacy controls** for SSH source lookups.
- **Reduced privilege** — exploring running with a reduced Linux capability set
  instead of full root (see [SECURITY.md](SECURITY.md#future-hardening-opportunities)).

## Long-term ideas

Bigger directions that would be genuinely useful but are explicitly *out of
scope for the current design* (see [mvp.md](mvp.md) §8). Listing them is not a
commitment, and some would require revisiting the "no central server, no
database" trade-offs:

- Optional lightweight local history/persistence (today, history is in-memory
  and lost on restart, by design).
- A live TUI dashboard (the TUI is installer-only today).
- Any form of multi-server view or cross-server brute-force correlation — which
  would mean stepping beyond the strictly-decentralized model.

## Where community help is especially valuable

If you're looking for a place to contribute, these areas have the highest
impact right now:

- **Linux distro compatibility** — test on your distro and fix what doesn't fit.
- **Hardware / sensor support** — thermal, hwmon, and power-supply parsing plus
  fixtures for hardware we haven't seen.
- **SSH / security detection** — auth-log formats, session sources, and
  brute-force heuristics.
- **Tests** — filling coverage gaps anywhere in the tree.
- **Integrations** — additional confirmation-gated remediation actions and
  workload checks.
- **UX improvements** — clearer Telegram views, keyboards, and alerts.
- **Reliability** — hardening the goroutine lifecycle, restarts, and edge cases.
- **Documentation** — anything unclear here or in the other docs.

See [CONTRIBUTING.md](CONTRIBUTING.md) to get started.
