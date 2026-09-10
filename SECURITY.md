# Security Policy

StatixAgent runs continuously on a machine you care about, holds a Telegram bot
token, and can replace its own binary. Its security properties matter, so this
document is precise about what is implemented today and what is not.

This policy describes the security model of the code in this repository. It is
**not** a security audit, and StatixAgent has not had one. See
[Future hardening opportunities](#future-hardening-opportunities).

## Reporting a vulnerability

Please report security issues **privately**, not in a public issue or pull
request.

- Open a [GitHub Security Advisory](https://github.com/eliau2005/statixagent/security/advisories/new)
  on this repository.

Please include, where you can: what an attacker can do, the affected component,
and steps or a proof of concept to reproduce it. We will acknowledge the report,
work with you on an assessment and fix, and credit you in the release notes
unless you prefer to remain anonymous. As an early-stage project there is no
formal SLA yet, but reports are taken seriously and handled as a priority.

## Threat model

StatixAgent is a single-machine agent with a private Telegram control plane.
The security model is built around three sensitive surfaces:

1. **The bot token** — anyone who reads it can impersonate the bot.
2. **The command surface** — the bot can read system state and take a small set
   of privileged actions.
3. **The update channel** — whoever controls what the agent installs controls
   the machine, since the agent runs with root privileges.

The design assumes:

- Telegram's Bot API is the transport and is trusted to deliver messages to and
  from the configured chat. StatixAgent does not add end-to-end encryption on
  top of Telegram.
- The GitHub Releases of the configured repository are the update source; their
  integrity is enforced by signature verification (below) rather than trusting
  the transport alone.
- The operator controls the host and the Telegram account that owns the bot.

Out of scope: defending against an attacker who already has root on the host, a
compromised Telegram account, or a compromised release-signing key.

## Implemented security controls

### Telegram authentication & authorization

- The agent accepts commands **only** from the single `chat_id` in the config.
  Updates from any other chat are dropped before parsing (`internal/bot`,
  `Router.Dispatch`).
- Inline-keyboard callbacks are checked the same way; callbacks from a foreign
  chat are ignored.
- State-changing actions require an explicit, separate confirmation:
  - `/update` only *checks*; installing requires `/update_confirm`.
  - `/firewall` presents a mandatory confirmation screen before changing a rule.

### Secret / token handling

- The bot token lives in `/etc/statix-agent/config.toml`.
- The config writer always creates the file with `0600` permissions, using an
  atomic temp-file + `rename` so the token is never briefly world-readable
  (`internal/config`, `Save`).
- The installer creates `/etc/statix-agent` and the systemd unit grants the
  service write access to that directory (plus the binary path and, optionally,
  the `ufw` directories) and nothing else.

### systemd hardening

The shipped unit (`deploy/statix-agent.service`) applies:

- `NoNewPrivileges=yes`
- `ProtectSystem=full` — most of the filesystem is read-only
- `ProtectHome=read-only`
- `ReadWritePaths=/etc/statix-agent /usr/local/bin -/etc/ufw -/lib/ufw` — the
  binary path is writable so self-update can swap it; the `ufw` paths are
  writable so `/firewall` can edit rules, and are skipped if absent
- `PrivateTmp=yes`, `ProtectKernelTunables=yes`, `ProtectControlGroups=yes`,
  `RestrictSUIDSGID=yes`
- `MemoryMax=128M`

### Self-update verification

Self-update (`internal/update`) is safe-by-construction:

- **Ed25519 trust model.** Each release ships `checksums.txt` and a detached
  `checksums.txt.sig`. The signature is verified against an ed25519 **public
  key compiled into the agent** at release time (`-ldflags -X main.pubKeyHex`).
  The matching private key exists only as the `STATIX_SIGNING_KEY` CI secret.
- **Mandatory verification.** `Apply` refuses to run if the build carries no
  public key, if the signature does not verify, or if the release is missing the
  signed checksums. There is no flag to skip it.
- **SHA256 verification.** The downloaded binary's SHA256 must match the entry
  in the signed `checksums.txt`, or the update aborts before touching disk.
- **Atomic swap.** The new binary is written to a temp file and `rename`d into
  place; the previous binary is preserved as `<binary>.prev`.
- **Rollback behavior.** A crash-loop guard runs at startup: if the process
  starts too many times inside a short window (default: 3 starts in 2 minutes)
  and a `.prev` binary exists, it restores `.prev`, consumes it (so versions
  cannot ping-pong), and exits for systemd to start the restored binary.
- **Off by default.** Automatic update checks are disabled unless enabled at
  install time; the bot's `/update` flow is always manual and confirmed.

### What the agent can execute with root privileges

The agent runs as root (it reads privileged paths and manages a system
service). Its outward actions are deliberately narrow:

- **Reads** `/proc`, `/sys`, the SSH auth log, utmp, `authorized_keys` files,
  and the Docker socket.
- **Invokes** external tools for specific tasks: `systemctl` (service status and
  self-restart), `journalctl` / `tail` (auth-log stream), `loginctl` (session
  fallback and SSH disconnect), and `ufw` (firewall rule changes). Each is used
  only where it is already installed — the agent never installs a package, and
  `/firewall` states that it cannot manage this host's firewall rather than
  acting through a different backend.
- **Writes** only its config file, its binary (on update), and its start-count
  state file.
- **Network:** talks to the Telegram Bot API, to GitHub (release checks), and to
  the geo-IP lookup service for SSH source IPs; performs outbound TCP connects
  for `/ping`, port checks, and TLS certificate expiry checks.

There is no arbitrary shell command execution exposed through the bot, and no
remote code path that is not signature-verified.

## Future hardening opportunities

These are **not** implemented today. They are recorded so expectations are
honest and so contributors know where help is welcome.

- **Running as a non-root user.** The agent currently runs as root. A reduced
  set of Linux capabilities (or a dedicated user for parts of the workload)
  would shrink the blast radius.
- **Token encryption at rest.** The token is protected by file permissions
  (`0600`), not encrypted. `mvp.md` notes encryption at rest as a possible
  future step.
- **Signing-key rotation & transparency.** There is a single embedded signing
  key and no documented rotation procedure or transparency log.
- **Rate limiting / audit logging** of bot commands.
- **A third-party security review.** None has been performed.

## Scope of this policy

This policy covers the agent, installer, and update tooling in this repository.
It does not cover Telegram, GitHub, the geo-IP provider, or the security of the
host OS on which the agent runs.
