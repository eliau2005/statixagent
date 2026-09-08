# Contributing to StatixAgent

Thank you for considering a contribution. StatixAgent is an early-stage,
single-maintainer-scale project with a deliberately small and well-tested
codebase — which makes it a good project to contribute to, and a good one to
keep tidy. This guide explains how to get set up, what a good change looks like,
and how to get it merged.

## Project philosophy

A few principles guide almost every decision here. Understanding them will make
your changes land faster:

- **Featherweight.** One static binary, no runtime dependencies, no database,
  a small memory ceiling. New dependencies and background state are resisted,
  not welcomed by default.
- **Isolated.** One agent, one machine, one private bot. StatixAgent is
  intentionally not a fleet tool.
- **Honest.** The docs describe what the code actually does. We do not document
  aspirational features as if they exist.
- **Testable everywhere.** OS-specific behavior is thin and lives behind
  interfaces; the logic that matters is pure and tested with fixtures, so the
  suite is green on Linux, macOS, and Windows.
- **Safe by construction.** Privileged and state-changing actions are narrow,
  explicit, and confirmed. Self-update is signature-verified with no bypass.

If a change pulls against one of these, that is not an automatic "no" — but say
so in the PR and make the case.

## Prerequisites

- **Go 1.25 or newer** (`go version`). The module targets the version in
  [`go.mod`](go.mod).
- **git**.
- Optional, for building or running the agent on a real host: a Linux machine,
  and `make` for the convenience targets.

You do **not** need Linux to develop: the full test suite runs on any OS.

## Getting set up

```sh
git clone https://github.com/eliau2005/statixagent.git
cd statixagent
go test -race ./... # should be all green and race-free
```

That's it — there is no code generation, no vendored tree to sync, and no
services to stand up.

## Everyday commands

```sh
go test -race ./...           # run the full suite with the race detector
go test ./internal/alert/...  # run one package while iterating
go vet ./...                  # static checks — must be clean
gofmt -l .                    # list unformatted files (should print nothing)

make build                    # cross-compile the linux/amd64 binaries into bin/
make dist                     # build every release artifact + checksums
make clean
```

### Cross-compilation

The agent only *runs* on Linux, but you can build it from anywhere:

```sh
GOOS=linux GOARCH=amd64 go build ./cmd/statix-agent
GOOS=linux GOARCH=arm64 go build ./cmd/statix-agent
```

CI cross-compiles both architectures on every push and pull request, so a change
that only breaks one of them will be caught.

## Code quality expectations

- **`gofmt`** — all code must be formatted. Configure your editor to run it on
  save, or run `gofmt -w .` before committing.
- **`go vet` clean** — no vet warnings.
- **Match the surrounding code.** The codebase has a consistent, comment-forward
  style: package doc comments explain *why* a package exists, and non-obvious
  logic gets a short explanatory comment. New code should read like the code
  next to it.
- **No new dependencies without a reason.** The dependency list is short on
  purpose. If a change needs a new module, justify it in the PR — the bar is
  high for anything in the agent's runtime path.
- **Respect the OS-abstraction boundary.** Anything that parses text or bytes
  should be a pure function tested with fixtures; only thin `//go:build linux`
  files should open real paths or run commands. See
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Testing expectations

- **New behavior comes with tests.** For parsers, that means a fixture and a
  table test. For agent orchestration, that means driving a faked `Sources`
  through the scenario.
- **Fixes come with a regression test** that fails before the fix and passes
  after, where practical.
- **Keep the suite fast and hermetic.** Tests must not reach the network, touch
  real system paths, or depend on the host OS. Use fixtures, `fstest.MapFS`,
  temp dirs, and the existing fakes.
- Run `go test -race ./...` before pushing; it should be green and race-free on your machine.

## How to structure a change

1. **Open an issue first** for anything non-trivial, so the approach can be
   discussed before you invest time. Small, obvious fixes can go straight to a
   PR.
2. **Branch** from `main`.
3. **Keep the change focused.** One logical change per pull request. Unrelated
   cleanups belong in their own PR.
4. **Update the docs** in the same PR when you change behavior, commands, the
   config schema, or the security surface — the docs are expected to match the
   code (README, ARCHITECTURE, SECURITY, ROADMAP as relevant).

### Commits and pull requests

- Write clear commit messages: a concise summary line, and a body explaining the
  *why* when it isn't obvious.
- In the PR description, cover: **what** changed, **why**, and **how you tested
  it**. Link the issue it addresses.
- Make sure `go test -race ./...`, `go vet ./...`, and `gofmt` are clean — CI runs the
  first two plus a cross-compile smoke on both architectures, and a red build
  will not be merged.

## Reporting issues

Use the issue templates:

- **Bug report** — include what you expected, what actually happened, your
  environment (OS/distro, architecture, agent version from `/status` or
  `statix-agent --version`), and reproduction steps or relevant logs. Redact
  your bot token and chat ID.
- **Feature request** — describe the problem you're trying to solve first, then
  the change you have in mind. Because "featherweight and isolated" is a core
  value, proposals are weighed against footprint and scope.

## Security issues

**Do not** report vulnerabilities in public issues or pull requests. Follow the
private disclosure process in [SECURITY.md](SECURITY.md) (a GitHub Security
Advisory).

## First-time contributors

Welcome — this is a friendly place to make a first open-source contribution. Low
-risk, high-value areas to start with:

- **Linux distro compatibility** — try the agent (or just the parsers against
  captured fixtures) on a distro you use and fix what doesn't line up.
- **Hardware / sensor coverage** — thermal zones, hwmon, and power-supply
  layouts vary; more fixtures and parsing fixes are always useful.
- **Tests** — filling gaps in coverage is a genuinely valuable contribution and
  a great way to learn the codebase.
- **Documentation** — if something here or in the other docs was unclear or
  wrong, fixing it helps the next person.

If you're not sure where to start, open an issue describing what you'd like to
work on and ask.

## What makes a good contribution

- It solves a real problem, and the PR explains that problem.
- It is focused, tested, formatted, and vet-clean.
- It keeps the agent light and the OS-abstraction boundary intact.
- It leaves the docs true.
- It is honest about its limitations.

We would rather merge a small, correct, well-tested change than a large one that
needs three rounds of untangling. Thanks for helping StatixAgent grow.

## License

StatixAgent is licensed under the [MIT License](LICENSE). By submitting a
contribution, you agree that it is licensed under the same terms.
