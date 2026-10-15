package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/eliau2005/statixagent/internal/services"
	"github.com/eliau2005/statixagent/internal/sshwatch"
)

// Firewall backends (docs/telegram-ux-redesign.md §5.2): ufw here and
// firewalld (fwfirewalld.go), with only the methods the plans and the
// dead-man switch (fwdeadman.go) need: read the state, snapshot it,
// apply a plan, take it back. Both map their rules onto the ufw rule
// model (fwufw.go), so one simulation and one SSH guard serve both.

// FwBackend is a firewall the agent can change under a trial.
type FwBackend interface {
	Name() string
	// Probe reads the current state.
	Probe(ctx context.Context) ufwProbe
	// Added lists the user rules as specs (see fwChange), the ones a plan
	// may delete by spec. The trace is set when listing failed.
	Added(ctx context.Context) ([][]string, *cmdTrace)
	// Snapshot copies the rules, plus the status text, into dir.
	Snapshot(ctx context.Context, dir string) (fwSnap, error)
	// Load reads a snapshot Snapshot wrote.
	Load(dir string) (fwSnap, error)
	// Hash fingerprints the rules as they are now.
	Hash(ctx context.Context) (string, error)
	// Commands is what Apply runs for p, one shell line each, for the
	// confirm screen; an error when the backend cannot make a change.
	Commands(p fwPlan) ([]string, error)
	// Apply runs every change in order, stopping at the first failure.
	// The trace is the last command run, for the audit log.
	Apply(ctx context.Context, p fwPlan) (*cmdTrace, error)
	// Revert applies the inverse of p, change by change and best effort,
	// leaving rules p did not touch alone.
	Revert(ctx context.Context, p fwPlan) error
	// Commit makes p permanent on Keep.
	Commit(ctx context.Context, p fwPlan) error
	// Restore puts a snapshot's rules back.
	Restore(ctx context.Context, s fwSnap) error
	// ident is what a trial record keeps to reach the same backend from
	// another process: the binary that answered, and the zone.
	ident() (bin, zone string)
}

// fwNoter is a backend whose last Restore has something to tell the
// user, such as a firewalld reload that dropped other tools' rules.
type fwNoter interface{ takeNote() string }

// restoreNote is what b's last Restore has to tell, or "".
func restoreNote(b FwBackend) string {
	if n, ok := b.(fwNoter); ok {
		return n.takeNote()
	}
	return ""
}

// Plan operations.
const (
	opInsert  = "insert"  // ufw insert 1 <spec>
	opPrepend = "prepend" // ufw prepend <spec>: first of its family (IPv6 rules)
	opAdd     = "add"     // ufw <spec>
	opDelete  = "delete"  // ufw --force delete <spec>
)

// fwChange is one rule change. Spec is a ufw rule as `ufw show added`
// prints it, without the leading "ufw": built from parsed values or read
// back from the firewall itself, never from user text. firewalld turns
// the same words into its own arguments (fwfirewalld.go).
type fwChange struct {
	Op   string   `json:"op"`
	Spec []string `json:"spec"`
}

// argv is the ufw arguments that make the change.
func (c fwChange) argv() []string {
	switch c.Op {
	case opInsert:
		return append([]string{"insert", "1"}, c.Spec...)
	case opPrepend:
		return append([]string{"prepend"}, c.Spec...)
	case opDelete:
		return append([]string{"--force", "delete"}, c.Spec...)
	}
	return slices.Clone(c.Spec)
}

// fwPlan is an ordered list of changes.
type fwPlan []fwChange

// inverse takes p back: changes in reverse order, each undone by spec. A
// deleted rule comes back at the end of the list, not where it was.
func (p fwPlan) inverse() fwPlan {
	var inv fwPlan
	for i := len(p) - 1; i >= 0; i-- {
		c := p[i]
		if c.Op == opDelete {
			inv = append(inv, fwChange{Op: opAdd, Spec: c.Spec})
		} else {
			inv = append(inv, fwChange{Op: opDelete, Spec: c.Spec})
		}
	}
	return inv
}

// fwSnap is a snapshot of the rules.
type fwSnap struct {
	Files  map[string][]byte // ufw: by base name; a file absent then is absent here
	Status string            // `ufw status verbose` (firewalld: --list-all) at snapshot time
	SHA    string
	// fw is Status parsed into the rule model.
	fw ufwStatus
	// zone is firewalld's zone at snapshot time; nil for ufw.
	zone *fwdZone
	// Added is `ufw show added` at snapshot time, nil when it was not
	// recorded: a restore then has no plan to undo by spec.
	Added [][]string
}

// ufwRuleFiles are the files ufw keeps user rules in.
var ufwRuleFiles = []string{"user.rules", "user6.rules"}

const (
	snapStatusFile = "status.txt"
	snapAddedFile  = "added.txt"
)

// hashRuleFiles fingerprints rule files by name and content, so an absent
// file and an empty one differ.
func hashRuleFiles(files map[string][]byte) string {
	h := sha256.New()
	for _, name := range ufwRuleFiles {
		data, ok := files[name]
		if !ok {
			fmt.Fprintf(h, "%s\x00-\x00", name)
			continue
		}
		fmt.Fprintf(h, "%s\x00%d\x00", name, len(data))
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// readRuleFiles reads the rule files present in dir.
func readRuleFiles(dir string) (map[string][]byte, error) {
	files := map[string][]byte{}
	for _, name := range ufwRuleFiles {
		data, err := os.ReadFile(filepath.Join(dir, name))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return nil, err
		}
		files[name] = data
	}
	return files, nil
}

// loadSnap reads a snapshot written by Snapshot.
func loadSnap(dir string) (fwSnap, error) {
	files, err := readRuleFiles(dir)
	if err != nil {
		return fwSnap{}, err
	}
	if _, ok := files["user.rules"]; !ok {
		return fwSnap{}, fmt.Errorf("snapshot %s has no user.rules", dir)
	}
	status, _ := os.ReadFile(filepath.Join(dir, snapStatusFile))
	s := fwSnap{Files: files, Status: string(status), SHA: hashRuleFiles(files), fw: parseUFWOutput(string(status))}
	if added, err := os.ReadFile(filepath.Join(dir, snapAddedFile)); err == nil {
		s.Added = parseShowAdded(string(added))
		if s.Added == nil {
			s.Added = [][]string{} // recorded, and empty
		}
	}
	return s, nil
}

// ufwBackend is ufw: rules live in dir (/etc/ufw), changes go through
// the ufw binary, which reload applies.
type ufwBackend struct {
	run services.Runner
	dir string
	bin string // the binary that answered; resolved on first use
}

func (b *ufwBackend) Name() string { return "ufw" }

func (b *ufwBackend) ident() (string, string) { return b.bin, "" }

func (b *ufwBackend) Probe(ctx context.Context) ufwProbe {
	p := probeUFW(ctx, b.run)
	if p.bin != "" {
		b.bin = p.bin
	}
	return p
}

// ufw runs one ufw command with the resolved binary, resolving it first
// when no probe has.
func (b *ufwBackend) ufw(ctx context.Context, args ...string) *cmdTrace {
	if b.bin == "" {
		for _, bin := range ufwPaths {
			if _, err := b.run.Run(ctx, bin, "version"); !notFound(err) {
				b.bin = bin
				break
			}
		}
		if b.bin == "" {
			b.bin = ufwPaths[0]
		}
	}
	t := &cmdTrace{argv: append([]string{b.bin}, args...)}
	start := time.Now()
	t.out, t.err = b.run.Run(ctx, b.bin, args...)
	t.dur = time.Since(start)
	return t
}

// added lists the user rules as `ufw show added` prints them, each
// without the leading "ufw".
func (b *ufwBackend) added(ctx context.Context) ([][]string, *cmdTrace) {
	t := b.ufw(ctx, "show", "added")
	if t.err != nil {
		return nil, t
	}
	return parseShowAdded(t.out), nil
}

func (b *ufwBackend) Added(ctx context.Context) ([][]string, *cmdTrace) { return b.added(ctx) }

func (b *ufwBackend) Load(dir string) (fwSnap, error) { return loadSnap(dir) }

// Commands is the ufw command of each change, then the reload.
func (b *ufwBackend) Commands(p fwPlan) ([]string, error) {
	var lines []string
	for _, c := range p {
		lines = append(lines, "ufw "+specText(c.argv()))
	}
	return append(lines, "ufw reload"), nil
}

func (b *ufwBackend) Snapshot(ctx context.Context, dir string) (fwSnap, error) {
	files, err := readRuleFiles(b.dir)
	if err != nil {
		return fwSnap{}, err
	}
	if _, ok := files["user.rules"]; !ok {
		return fwSnap{}, fmt.Errorf("%s not found", filepath.Join(b.dir, "user.rules"))
	}
	t := b.ufw(ctx, "status", "verbose")
	if t.err != nil {
		return fwSnap{}, fmt.Errorf("ufw status verbose: %s", detail(t.out, t.err))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fwSnap{}, err
	}
	for name, data := range files {
		if err := sshwatch.WriteStateFile(filepath.Join(dir, name), data); err != nil {
			return fwSnap{}, err
		}
	}
	if err := sshwatch.WriteStateFile(filepath.Join(dir, snapStatusFile), []byte(t.out)); err != nil {
		return fwSnap{}, err
	}
	snap := fwSnap{Files: files, Status: t.out, SHA: hashRuleFiles(files), fw: parseUFWOutput(t.out)}
	// The rule specs let a later restore of this snapshot be undone by
	// spec. Without them the snapshot is still a rollback target.
	if a := b.ufw(ctx, "show", "added"); a.err == nil {
		if err := sshwatch.WriteStateFile(filepath.Join(dir, snapAddedFile), []byte(a.out)); err == nil {
			snap.Added = parseShowAdded(a.out)
			if snap.Added == nil {
				snap.Added = [][]string{}
			}
		}
	}
	return snap, nil
}

func (b *ufwBackend) Hash(context.Context) (string, error) {
	files, err := readRuleFiles(b.dir)
	if err != nil {
		return "", err
	}
	return hashRuleFiles(files), nil
}

// traceCmd is a traced command as a user would type it: "ufw show added".
func traceCmd(t *cmdTrace) string {
	if len(t.argv) == 0 {
		return ""
	}
	return strings.Join(append([]string{filepath.Base(t.argv[0])}, t.argv[1:]...), " ")
}

// errFwCmd is a failed firewall command, with its own output for display.
type errFwCmd struct{ t *cmdTrace }

func (e errFwCmd) Error() string {
	return strings.Join(e.t.argv, " ") + ": " + detail(e.t.out, e.t.err)
}

// Apply reloads after the changes.
func (b *ufwBackend) Apply(ctx context.Context, p fwPlan) (*cmdTrace, error) {
	for _, c := range p {
		if t := b.ufw(ctx, c.argv()...); t.err != nil {
			return t, errFwCmd{t}
		}
	}
	// Rule edits alone do not reliably reach the live tables on all
	// setups (observed in the field).
	t := b.ufw(ctx, "reload")
	if t.err != nil {
		return t, errFwCmd{t}
	}
	return t, nil
}

// Revert reloads after the changes.
func (b *ufwBackend) Revert(ctx context.Context, p fwPlan) error {
	for _, c := range p.inverse() {
		// Deleting a rule someone already removed, or adding one that
		// is back, is not an error worth stopping for.
		b.ufw(ctx, c.argv()...)
	}
	if t := b.ufw(ctx, "reload"); t.err != nil {
		return errFwCmd{t}
	}
	return nil
}

// Commit is a no-op: ufw rule changes are already persistent.
func (b *ufwBackend) Commit(context.Context, fwPlan) error { return nil }

// Restore writes the snapshot's files back and reloads.
func (b *ufwBackend) Restore(ctx context.Context, s fwSnap) error {
	for _, name := range ufwRuleFiles {
		data, ok := s.Files[name]
		if !ok {
			continue
		}
		if err := sshwatch.WriteStateFile(filepath.Join(b.dir, name), data); err != nil {
			return err
		}
	}
	if t := b.ufw(ctx, "reload"); t.err != nil {
		return errFwCmd{t}
	}
	return nil
}

// parseShowAdded reads `ufw show added`: one "ufw <rule>" line per rule.
// Route rules are left out; they never decide incoming SSH.
func parseShowAdded(out string) [][]string {
	var specs [][]string
	for _, line := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "ufw ")
		if !ok {
			continue
		}
		spec := splitQuoted(rest)
		if len(spec) == 0 || spec[0] == "route" {
			continue
		}
		specs = append(specs, spec)
	}
	return specs
}

// splitQuoted splits on spaces, keeping single- or double-quoted runs
// (an app profile like 'Nginx Full', a comment) as one argument.
func splitQuoted(s string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	inWord := false
	for _, r := range s {
		switch {
		case quote != 0 && r == quote:
			quote = 0
		case quote != 0:
			cur.WriteRune(r)
		case r == '\'' || r == '"':
			quote, inWord = r, true
		case r == ' ' || r == '\t':
			if inWord {
				out = append(out, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		out = append(out, cur.String())
	}
	return out
}

// ruleSpec is the part of a ufw rule spec the SSH plan cares about.
type ruleSpec struct {
	action string // allow|deny|reject|limit
	port   string // "22", "22/tcp", "80,443/tcp"; empty for an app or any
	app    string
	// plain: incoming, from and to anywhere, on every interface.
	plain bool
}

// parseRuleSpec reads a spec in ufw's simple ("allow 22/tcp", "limit
// OpenSSH") or extended ("allow from any to any port 22 proto tcp")
// syntax. Logging and comments do not change what a rule matches.
func parseRuleSpec(spec []string) (ruleSpec, bool) {
	var words []string
	for i := 0; i < len(spec); i++ {
		switch w := spec[i]; w {
		case "log", "log-all":
		case "comment":
			i++ // and its text
		default:
			words = append(words, w)
		}
	}
	if len(words) < 2 {
		return ruleSpec{}, false
	}
	r := ruleSpec{action: words[0], plain: true}
	switch r.action {
	case "allow", "deny", "reject", "limit":
	default:
		return ruleSpec{}, false
	}
	words = words[1:]
	switch words[0] {
	case "in":
		words = words[1:]
	case "out":
		return ruleSpec{}, false
	}
	if len(words) == 1 && words[0] != "from" && words[0] != "to" {
		var probe fwRule
		if parsePortSpec(&probe, words[0]) {
			r.port = words[0]
		} else {
			r.app = words[0]
		}
		return r, true
	}
	var proto string
	for i := 0; i+1 < len(words); i += 2 {
		k, v := words[i], words[i+1]
		switch k {
		case "from", "to":
			r.plain = r.plain && v == "any"
		case "port":
			r.port = v
		case "proto":
			proto = v
		case "app":
			r.app = v
		default: // "on eth0", source ports and the like
			r.plain = false
		}
	}
	if len(words)%2 != 0 {
		return ruleSpec{}, false
	}
	if proto != "" && r.port != "" {
		r.port += "/" + proto
	}
	return r, true
}

// sshOnly reports whether the rule is about the SSH port and nothing
// else: port 22 alone (TCP or any protocol), or an app profile whose
// ports, as `status verbose` expands them, are exactly 22. Deleting
// anything wider would change other ports too.
func (r ruleSpec) sshOnly(st ufwStatus) bool {
	if !r.plain {
		return false
	}
	if r.app != "" {
		seen := false
		for _, row := range st.rules {
			if row.App != r.app {
				continue
			}
			if row.unresolved || len(row.Ports) != 1 || row.Ports[0] != (portRange{22, 22}) || row.Proto == "udp" {
				return false
			}
			seen = true
		}
		return seen
	}
	return r.port == "22" || r.port == "22/tcp"
}

// matchesRow reports whether a status row is one of the rules spec r
// added (one per address family).
func (r ruleSpec) matchesRow(row fwRule) bool {
	if row.Action != r.action || row.Dir != "in" || row.From.IsValid() || row.Dst.IsValid() ||
		row.Iface != "" || row.partial {
		return false
	}
	if r.app != "" {
		return row.App == r.app
	}
	var probe fwRule
	if row.App != "" || !parsePortSpec(&probe, r.port) {
		return false
	}
	return probe.Proto == row.Proto && slices.Equal(probe.Ports, row.Ports)
}

// sshPortPlan is the corrected write path for port 22 (§5.1 item 3): the
// new rule goes in at position 1, so nothing listed earlier can match
// first, and every rule about port 22 alone that says the opposite is
// deleted by spec. An existing copy of the new rule is deleted too, or
// ufw would skip the insert and leave it where it was. ufw refuses
// `insert 1` into an empty IPv4 list, so then the rule is added instead.
func sshPortPlan(added [][]string, st ufwStatus, open bool) fwPlan {
	want, against := "deny", []string{"allow", "limit"}
	if open {
		want, against = "allow", []string{"deny", "reject"}
	}
	target := []string{want, sshPort}
	var plan fwPlan
	var gone []ruleSpec
	for _, spec := range added {
		r, ok := parseRuleSpec(spec)
		if !ok || !r.sshOnly(st) {
			continue
		}
		same := r.action == want && r.app == "" && r.port == sshPort
		if same || slices.Contains(against, r.action) {
			plan = append(plan, fwChange{Op: opDelete, Spec: spec})
			gone = append(gone, r)
		}
	}
	left := 0
	for _, row := range st.rules {
		if !row.V6 && !slices.ContainsFunc(gone, func(r ruleSpec) bool { return r.matchesRow(row) }) {
			left++
		}
	}
	op := opInsert
	if left == 0 {
		op = opAdd
	}
	return append(plan, fwChange{Op: op, Spec: target})
}
