package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/sshwatch"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// Dead-man switch for firewall changes (docs/telegram-ux-redesign.md
// §5.4). Anything other than an explicit Keep rolls back, through three
// independent layers:
//
//  1. a transient systemd timer, outside the agent's cgroup, that runs
//     `statix-agent --fw-rollback <id>` at the deadline; it survives a
//     crash, a hang or a restart of the agent;
//  2. an in-process timer, for hosts without systemd-run;
//  3. reconciliation at startup, which covers a reboot.
//
// The trial lives on disk in <FwDir>/current.json, next to a byte-for-byte
// snapshot of the rule files in <FwDir>/<id>/. Rollback is idempotent: the
// hash of the rule files says whether it already happened.

// Trial button actions, as the audit log records them.
const (
	actFwKeep     = "fw_keep"
	actFwRollback = "fw_rollback"
)

const (
	fwCurrentFile = "current.json"
	fwLockFile    = ".lock"
	// fwSnapKeep is how long a finished trial's snapshot is kept, past
	// the newest fwKeepSnaps, which are kept whatever their age.
	fwSnapKeep  = 24 * time.Hour
	fwKeepSnaps = 5
	// fwTickEvery spaces countdown edits.
	fwTickEvery = 10 * time.Second
	// fwNoTimerCap caps the trial when systemd-run is unavailable: only
	// the agent itself can roll back then.
	fwNoTimerCap = 60 * time.Second
	// fwLayer2Grace lets the systemd timer go first.
	fwLayer2Grace = 5 * time.Second
	// fwRollbackTimeout bounds one rollback run.
	fwRollbackTimeout = 2 * time.Minute
)

// fwIDPattern is a trial ID; anything else never reaches a path.
var fwIDPattern = regexp.MustCompile(`^[0-9a-f]{8}$`)

// fwTrialRecord is current.json: everything a rollback needs, in this
// process or another one.
type fwTrialRecord struct {
	ID       string    `json:"id"`
	Backend  string    `json:"backend"`
	Bin      string    `json:"bin,omitempty"`
	Action   string    `json:"action"`
	Deadline time.Time `json:"deadline"`
	PreSHA   string    `json:"pre_sha"`
	// PostSHA is empty until the plan was applied: a rollback then
	// restores the snapshot, since any change is the plan's own.
	PostSHA string `json:"post_sha"`
	ChatID  int64  `json:"chat_id"`
	MsgID   int64  `json:"msg_id"`
	ActorID int64  `json:"actor_id"`
	Plan    fwPlan `json:"plan"`
	// What says what the trial did ("2 rule changes"); empty in records
	// of older versions, which only opened or closed port 22.
	What string `json:"what,omitempty"`
	// Layer1 records that the systemd timer was armed.
	Layer1 bool `json:"layer1"`
	// Evidence: Keep needs a new SSH connection seen after the change
	// (Decisions 4 and 15); Baseline is the connections there before.
	Evidence bool     `json:"evidence,omitempty"`
	Baseline []string `json:"baseline,omitempty"`
}

// fwLive is this process's handle on the pending trial. Guarded by fwMu.
type fwLive struct {
	id       string
	kb       telegram.Keyboard // Keep and Roll back, for countdown edits
	nonces   []string
	stop2    func() bool // layer 2
	stopTick func() bool // the next countdown edit
}

// fwOutcome is how a rollback went, for the chat.
type fwOutcome struct {
	ok   bool
	text string // HTML
}

// fwReady reports whether trials can run: a state directory and the ufw
// rules directory are both configured.
func (a *Agent) fwReady() bool {
	return a.src.FwDir != "" && a.src.UFWDir != "" && a.src.Runner != nil
}

func (a *Agent) fwBackend(bin string) *ufwBackend {
	return &ufwBackend{run: a.src.Runner, dir: a.src.UFWDir, bin: bin}
}

// trialWindow is N, the configured trial length.
func (a *Agent) trialWindow() time.Duration {
	n := a.cfg.Firewall.TrialSeconds
	if n == 0 {
		n = config.DefaultTrialSeconds
	}
	n = min(max(n, config.MinTrialSeconds), config.MaxTrialSeconds)
	return time.Duration(n) * time.Second
}

// lockFw serializes trial state changes in this process and across
// processes. Never call it with the lock held.
func (a *Agent) lockFw() (func(), error) {
	a.fwMu.Lock()
	if err := os.MkdirAll(a.src.FwDir, 0o700); err != nil {
		a.fwMu.Unlock()
		return nil, err
	}
	unlock, err := lockFile(filepath.Join(a.src.FwDir, fwLockFile))
	if err != nil {
		a.fwMu.Unlock()
		return nil, err
	}
	return func() { unlock(); a.fwMu.Unlock() }, nil
}

// loadTrial reads current.json; ok is false when no trial is pending.
func loadTrial(dir string) (rec fwTrialRecord, ok bool, err error) {
	data, err := os.ReadFile(filepath.Join(dir, fwCurrentFile))
	if errors.Is(err, fs.ErrNotExist) {
		return rec, false, nil
	}
	if err != nil {
		return rec, false, err
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return rec, false, fmt.Errorf("%s: %w", fwCurrentFile, err)
	}
	if !fwIDPattern.MatchString(rec.ID) {
		return rec, false, fmt.Errorf("%s: invalid trial id", fwCurrentFile)
	}
	return rec, true, nil
}

// saveTrial writes current.json atomically and durably.
func saveTrial(dir string, rec fwTrialRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return sshwatch.WriteStateFile(filepath.Join(dir, fwCurrentFile), data)
}

func removeTrial(dir string) error {
	err := os.Remove(filepath.Join(dir, fwCurrentFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// FwTrialPending reports whether a firewall trial is waiting for Keep or
// rollback. Self-update is refused meanwhile: a restart into a new binary
// must not race the rollback. An unreadable state counts as pending.
func (a *Agent) FwTrialPending() bool {
	if a.src.FwDir == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(a.src.FwDir, fwCurrentFile))
	return !errors.Is(err, fs.ErrNotExist)
}

// trialPendingText answers an update while a trial is pending.
const trialPendingText = "⏳ A firewall change is on trial. Keep it or roll it back before updating the agent."

func newFwID() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// fwStep marks the end of one apply step; tests crash the agent there.
func (a *Agent) fwStep(step string) {
	if a.fwCrash != nil {
		a.fwCrash(step)
	}
}

type intentKey struct{}

// withIntent tags ctx with the confirm press a run comes from, so an
// action can bind follow-up buttons to the same user and message.
func withIntent(ctx context.Context, in tgui.Intent) context.Context {
	return context.WithValue(ctx, intentKey{}, in)
}

func intentFrom(ctx context.Context) tgui.Intent {
	in, _ := ctx.Value(intentKey{}).(tgui.Intent)
	return in
}

// fwBackKB is the keyboard of a finished trial.
func fwBackKB() telegram.Keyboard {
	return telegram.Keyboard{{{Text: "🛡 Firewall", Data: callData(tgui.Open(scrFirewall))}}}
}

// layer1Argv is the systemd-run command that arms the rollback timer.
// Its CLI contract (--config, --fw-rollback) stays stable across versions.
func layer1Argv(self, cfgPath, id string, n time.Duration) []string {
	return []string{"systemd-run",
		"--unit=statix-fw-rollback-" + id,
		fmt.Sprintf("--on-active=%ds", int((n+time.Second-1)/time.Second)),
		"--timer-property=AccuracySec=1s",
		"--property=Type=oneshot",
		self, "--config", cfgPath, "--fw-rollback", id}
}

// armLayer1 starts the systemd rollback timer; false when it cannot.
func (a *Agent) armLayer1(ctx context.Context, id string, n time.Duration) bool {
	if a.src.SelfPath == "" || a.src.ConfigPath == "" {
		return false
	}
	argv := layer1Argv(a.src.SelfPath, a.src.ConfigPath, id, n)
	if out, err := a.src.Runner.Run(ctx, argv[0], argv[1:]...); err != nil {
		log.Printf("agent: firewall trial %s: systemd-run unavailable: %s", id, detail(out, err))
		return false
	}
	return true
}

// stopLayer1 cancels the systemd timer. Failure is harmless: a rollback
// run with no pending trial does nothing.
func (a *Agent) stopLayer1(ctx context.Context, rec fwTrialRecord) {
	if !rec.Layer1 {
		return
	}
	if out, err := a.src.Runner.Run(ctx, "systemctl", "stop", "statix-fw-rollback-"+rec.ID+".timer"); err != nil {
		log.Printf("agent: firewall trial %s: stopping the rollback timer: %s", rec.ID, detail(out, err))
	}
}

// runFirewallTrial opens or closes port 22 under the dead-man switch. It
// runs from a confirmed press (confirmPress puts the press in ctx).
func (a *Agent) runFirewallTrial(ctx context.Context, open bool) actionResult {
	if !open && !a.cfg.Firewall.AllowCloseSSH {
		return actionResult{refused: true, driftToast: "Closing SSH is turned off", text: closeSSHOff, kb: fwBackKB()}
	}
	job := fwJob{action: actFwClose, target: "port " + sshPort, what: "port 22 closed", evidence: !open,
		prepare: func(ctx context.Context, b *ufwBackend, p ufwProbe) fwPrep {
			added, t := b.added(ctx)
			if t != nil {
				return fwPrep{fail: &fwFailure{cmd: "ufw show added", out: t.out, err: t.err}, trace: t}
			}
			return fwPrep{plan: sshPortPlan(added, p.fw, open)}
		},
		// ufw exiting 0 does not mean the port changed; only a fresh
		// reading decides.
		verify: func(_ context.Context, _, after ufwProbe) *fwFailure { return verifySSHPort(after, open) },
	}
	if open {
		job.action, job.what = actFwOpen, "port 22 opened"
	}
	return a.runTrial(ctx, job)
}

// fwJob is one firewall change to run under the dead-man switch.
type fwJob struct {
	action string // the trial's action, as the audit log records it
	target string // receipt and audit target, plain text
	what   string // what the trial did, for the countdown: "port 22 closed"
	// evidence: Keep needs a new SSH connection seen after the change.
	evidence bool
	// prepare builds the plan from a fresh reading, under the trial lock;
	// it may refuse instead (nothing has changed yet).
	prepare func(ctx context.Context, b *ufwBackend, p ufwProbe) fwPrep
	// apply, when set, makes the change instead of applying the plan (a
	// snapshot restore); the plan is then only what undoes it by spec.
	apply func(ctx context.Context, b *ufwBackend) (*cmdTrace, error)
	// verify checks a fresh reading after the change; a failure rolls
	// it back at once.
	verify func(ctx context.Context, before, after ufwProbe) *fwFailure
}

// fwPrep is what a job's prepare decided.
type fwPrep struct {
	plan    fwPlan
	refused *actionResult // shown as it is; nothing ran
	fail    *fwFailure
	trace   *cmdTrace
}

// runTrial runs job under the dead-man switch: snapshot, record, arm the
// systemd timer, apply, verify, then layer 2 and the countdown. It runs
// from a confirmed press (confirmPress puts the press in ctx).
func (a *Agent) runTrial(ctx context.Context, job fwJob) actionResult {
	res := actionResult{target: job.target}
	fail := func(f *fwFailure, trace *cmdTrace, extra string) actionResult {
		text, kb := a.firewallView(ctx)
		banner := "❌ <b>Change failed</b>\n<pre>" + esc(f.display()) + "</pre>\n"
		if hint := sandboxHint(f); hint != "" {
			banner += hint + "\n"
		}
		res.what, res.trace = "Firewall change failed", trace
		res.text, res.kb = banner+extra+text, kb
		return res
	}
	if a.src.Runner == nil {
		return fail(&fwFailure{reason: "firewall control unavailable in this build"}, nil, "")
	}
	if !a.fwReady() {
		return fail(&fwFailure{reason: "the firewall rollback switch is not set up in this build, so the agent will not change rules"}, nil, "")
	}
	unlock, err := a.lockFw()
	if err != nil {
		return fail(&fwFailure{reason: "could not lock the firewall trial state: " + err.Error()}, nil, "")
	}
	defer unlock()
	if _, pending, err := loadTrial(a.src.FwDir); pending || err != nil {
		return fail(&fwFailure{reason: "another firewall change is on trial; Keep it or roll it back first"}, nil, "")
	}
	a.pruneSnapshots("")

	b := a.fwBackend("")
	p := b.Probe(ctx)
	if f := probeRefusal(p); f != nil {
		return fail(f, nil, "")
	}
	prep := job.prepare(ctx, b, p)
	switch {
	case prep.refused != nil:
		return *prep.refused
	case prep.fail != nil:
		return fail(prep.fail, prep.trace, "")
	}
	plan := prep.plan

	// 1. Snapshot. Nothing may change unless steps 1-3 succeed.
	id, err := newFwID()
	if err != nil {
		return fail(&fwFailure{reason: "could not start a trial: " + err.Error()}, nil, "")
	}
	snapDir := filepath.Join(a.src.FwDir, id)
	snap, err := b.Snapshot(ctx, snapDir)
	if err != nil {
		os.RemoveAll(snapDir)
		return fail(&fwFailure{reason: "could not snapshot the current rules, so nothing was changed: " + err.Error()}, nil, "")
	}
	a.fwStep("snapshot")

	// 2. Record the trial.
	in := intentFrom(ctx)
	n := a.trialWindow()
	start := a.now()
	rec := fwTrialRecord{ID: id, Backend: b.Name(), Bin: b.bin, Action: job.action, What: job.what, Deadline: start.Add(n),
		PreSHA: snap.SHA, ChatID: in.ChatID, MsgID: in.MessageID, ActorID: in.ActorID, Plan: plan, Evidence: job.evidence}
	if err := saveTrial(a.src.FwDir, rec); err != nil {
		os.RemoveAll(snapDir)
		return fail(&fwFailure{reason: "could not record the trial, so nothing was changed: " + err.Error()}, nil, "")
	}
	a.fwStep("record")

	// 3. Layer 1. Without it only this process can roll back, so the
	// window shrinks.
	rec.Layer1 = a.armLayer1(ctx, id, n)
	if !rec.Layer1 && n > fwNoTimerCap {
		rec.Deadline = start.Add(fwNoTimerCap)
	}
	if rec.Evidence {
		rec.Baseline = connKeys(a.sshConns(ctx, a.sshPorts(ctx)))
	}
	if err := saveTrial(a.src.FwDir, rec); err != nil {
		a.stopLayer1(ctx, rec)
		removeTrial(a.src.FwDir)
		return fail(&fwFailure{reason: "could not record the trial, so nothing was changed: " + err.Error()}, nil, "")
	}
	a.fwStep("layer1")

	// 4. Apply, and record what the rules look like now.
	var trace *cmdTrace
	var applyErr error
	if job.apply != nil {
		trace, applyErr = job.apply(ctx, b)
	} else {
		trace, applyErr = b.Apply(ctx, plan)
	}
	a.fwStep("apply")
	if post, err := b.Hash(); err == nil {
		rec.PostSHA = post
		if err := saveTrial(a.src.FwDir, rec); err != nil {
			log.Printf("agent: firewall trial %s: %v", id, err) // an empty post_sha restores the snapshot
		}
	}
	a.fwStep("post")
	if applyErr != nil {
		out := a.rollbackLocked(ctx, rec)
		f := &fwFailure{reason: applyErr.Error()}
		var ue errUFW
		if errors.As(applyErr, &ue) {
			f = &fwFailure{cmd: "ufw " + strings.Join(ue.t.argv[1:], " "), out: ue.t.out, err: ue.t.err}
		}
		return fail(f, trace, out.text+"\n")
	}
	// A mismatch with what was intended is rolled back at once.
	if f := job.verify(ctx, p, b.Probe(ctx)); f != nil {
		out := a.rollbackLocked(ctx, rec)
		return fail(f, trace, out.text+"\n")
	}

	// 5. Layer 2 and the countdown.
	live := a.armTrial(rec)
	res.ok, res.trace = true, trace
	res.what = upperFirst(job.what) + " · on trial"
	res.text, res.kb = a.countdownText(rec), live.kb
	res.rebind = func(msgID int64) { a.rebindTrial(id, msgID) }
	return res
}

// upperFirst capitalizes the first letter of s.
func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// armTrial starts layer 2 and the countdown for rec, with fresh Keep and
// Roll back buttons. fwMu is held.
func (a *Agent) armTrial(rec fwTrialRecord) *fwLive {
	a.stopTrialTimers("")
	live := &fwLive{id: rec.ID}
	live.kb, live.nonces = a.mintTrialKB(rec)
	at := rec.Deadline
	if rec.Layer1 {
		at = at.Add(fwLayer2Grace)
	}
	live.stop2 = a.fwAfter(max(at.Sub(a.now()), 0), func() { a.autoRollback(rec.ID) })
	live.stopTick = a.fwAfter(fwTickEvery, func() { a.countdownTick(rec.ID) })
	a.fwTrial = live
	return live
}

// stopTrialTimers stops the in-process timers of trial id, or of any
// trial when id is empty. fwMu is held.
func (a *Agent) stopTrialTimers(id string) {
	live := a.fwTrial
	if live == nil || (id != "" && live.id != id) {
		return
	}
	if live.stop2 != nil {
		live.stop2()
	}
	if live.stopTick != nil {
		live.stopTick()
	}
	a.fwTrial = nil
}

// mintTrialKB mints the Keep and Roll back buttons of a trial. They are
// confirm tokens bound to the user who asked and the trial's message,
// valid until shortly after the deadline. A failure leaves no buttons;
// the trial still rolls back on its own.
func (a *Agent) mintTrialKB(rec fwTrialRecord) (telegram.Keyboard, []string) {
	ttl := rec.Deadline.Sub(a.now()) + time.Minute
	var kb telegram.Keyboard
	var nonces []string
	for _, b := range []struct{ act, label string }{
		{actFwKeep, "✅ Keep (new SSH works)"},
		{actFwRollback, "↩️ Roll back now"},
	} {
		in := tgui.Intent{Action: b.act, Target: rec.ID, ActorID: rec.ActorID, ChatID: rec.ChatID, MessageID: rec.MsgID}
		nonce, err := a.tokens.MintTTL(in, ttl)
		if err != nil {
			log.Printf("agent: firewall trial %s: %v", rec.ID, err)
			return nil, nil
		}
		data, err := tgui.Encode(a.tokens.Yes(nonce))
		if err != nil {
			log.Printf("agent: firewall trial %s: %v", rec.ID, err)
			return nil, nil
		}
		kb = append(kb, []telegram.Button{{Text: b.label, Data: data}})
		nonces = append(nonces, nonce)
	}
	return kb, nonces
}

// rebindTrial moves a trial to the message its countdown ended up in.
func (a *Agent) rebindTrial(id string, msgID int64) {
	unlock, err := a.lockFw()
	if err != nil {
		return
	}
	defer unlock()
	rec, ok, _ := loadTrial(a.src.FwDir)
	if !ok || rec.ID != id {
		return
	}
	rec.MsgID = msgID
	if err := saveTrial(a.src.FwDir, rec); err != nil {
		log.Printf("agent: firewall trial %s: %v", id, err)
	}
	if live := a.fwTrial; live != nil && live.id == id {
		for _, n := range live.nonces {
			a.tokens.Rebind(n, msgID)
		}
	}
}

// countdownText is the trial message.
func (a *Agent) countdownText(rec fwTrialRecord) string {
	what := rec.What
	switch {
	case what != "":
	case rec.Action == actFwOpen:
		what = "port 22 opened"
	default:
		what = "port 22 closed"
	}
	s := "⏳ <b>Trial applied</b> · " + esc(what) + " · rollback in " + mmss(rec.Deadline.Sub(a.now())) + "\n" +
		"Open a <b>new</b> SSH session now.\n" +
		"If you do nothing or the bot goes offline, the old rules return at " +
		rec.Deadline.UTC().Format("15:04:05") + " UTC."
	if rec.Evidence {
		s += "\nKeep is allowed only once a new SSH connection is seen."
	}
	if !rec.Layer1 {
		s += "\n⚠️ systemd-run is unavailable: only the agent itself can roll back, so the trial is capped at 60 s."
	}
	return s
}

// mmss renders a duration as m:ss, never negative.
func mmss(d time.Duration) string {
	s := int(max(d, 0).Round(time.Second) / time.Second)
	return fmt.Sprintf("%d:%02d", s/60, s%60)
}

// countdownTick edits the countdown, at most every fwTickEvery, and
// stops on a 429 or once the trial is over. It holds the lock while it
// edits, so it can never overwrite an outcome.
func (a *Agent) countdownTick(id string) {
	unlock, err := a.lockFw()
	if err != nil {
		return
	}
	defer unlock()
	live := a.fwTrial
	if live == nil || live.id != id {
		return
	}
	rec, ok, _ := loadTrial(a.src.FwDir)
	if !ok || rec.ID != id || !a.now().Before(rec.Deadline) || a.send == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	err = a.send.EditMessageKB(ctx, rec.ChatID, rec.MsgID, a.countdownText(rec), live.kb)
	if _, is429 := telegram.RetryAfter(err); is429 {
		log.Printf("agent: firewall trial %s: countdown stopped: %v", id, err)
		return
	}
	live.stopTick = a.fwAfter(fwTickEvery, func() { a.countdownTick(id) })
}

// rollbackLocked takes trial rec back and ends it. fwMu is held. It is
// idempotent: the hash of the rule files tells what is left to do.
//   - pre_sha: nothing applied, or already rolled back: clean up only.
//   - post_sha, or no post_sha yet (the apply never finished, so any
//     change is the plan's own): restore the snapshot byte for byte.
//   - anything else: someone else edited the rules during the trial;
//     see revertForeign.
//
// current.json is removed last, and kept when the rollback failed, so a
// restart tries again.
func (a *Agent) rollbackLocked(ctx context.Context, rec fwTrialRecord) fwOutcome {
	b := a.fwBackend(rec.Bin)
	snap, err := loadSnap(filepath.Join(a.src.FwDir, rec.ID))
	if err != nil {
		return fwOutcome{text: "❌ <b>Rollback failed</b>: the snapshot could not be read: " + esc(err.Error())}
	}
	cur, herr := b.Hash()
	var out fwOutcome
	switch {
	case herr == nil && cur == rec.PreSHA:
		out = fwOutcome{ok: true, text: "↩️ <b>Rolled back</b> · the rules are as they were before the trial"}
	case herr == nil && rec.PostSHA != "" && cur != rec.PostSHA:
		out = a.revertForeign(ctx, b, rec, snap)
	default:
		if err := b.Restore(ctx, snap); err != nil {
			out = fwOutcome{text: "❌ <b>Rollback failed</b>\n<pre>" + esc(truncate(err.Error(), 300)) + "</pre>"}
		} else {
			out = fwOutcome{ok: true, text: "↩️ <b>Rolled back</b> at " + a.now().UTC().Format("15:04:05") + " UTC"}
		}
	}
	if !out.ok {
		return out
	}
	a.stopLayer1(ctx, rec)
	a.stopTrialTimers(rec.ID)
	if err := removeTrial(a.src.FwDir); err != nil {
		log.Printf("agent: firewall trial %s: %v", rec.ID, err)
	}
	return out
}

// revertForeign handles rules edited by someone else during the trial
// (fail2ban, a script, a human). A byte restore would clobber their
// change, so only the plan's own changes are undone, by spec. But if an
// SSH admin peer would still be blocked, lockout prevention wins: the
// snapshot is restored anyway, and the notice says so.
func (a *Agent) revertForeign(ctx context.Context, b FwBackend, rec fwTrialRecord, snap fwSnap) fwOutcome {
	err := b.Revert(ctx, rec.Plan)
	p := b.Probe(ctx)
	if why := a.lockoutRisk(ctx, p, snap, err); why != "" {
		if err := b.Restore(ctx, snap); err != nil {
			return fwOutcome{text: "❌ <b>Rollback failed</b>: " + esc(why) + ", and restoring the snapshot failed:\n<pre>" +
				esc(truncate(err.Error(), 300)) + "</pre>"}
		}
		return fwOutcome{ok: true, text: "↩️ <b>Rolled back from the snapshot</b>\n" +
			"⚠️ The rules were changed on the server during the trial. Undoing only the trial's own changes " +
			"left SSH at risk (" + esc(why) + "), so the snapshot was restored byte for byte and those changes were lost:\n" +
			ruleDiff(p.out, snap.Status) + "\nSnapshot " + rec.ID + " is kept for 24 h."}
	}
	return fwOutcome{ok: true, text: "↩️ <b>Rolled back the trial's own changes</b>\n" +
		"⚠️ The rules were changed on the server during the trial, so the snapshot was not restored; " +
		"those changes were kept. Differences from before the trial:\n" +
		ruleDiff(snap.Status, p.out) + "\nSnapshot " + rec.ID + " is kept for 24 h."}
}

// lockoutRisk re-runs the SSH guard on the state after a partial
// rollback: every established SSH peer must still be allowed in on its
// port, and an SSH port that was reachable before the trial must be
// again. It returns why not, or "".
func (a *Agent) lockoutRisk(ctx context.Context, p ufwProbe, snap fwSnap, revertErr error) string {
	if revertErr != nil {
		return "undoing the changes failed"
	}
	if !p.manageable() {
		return "the rules could not be read back"
	}
	ports := a.sshPorts(ctx)
	for _, c := range a.sshConns(ctx, ports) {
		peer := c.peer.Addr()
		if !reachable(p.fw.verdict(int(c.local.Port()), peer.Is6(), peer)) {
			return fmt.Sprintf("SSH port %d would block %s", c.local.Port(), peer)
		}
	}
	pre := parseUFWOutput(snap.Status)
	for _, port := range ports {
		for _, v6 := range []bool{false, true} {
			if v6 && !pre.hasV6() {
				continue
			}
			if reachable(pre.verdict(port, v6, netip.Addr{})) && !reachable(p.fw.verdict(port, v6, netip.Addr{})) {
				return fmt.Sprintf("SSH port %d would stay closed", port)
			}
		}
	}
	return ""
}

// reachable reports whether a verdict lets the connection in.
func reachable(v portVerdict) bool {
	return v.state == fwOpen || (v.state == fwUnmanaged && v.policy == "allow")
}

// ruleDiff renders the rows only in from as "−" and only in to as "+".
func ruleDiff(from, to string) string {
	rows := func(s string) []string {
		var out []string
		for _, r := range parseUFWOutput(s).rules {
			out = append(out, r.Raw)
		}
		return out
	}
	a, b := rows(from), rows(to)
	var lines []string
	for _, r := range a {
		if !slices.Contains(b, r) {
			lines = append(lines, "− "+r)
		}
	}
	for _, r := range b {
		if !slices.Contains(a, r) {
			lines = append(lines, "+ "+r)
		}
	}
	if len(lines) == 0 {
		return "<pre>(no rule differences)</pre>"
	}
	return "<pre>" + esc(truncate(strings.Join(lines, "\n"), 1500)) + "</pre>"
}

// sshConn is one established connection to an SSH port.
type sshConn struct{ local, peer netip.AddrPort }

func (c sshConn) key() string { return c.local.String() + ">" + c.peer.String() }

func connKeys(cs []sshConn) []string {
	keys := make([]string, 0, len(cs))
	for _, c := range cs {
		keys = append(keys, c.key())
	}
	return keys
}

// sshConns lists established connections to the SSH ports.
func (a *Agent) sshConns(ctx context.Context, ports []int) []sshConn {
	out, err := a.src.Runner.Run(ctx, "ss", "-Htn", "state", "established")
	if err != nil {
		return nil
	}
	return parseSSEstablished(out, ports)
}

// parseSSEstablished reads `ss -Htn state established`: the first two
// address:port columns are the local and the peer end.
func parseSSEstablished(out string, ports []int) []sshConn {
	var conns []sshConn
	for _, line := range strings.Split(out, "\n") {
		var eps []netip.AddrPort
		for _, f := range strings.Fields(line) {
			if ap, err := netip.ParseAddrPort(f); err == nil {
				eps = append(eps, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
			}
		}
		if len(eps) < 2 || !slices.Contains(ports, int(eps[0].Port())) {
			continue
		}
		conns = append(conns, sshConn{local: eps[0], peer: eps[1]})
	}
	return conns
}

// newSSHSeen reports whether an SSH connection exists that was not there
// when the change was applied: the evidence Keep needs.
func (a *Agent) newSSHSeen(ctx context.Context, rec fwTrialRecord) bool {
	for _, c := range a.sshConns(ctx, a.sshPorts(ctx)) {
		if !slices.Contains(rec.Baseline, c.key()) {
			return true
		}
	}
	return false
}

// trialGone is the answer to a Keep or Roll back press on a trial that
// already ended.
func trialGone() actionResult {
	return actionResult{drift: true, driftToast: "This trial has already ended",
		text: "⌛ This firewall trial has already ended.", kb: fwBackKB()}
}

// keepTrial is Keep: stop the timer, commit, end the trial.
func (a *Agent) keepTrial(ctx context.Context, id string) actionResult {
	if !a.fwReady() {
		return trialGone()
	}
	unlock, err := a.lockFw()
	if err != nil {
		return actionResult{target: "trial " + id, what: "Keep failed", text: "❌ " + esc(err.Error()), kb: fwBackKB()}
	}
	defer unlock()
	rec, ok, _ := loadTrial(a.src.FwDir)
	if !ok || rec.ID != id {
		return trialGone()
	}
	if rec.Evidence && !a.newSSHSeen(ctx, rec) {
		// The Keep token is spent; offer fresh buttons.
		var kb telegram.Keyboard
		if live := a.fwTrial; live != nil && live.id == id {
			live.kb, live.nonces = a.mintTrialKB(rec)
			kb = live.kb
		}
		return actionResult{refused: true, driftToast: "No new SSH connection seen yet",
			text: a.countdownText(rec) + "\n\n⚠️ <b>Not kept</b>: no new SSH connection has been seen since the change. " +
				"Open a new SSH session first, then tap Keep.", kb: kb}
	}
	a.stopLayer1(ctx, rec)
	if err := a.fwBackend(rec.Bin).Commit(ctx, rec.Plan); err != nil {
		return actionResult{target: "trial " + id, what: "Keep failed", text: "❌ " + esc(err.Error()), kb: fwBackKB()}
	}
	if err := removeTrial(a.src.FwDir); err != nil {
		return actionResult{target: "trial " + id, what: "Keep failed", text: "❌ " + esc(err.Error()), kb: fwBackKB()}
	}
	a.stopTrialTimers(id)
	return actionResult{ok: true, what: "Firewall change kept", target: "trial " + id,
		text: "✅ Kept · snapshot " + id + " kept 24h", kb: fwBackKB()}
}

// rollbackTrial is Roll back now.
func (a *Agent) rollbackTrial(ctx context.Context, id string) actionResult {
	if !a.fwReady() {
		return trialGone()
	}
	unlock, err := a.lockFw()
	if err != nil {
		return actionResult{target: "trial " + id, what: "Rollback failed", text: "❌ " + esc(err.Error()), kb: fwBackKB()}
	}
	defer unlock()
	rec, ok, _ := loadTrial(a.src.FwDir)
	if !ok || rec.ID != id {
		return trialGone()
	}
	out := a.rollbackLocked(ctx, rec)
	res := actionResult{ok: out.ok, what: "Firewall change rolled back", target: "trial " + id, text: out.text, kb: fwBackKB()}
	if !out.ok {
		res.what = "Rollback failed"
	}
	return res
}

// autoRollback is layer 2: the deadline passed without Keep.
func (a *Agent) autoRollback(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), fwRollbackTimeout)
	defer cancel()
	unlock, err := a.lockFw()
	if err != nil {
		log.Printf("agent: firewall trial %s: %v", id, err)
		return
	}
	defer unlock()
	rec, ok, err := loadTrial(a.src.FwDir)
	if err != nil || !ok || rec.ID != id {
		a.stopTrialTimers(id) // rolled back or kept elsewhere
		return
	}
	a.finishAuto(ctx, rec)
}

// finishAuto rolls back a trial nobody kept, audits it and tells the
// chat. fwMu is held.
func (a *Agent) finishAuto(ctx context.Context, rec fwTrialRecord) {
	start := a.now()
	out := a.rollbackLocked(ctx, rec)
	r := auditRecord{Phase: phaseExecuted, Action: actFwRollback, Target: "trial " + rec.ID,
		ChatID: rec.ChatID, MessageID: rec.MsgID, DurationMS: a.now().Sub(start).Milliseconds()}
	if !out.ok {
		r.Phase = phaseFailed
	}
	a.writeAudit(r)
	a.notifyTrial(ctx, rec, out.text)
}

// notifyTrial puts an outcome into the trial's message, or a new one.
func (a *Agent) notifyTrial(ctx context.Context, rec fwTrialRecord, text string) {
	if a.send == nil || rec.ChatID == 0 {
		return
	}
	if rec.MsgID != 0 {
		if err := a.send.EditMessageKB(ctx, rec.ChatID, rec.MsgID, text, fwBackKB()); err == nil {
			return
		}
	}
	if _, err := a.send.SendMessageKB(ctx, rec.ChatID, text, fwBackKB()); err != nil {
		log.Printf("agent: firewall trial %s: %v", rec.ID, err)
	}
}

// reconcileFwTrial is layer 3, run at startup before the bot answers
// anything: a trial whose deadline passed while the agent was down (a
// crash, a restart, a reboot) is rolled back now; one still running gets
// layer 2 again and its countdown back, with fresh buttons.
func (a *Agent) reconcileFwTrial(ctx context.Context) {
	if !a.fwReady() {
		return
	}
	unlock, err := a.lockFw()
	if err != nil {
		log.Printf("agent: firewall trial: %v", err)
		return
	}
	defer unlock()
	rec, ok, err := loadTrial(a.src.FwDir)
	if err != nil {
		log.Printf("agent: firewall trial: %v", err)
		return
	}
	a.pruneSnapshots(rec.ID)
	if !ok {
		return
	}
	if !a.now().Before(rec.Deadline) {
		a.finishAuto(ctx, rec)
		return
	}
	live := a.armTrial(rec)
	if a.send != nil && rec.ChatID != 0 && rec.MsgID != 0 {
		if err := a.send.EditMessageKB(ctx, rec.ChatID, rec.MsgID, a.countdownText(rec), live.kb); err != nil {
			log.Printf("agent: firewall trial %s: resuming countdown: %v", rec.ID, err)
		}
	}
}

// fwSnapInfo is one snapshot directory.
type fwSnapInfo struct {
	id string
	at time.Time // when it was taken
}

// listSnapshots lists the snapshot directories, newest first.
func (a *Agent) listSnapshots() []fwSnapInfo {
	entries, err := os.ReadDir(a.src.FwDir)
	if err != nil {
		return nil
	}
	var snaps []fwSnapInfo
	for _, e := range entries {
		if !e.IsDir() || !fwIDPattern.MatchString(e.Name()) {
			continue
		}
		if info, err := e.Info(); err == nil {
			snaps = append(snaps, fwSnapInfo{id: e.Name(), at: info.ModTime()})
		}
	}
	slices.SortStableFunc(snaps, func(x, y fwSnapInfo) int { return y.at.Compare(x.at) })
	return snaps
}

// pruneSnapshots removes trial snapshots older than fwSnapKeep, except
// the pending one and the newest fwKeepSnaps, which "↩️ Restore
// previous" offers. fwMu is held.
func (a *Agent) pruneSnapshots(keep string) {
	for i, s := range a.listSnapshots() {
		if s.id == keep || i < fwKeepSnaps {
			continue
		}
		if a.now().Sub(s.at) > fwSnapKeep {
			os.RemoveAll(filepath.Join(a.src.FwDir, s.id))
		}
	}
}

// RunFwRollback is `statix-agent --fw-rollback <id>`, run by the layer 1
// timer: roll trial id back if it is still pending, then tell the chat.
// send may be nil when the config could not be read; the rollback still
// runs.
func RunFwRollback(ctx context.Context, cfg config.Config, src Sources, send Sender, id string) error {
	if !fwIDPattern.MatchString(id) {
		return fmt.Errorf("invalid firewall trial id %q", id)
	}
	a := New(cfg, send, nil, src)
	if !a.fwReady() {
		return errors.New("firewall trial state is not configured")
	}
	unlock, err := a.lockFw()
	if err != nil {
		return err
	}
	defer unlock()
	rec, ok, err := loadTrial(a.src.FwDir)
	if err != nil {
		return err
	}
	if !ok || rec.ID != id {
		log.Printf("statix-agent: firewall trial %s already ended", id)
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, fwRollbackTimeout)
	defer cancel()
	a.finishAuto(ctx, rec)
	if _, still, _ := loadTrial(a.src.FwDir); still {
		return fmt.Errorf("firewall trial %s: rollback failed", id)
	}
	return nil
}
