package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/eliau2005/statixagent/internal/telegram"
)

// The audit log (docs/telegram-ux-redesign.md §6, Decision 7) records
// every step of every host-changing action as one JSON line, locally:
// /clear_chat can erase the Telegram history, so this file is the record
// of truth. It never holds a confirm token or nonce, only a hash of the
// nonce. A failure to write is logged and never blocks the action.

// Audit phases.
const (
	phaseRequested = "requested" // a confirm screen was shown
	phaseConfirmed = "confirmed" // its Yes won the token
	phaseDenied    = "denied"    // pressed by someone else, or already used
	phaseExpired   = "expired"   // pressed after the TTL
	phaseStale     = "stale"     // previous boot, unknown token, other message, or target drift
	phaseExecuted  = "executed"
	phaseFailed    = "failed"
	phaseCancelled = "cancelled"
)

const (
	auditMaxSize = 1 << 20 // rotate past 1 MiB
	auditKeep    = 5       // files kept, the live one included
	auditHead    = 512     // bytes of output kept
)

// auditRecord is one line of the audit log.
type auditRecord struct {
	TS        time.Time `json:"ts"`
	BootEpoch string    `json:"boot_epoch"`
	Phase     string    `json:"phase"`
	Action    string    `json:"action,omitempty"`
	Target    string    `json:"target,omitempty"`
	ActorID   int64     `json:"actor_id"`
	ChatID    int64     `json:"chat_id"`
	MessageID int64     `json:"message_id,omitempty"`
	// NonceHash identifies a token across phases without making it
	// replayable from the file.
	NonceHash    string   `json:"nonce_hash,omitempty"`
	Argv         []string `json:"argv,omitempty"`
	ExitCode     *int     `json:"exit_code,omitempty"`
	DurationMS   int64    `json:"duration_ms,omitempty"`
	OutputSHA256 string   `json:"output_sha256,omitempty"`
	OutputHead   string   `json:"output_head,omitempty"`
}

// nonceHash is the first 16 hex digits of the nonce's SHA-256.
func nonceHash(nonce string) string {
	if nonce == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(nonce))
	return hex.EncodeToString(sum[:8])
}

// cmdTrace is the command an action ran, for its audit record.
type cmdTrace struct {
	argv []string
	out  string
	err  error
	dur  time.Duration
}

// record fills r's command fields; redact cleans the kept output head.
func (c *cmdTrace) record(r *auditRecord, redact func(string) string) {
	if c == nil || len(c.argv) == 0 {
		return
	}
	r.Argv = c.argv
	var code int
	var ee *exec.ExitError
	switch {
	case c.err == nil:
	case errors.As(c.err, &ee):
		code = ee.ExitCode()
	default:
		code = -1 // did not run, or no exit status
	}
	r.ExitCode = &code
	r.DurationMS = c.dur.Milliseconds()
	sum := sha256.Sum256([]byte(c.out))
	r.OutputSHA256 = hex.EncodeToString(sum[:])
	head := c.out
	if len(head) > auditHead {
		head = head[:auditHead]
	}
	r.OutputHead = redact(strings.ToValidUTF8(head, ""))
}

// auditLog appends records to path, rotating it; nil writes nothing.
type auditLog struct {
	path string
	max  int64 // rotation size; auditMaxSize outside tests

	mu sync.Mutex
}

// newAuditLog returns the log at path, or nil when path is empty.
func newAuditLog(path string) *auditLog {
	if path == "" {
		return nil
	}
	return &auditLog{path: path, max: auditMaxSize}
}

// write appends r. Errors are logged: auditing never blocks an action.
func (l *auditLog) write(r auditRecord) {
	if l == nil {
		return
	}
	line, err := json.Marshal(r)
	if err != nil {
		log.Printf("agent: audit: %v", err)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.append(append(line, '\n')); err != nil {
		log.Printf("agent: audit: %v", err)
	}
}

func (l *auditLog) append(line []byte) error {
	dir := filepath.Dir(l.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// MkdirAll leaves an existing directory as it is.
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	if fi, err := os.Stat(l.path); err == nil && fi.Size()+int64(len(line)) > l.max {
		if err := l.rotate(); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(line); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// rotate shifts path.N to path.N+1, dropping the oldest, and path to
// path.1.
func (l *auditLog) rotate() error {
	name := func(i int) string { return fmt.Sprintf("%s.%d", l.path, i) }
	if err := os.Remove(name(auditKeep - 1)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for i := auditKeep - 2; i >= 1; i-- {
		if err := os.Rename(name(i), name(i+1)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return os.Rename(l.path, name(1))
}

// redactOutput removes the bot token from command output kept in the
// audit log, whether or not it appears in URL form.
func (a *Agent) redactOutput(s string) string {
	if tok := a.cfg.Telegram.Token; tok != "" {
		s = strings.ReplaceAll(s, tok, "<redacted>")
	}
	return telegram.Redact(s)
}

// writeAudit records r in the audit file and mirrors it to the log.
func (a *Agent) writeAudit(r auditRecord) {
	r.TS = a.now().UTC()
	r.BootEpoch = a.tokens.Epoch()
	log.Printf("audit: %s %s target=%q actor=%d", r.Phase, r.Action, r.Target, r.ActorID)
	a.audit.write(r)
}
