package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/sshwatch"
	"github.com/eliau2005/statixagent/internal/telegram"
)

// Replay safety. Telegram drops an update only once a later getUpdates
// confirms it, so a process restart would hand the last batch back and
// run its actions twice. The cursor is therefore saved to disk before any
// update that may change state, and text commands that were queued while
// the agent was down only run if they are views.

// queuedGrace is how far before boot a command may have been sent and
// still count as live rather than queued while the agent was down.
const queuedGrace = 30 * time.Second

// offsetMaxAge bounds how old a saved offset may be and still be used.
// Telegram keeps pending updates for 24 hours, so an older offset protects
// nothing; and after a week without updates their IDs restart at random,
// where a stale higher offset would silently confirm (drop) new commands.
const offsetMaxAge = 24 * time.Hour

// viewCommands are the text commands that only read state. Anything not
// listed, including unknown commands, is treated as Config or Mutate.
// Commands whose arguments can change state are checked in isView.
var viewCommands = map[string]bool{
	"start": true, "help": true, "status": true, "cpu": true, "mem": true,
	"top": true, "digest": true, "disk": true, "net": true, "temp": true,
	"battery": true, "services": true, "docker": true, "ssh": true,
	"ping": true, "ssh_history": true, "ssh_fails": true, "trusted": true,
	"watching": true, "settings": true, "firewall": true, "metrics": true, "security": true,
	"services_scan": true, "ports_scan": true,
}

// isView reports whether a text command only reads state. /ssl, /http and
// /update are views bare but add, remove or install with arguments.
func isView(cmd string, args []string) bool {
	switch cmd {
	case "ssl", "http", "update":
		return len(args) == 0
	}
	return viewCommands[cmd]
}

// handleUpdate runs one update after botLoop has advanced the cursor past
// it. Callback data is not classified: any press may change state, so the
// cursor is saved first.
func (a *Agent) handleUpdate(ctx context.Context, u telegram.Update) {
	if u.Callback != nil {
		a.commitOffset(ctx)
		a.handleCallback(ctx, u.Callback)
		return
	}
	cmd, args, ok := bot.Parse(u.Text)
	if !ok {
		return // not a command; Dispatch would ignore it too
	}
	view := isView(cmd, args)
	s := sender{
		chatID:   u.ChatID,
		fromID:   u.FromID,
		chatType: u.ChatType,
		relayed:  u.Forwarded || u.ViaBot || u.SenderChat,
	}
	switch a.authorize(ctx, s, view) {
	case ignored:
		return
	case adminOnly:
		a.push(ctx, fmt.Sprintf("⛔ Only the users in <code>telegram.admin_user_ids</code> can run <code>/%s</code> here.", esc(cmd)))
		return
	}
	if !view {
		if a.queued(u) {
			a.push(ctx, fmt.Sprintf("⏸ <code>/%s</code> was sent while the agent was offline and was not run. Send it again if you still want it.", esc(cmd)))
			return
		}
		a.commitOffset(ctx)
	}
	// A confirm the command asks for is bound to its sender.
	if reply, cmd, ok := a.router.Dispatch(withActor(ctx, u.FromID), u); ok {
		a.reply(ctx, cmd, reply)
	}
}

// queued reports whether a text message was sent well before this boot,
// i.e. it waited in Telegram's queue while the agent was down.
func (a *Agent) queued(u telegram.Update) bool {
	return !u.Date.IsZero() && u.Date.Before(a.boot.Add(-queuedGrace))
}

// commitOffset makes the current cursor survive a restart before a
// state-changing update runs. When it cannot be saved to disk, Telegram
// is asked to confirm it instead (a zero-timeout getUpdates); updates that
// call returns are fetched again by the next poll.
func (a *Agent) commitOffset(ctx context.Context) {
	if a.src.OffsetPath != "" {
		err := sshwatch.WriteStateFile(a.src.OffsetPath, []byte(strconv.FormatInt(a.offset, 10)+"\n"))
		if err == nil {
			return
		}
		log.Printf("agent: saving update offset: %v", err)
	}
	if _, err := a.updates.GetUpdates(ctx, a.offset, 0); err != nil {
		log.Printf("agent: confirming update offset: %v", err)
	}
}

// loadOffset reads the cursor saved by commitOffset. A missing, stale or
// unreadable file yields 0, which starts from whatever Telegram still
// holds; a corrupt one is logged.
func loadOffset(path string) int64 {
	if path == "" {
		return 0
	}
	fi, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0
	}
	if err != nil {
		log.Printf("agent: update offset: %v", err)
		return 0
	}
	if time.Since(fi.ModTime()) > offsetMaxAge {
		return 0
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("agent: update offset: %v", err)
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || n < 0 {
		log.Printf("agent: update offset: ignoring corrupt %s", path)
		return 0
	}
	return n
}
