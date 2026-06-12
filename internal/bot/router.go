// Package bot routes incoming Telegram commands to handlers and formats
// agent state into HTML messages. The router enforces the single-chat
// allowlist (MVP §7): commands from any other chat are dropped.
package bot

import (
	"context"
	"strings"

	"github.com/eliau2005/statixagent/internal/telegram"
)

// Handler answers one command. args holds the words after the command
// ("/ssh history" → ["history"]). The returned string is HTML.
type Handler func(ctx context.Context, args []string) string

// Router dispatches commands for exactly one allowed chat.
type Router struct {
	allowedChat int64
	handlers    map[string]Handler
}

// NewRouter returns a router that only accepts the given chat ID.
func NewRouter(allowedChat int64) *Router {
	return &Router{allowedChat: allowedChat, handlers: map[string]Handler{}}
}

// Handle registers a command (without the leading slash).
func (r *Router) Handle(cmd string, h Handler) {
	r.handlers[cmd] = h
}

// Dispatch processes one text update. It returns the reply, the resolved
// command name (for keyboard selection), and true; or ("", "", false) when
// the update should be ignored (wrong chat, not a command). Unknown
// commands from the allowed chat get a help pointer.
func (r *Router) Dispatch(ctx context.Context, u telegram.Update) (string, string, bool) {
	if u.ChatID != r.allowedChat || !strings.HasPrefix(u.Text, "/") {
		return "", "", false
	}
	fields := strings.Fields(u.Text)
	cmd := strings.TrimPrefix(fields[0], "/")
	// "/status@my_bot" form used in groups
	cmd, _, _ = strings.Cut(cmd, "@")
	cmd = strings.ToLower(cmd)
	reply, ok := r.Invoke(ctx, cmd, fields[1:])
	if !ok {
		return "Unknown command. Try /help", cmd, true
	}
	return reply, cmd, true
}

// Invoke runs a command handler directly (used for keyboard callbacks,
// which carry the command in callback data). It does NOT check the chat
// allowlist — the caller must.
func (r *Router) Invoke(ctx context.Context, cmd string, args []string) (string, bool) {
	h, ok := r.handlers[cmd]
	if !ok {
		return "", false
	}
	return h(ctx, args), true
}

// Commands returns the registered command names, for /help.
func (r *Router) Commands() []string {
	out := make([]string, 0, len(r.handlers))
	for c := range r.handlers {
		out = append(out, c)
	}
	return out
}
