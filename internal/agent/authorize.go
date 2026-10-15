package agent

import (
	"context"
	"log"
	"slices"
)

// sender is who an update came from, as far as authorization needs.
type sender struct {
	chatID   int64
	fromID   int64
	chatType string
	// relayed is set for text that was forwarded, sent via an inline bot
	// or sent on behalf of a chat (anonymous admin, channel): its author
	// is not the user it appears to come from.
	relayed bool
}

// verdict is authorize's decision on one update.
type verdict int

const (
	allowed verdict = iota
	// ignored updates are dropped without any reply.
	ignored
	// adminOnly is a group member outside telegram.admin_user_ids asking
	// for something that is not a view: refused with a short reply.
	adminOnly
)

// adminOnlyToast answers a button press refused by adminOnly.
const adminOnlyToast = "⛔ Only admins can do this here"

// inaccessibleToast answers a press on a message Telegram no longer
// hands the bot, so it cannot be edited.
const inaccessibleToast = "This message is too old. Send /status for a fresh view."

// groupNotice is sent once per process to a group chat that has no
// admin_user_ids, while every member can still change state.
const groupNotice = "⚠️ <b>Every member of this group can control the agent.</b> " +
	"Set <code>telegram.admin_user_ids</code> in <code>/etc/statix-agent/config.toml</code> " +
	"to the user IDs allowed to change state; a future release will require it in group chats."

// authorize is the one gate for text commands and button presses. view
// says the update only reads state. The chat allowlist is checked first
// and a foreign chat is ignored without a trace, as before. Then:
// relayed text is ignored; in a private chat the sender must be the chat
// itself; in a group, once admin_user_ids is set, only those users may
// do more than view.
func (a *Agent) authorize(ctx context.Context, s sender, view bool) verdict {
	if s.chatID != a.cfg.Telegram.ChatID {
		return ignored
	}
	if s.relayed {
		log.Printf("agent: ignoring forwarded, via-bot or anonymous message from %d", s.fromID)
		return ignored
	}
	switch s.chatType {
	case "":
		// Only updates built in code have no type: the client always
		// sets one (see telegram.GetUpdates).
		return allowed
	case "private":
		if s.fromID != s.chatID {
			log.Printf("agent: ignoring update from user %d in private chat %d", s.fromID, s.chatID)
			return ignored
		}
		return allowed
	case "group", "supergroup", "channel":
		admins := a.cfg.Telegram.AdminUserIDs
		if len(admins) == 0 {
			if !a.groupNoticeSent {
				a.groupNoticeSent = true
				a.push(ctx, groupNotice)
			}
			return allowed
		}
		if view || slices.Contains(admins, s.fromID) {
			return allowed
		}
		log.Printf("agent: refusing non-view action from non-admin %d", s.fromID)
		return adminOnly
	}
	log.Printf("agent: ignoring update from chat type %q", s.chatType)
	return ignored
}
