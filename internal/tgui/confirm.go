package tgui

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"
)

// Confirm tokens (docs/telegram-ux-redesign.md §4.2, §6). A host-changing
// action never travels in callback data: its Yes button carries only a
// single-use token, "~1y|<epoch><nonce>", and Cancel "~1n|<nonce>". What
// the token stands for lives here, in memory, so a forged Yes names
// nothing and a restart fails closed: the old buttons find no token and
// are asked again instead of acting.

// Confirm acts, outside the screen registry: they name a token, not a
// screen.
const (
	ActYes = "y"
	ActNo  = "n"
)

const (
	// TokenTTL is how long a confirm screen stays good.
	TokenTTL = 120 * time.Second
	// maxTokens bounds the store; minting past it evicts.
	maxTokens = 256
	epochLen  = 4  // base32 characters, random per process
	nonceLen  = 12 // 9 random bytes, base64url
)

// Intent is what one token stands for.
type Intent struct {
	Action string // the action's ID
	Target string // the resolved target, re-checked against fresh state on Yes
	// Only ActorID may press Yes, in ChatID, on MessageID (Decision 3).
	ActorID   int64
	ChatID    int64
	MessageID int64
	// Final marks the second screen of a double confirm.
	Final bool
}

// Check is the verdict on one Yes or Cancel press.
type Check uint8

const (
	// Confirmed: the press won the token. On Yes it is now running and
	// the caller must Finish it; on Cancel it is gone.
	Confirmed Check = iota
	// Stale: a previous boot's token, an unknown or malformed one, or one
	// pressed on another chat or message. Never acted on.
	Stale
	// Expired: the token outlived TokenTTL. Never acted on.
	Expired
	// WrongActor: someone other than the user who asked pressed it. The
	// token stays pending for its owner.
	WrongActor
	// Running and Done: the token was already used.
	Running
	Done
)

type tokenState uint8

const (
	pending tokenState = iota
	running
	done
)

type token struct {
	Intent
	nonce   string
	expires time.Time
	state   tokenState
}

// Tokens is the pending-token store of one process.
type Tokens struct {
	epoch string
	now   func() time.Time
	rand  io.Reader

	mu     sync.Mutex
	tokens map[string]*token // by nonce
	order  []string          // nonces, oldest first
}

// NewTokens returns an empty store with a fresh random epoch. now is the
// clock for expiry; rnd supplies the epoch and nonces (crypto/rand.Reader
// outside tests).
func NewTokens(now func() time.Time, rnd io.Reader) *Tokens {
	var b [5]byte
	if _, err := io.ReadFull(rnd, b[:]); err != nil {
		// Even a constant epoch fails closed: tokens are memory-only.
		b = [5]byte{}
	}
	return &Tokens{
		epoch:  base32.StdEncoding.EncodeToString(b[:])[:epochLen],
		now:    now,
		rand:   rnd,
		tokens: map[string]*token{},
	}
}

// Epoch is this process's boot epoch.
func (t *Tokens) Epoch() string { return t.epoch }

// Mint stores a pending token for in and returns its nonce.
func (t *Tokens) Mint(in Intent) (string, error) {
	var b [9]byte
	if _, err := io.ReadFull(t.rand, b[:]); err != nil {
		return "", fmt.Errorf("tgui: minting confirm token: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(b[:])
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, dup := t.tokens[nonce]; dup {
		// Never with crypto/rand; a broken source must not rebind a token.
		return "", fmt.Errorf("tgui: minting confirm token: nonce reused")
	}
	t.evict()
	t.tokens[nonce] = &token{Intent: in, nonce: nonce, expires: t.now().Add(TokenTTL)}
	t.order = append(t.order, nonce)
	return nonce, nil
}

// evict makes room for one more token: expired ones go first, then the
// oldest. t.mu is held.
func (t *Tokens) evict() {
	if len(t.order) < maxTokens {
		return
	}
	now := t.now()
	t.order = slices.DeleteFunc(t.order, func(n string) bool {
		if tok := t.tokens[n]; !now.Before(tok.expires) {
			delete(t.tokens, n)
			return true
		}
		return false
	})
	for len(t.order) >= maxTokens {
		delete(t.tokens, t.order[0])
		t.order = t.order[1:]
	}
}

// remove drops a token. t.mu is held.
func (t *Tokens) remove(nonce string) {
	delete(t.tokens, nonce)
	t.order = slices.DeleteFunc(t.order, func(n string) bool { return n == nonce })
}

// Yes is the call of a Yes button for nonce.
func (t *Tokens) Yes(nonce string) Call {
	return Call{Act: ActYes, Args: []string{t.epoch + nonce}}
}

// No is the call of a Cancel button for nonce.
func No(nonce string) Call {
	return Call{Act: ActNo, Args: []string{nonce}}
}

// Nonce returns the nonce part of a Yes argument, or "" when it is
// malformed. It is for hashing into the audit log: never log it as is.
func Nonce(arg string) string {
	if len(arg) != epochLen+nonceLen {
		return ""
	}
	return arg[epochLen:]
}

// Rebind moves a token to the message its screen ended up in: a typed
// command's prompt is sent before its ID is known, and a failed edit
// falls back to a new message.
func (t *Tokens) Rebind(nonce string, messageID int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if tok, ok := t.tokens[nonce]; ok && tok.state == pending {
		tok.MessageID = messageID
	}
}

// Claim checks a Yes press, arg being the button's "<epoch><nonce>", and
// on Confirmed moves the token from pending to running, so of two taps
// exactly one wins. The Intent is returned whenever the token is known.
func (t *Tokens) Claim(arg string, actorID, chatID, messageID int64) (Intent, Check) {
	if len(arg) != epochLen+nonceLen || arg[:epochLen] != t.epoch {
		return Intent{}, Stale
	}
	return t.take(arg[epochLen:], actorID, chatID, messageID, func(tok *token) { tok.state = running })
}

// Cancel checks a Cancel press and on Confirmed drops the pending token.
func (t *Tokens) Cancel(nonce string, actorID, chatID, messageID int64) (Intent, Check) {
	if len(nonce) != nonceLen {
		return Intent{}, Stale
	}
	return t.take(nonce, actorID, chatID, messageID, func(tok *token) { t.remove(tok.nonce) })
}

// take runs the checks Claim and Cancel share and applies win to a
// pending token that passes them.
func (t *Tokens) take(nonce string, actorID, chatID, messageID int64, win func(*token)) (Intent, Check) {
	t.mu.Lock()
	defer t.mu.Unlock()
	tok, ok := t.tokens[nonce]
	switch {
	case !ok:
		return Intent{}, Stale
	case !t.now().Before(tok.expires):
		t.remove(nonce)
		return tok.Intent, Expired
	case tok.ChatID != chatID || tok.MessageID != messageID || messageID == 0:
		// 0 is a prompt whose message is not known yet.
		return tok.Intent, Stale
	case tok.ActorID != actorID:
		return tok.Intent, WrongActor
	case tok.state == running:
		return tok.Intent, Running
	case tok.state == done:
		return tok.Intent, Done
	}
	win(tok)
	return tok.Intent, Confirmed
}

// Finish marks a running token done; a later tap gets Done until it
// expires.
func (t *Tokens) Finish(nonce string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if tok, ok := t.tokens[nonce]; ok {
		tok.state = done
	}
}
