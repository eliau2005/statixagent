// Package telegram is a minimal Telegram Bot API client: sendMessage and a
// getUpdates long-poll. No SDK — the agent uses exactly two endpoints and a
// hand-rolled client keeps the binary small (MVP §1).
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Update is one incoming event, reduced to what the bot needs: either a
// text message or a button press (Callback non-nil).
type Update struct {
	ID       int64 // update_id, used as the getUpdates offset cursor
	ChatID   int64
	Text     string
	Date     time.Time // when a text message was sent; zero for callbacks
	Callback *Callback

	// Sender identity of a text message, for authorization.
	FromID   int64  // from.id; zero when Telegram sent no user
	ChatType string // chat.type: private, group, supergroup or channel
	// Forwarded is set for forwarded and automatically forwarded
	// messages: their text was written by someone else, earlier.
	Forwarded bool
	ViaBot    bool // sent through an inline bot
	// SenderChat is set when the message was sent on behalf of a chat
	// (an anonymous group admin or a channel), so from is not a person.
	SenderChat bool
}

// Callback is an inline-keyboard button press.
type Callback struct {
	ID        string // callback_query id, must be answered
	ChatID    int64
	MessageID int64 // the message carrying the keyboard
	Data      string
	FromID    int64  // from.id: the user who pressed the button
	ChatType  string // chat.type of the message carrying the keyboard
	// Inaccessible is set when Telegram no longer gives the bot the
	// message (too old or deleted): there is nothing to edit, and with no
	// message at all the chat is unknown too (ChatID is zero).
	Inaccessible bool
}

// Button is one inline-keyboard button; Data is sent back on press.
type Button struct {
	Text string `json:"text"`
	Data string `json:"callback_data"`
}

// Keyboard is rows of buttons.
type Keyboard [][]Button

// Client talks to the Bot API for one bot token.
type Client struct {
	HTTP *http.Client
	// BaseURL includes the token: https://api.telegram.org/bot<token>
	// Errors returned by Client have the token redacted.
	BaseURL string

	// limiter paces messages and edits per chat; nil disables pacing.
	limiter *chatLimiter
	// clock times 429 retry waits; the zero value uses the real clock.
	clock clock
}

// maxRetryWait caps how long a 429 retry may wait. A longer retry_after
// is a flood ban rather than a burst, so the error goes to the caller.
const maxRetryWait = 30 * time.Second

// APIError is a Bot API "ok": false reply.
type APIError struct {
	Code        int    // error_code, e.g. 400, 403, 429
	Description string // human-readable reason, token redacted
	// RetryAfter is parameters.retry_after on a 429, zero otherwise.
	RetryAfter time.Duration
}

func (e *APIError) Error() string { return e.Description }

// RetryAfter reports the wait Telegram asked for when err is a 429.
func RetryAfter(err error) (time.Duration, bool) {
	var ae *APIError
	if errors.As(err, &ae) && ae.Code == http.StatusTooManyRequests {
		return ae.RetryAfter, true
	}
	return 0, false
}

// IsMessageNotFound reports an edit of a message that no longer exists,
// e.g. one removed by /clear_chat or by the user.
func IsMessageNotFound(err error) bool {
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != http.StatusBadRequest {
		return false
	}
	d := ae.Description
	return strings.Contains(d, "message to edit not found") ||
		strings.Contains(d, "message not found") ||
		strings.Contains(d, "MESSAGE_ID_INVALID")
}

// isNotModified reports an edit that would change nothing.
func isNotModified(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && strings.Contains(ae.Description, "message is not modified")
}

// tokenPattern matches the bot token segment of a Bot API URL.
var tokenPattern = regexp.MustCompile(`bot[0-9]+:[A-Za-z0-9_-]+`)

// redact replaces any bot token in s with a placeholder.
func redact(s string) string {
	return tokenPattern.ReplaceAllString(s, "bot<redacted>")
}

// redactedError hides a token that appears in a wrapped error's text while
// keeping the chain intact for errors.Is / errors.As.
type redactedError struct {
	msg string
	err error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.err }

// sanitizeErr strips the bot token from err. net/http reports transport
// failures as *url.Error carrying the full request URL, which would leak the
// token into logs; its URL is rewritten in place so the error type, Timeout()
// and Unwrap() keep working.
func sanitizeErr(err error) error {
	if err == nil {
		return nil
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		ue.URL = redact(ue.URL)
	}
	msg := err.Error()
	if clean := redact(msg); clean != msg {
		return &redactedError{msg: clean, err: err}
	}
	return err
}

// New returns a client for the given bot token.
func New(token string) *Client {
	return &Client{
		// Long-poll timeout is 50s server-side; the client must outlive it.
		HTTP:    &http.Client{Timeout: 70 * time.Second},
		BaseURL: "https://api.telegram.org/bot" + token,
		limiter: newChatLimiter(time.Second, 3, realClock),
	}
}

// apiResponse is the Bot API envelope.
type apiResponse struct {
	OK          bool   `json:"ok"`
	ErrorCode   int    `json:"error_code"`
	Description string `json:"description"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
	Result json.RawMessage `json:"result"`
}

// call performs one Bot API request.
func (c *Client) call(ctx context.Context, method string, payload, result any) error {
	if err := c.do(ctx, method, payload, result); err != nil {
		return wrapErr(method, err)
	}
	return nil
}

// wrapErr is the single exit for every error the client returns: it adds
// the method name and redacts the token, keeping the chain for errors.As.
func wrapErr(method string, err error) error {
	return fmt.Errorf("telegram: %s: %w", method, sanitizeErr(err))
}

func (c *Client) do(ctx context.Context, method string, payload, result any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/"+method, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var env apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("HTTP %d: %w", resp.StatusCode, err)
	}
	if !env.OK {
		code := env.ErrorCode
		if code == 0 {
			code = resp.StatusCode
		}
		return &APIError{
			Code:        code,
			Description: redact(env.Description),
			RetryAfter:  time.Duration(env.Parameters.RetryAfter) * time.Second,
		}
	}
	if result != nil {
		return json.Unmarshal(env.Result, result)
	}
	return nil
}

// callChat is call for a message, edit or answer: it waits for the chat's
// send budget (chatID 0 skips pacing) and retries once after a 429 whose
// retry_after is within maxRetryWait. Only these idempotent-enough calls
// retry; any bot action has already run before the reply is sent.
func (c *Client) callChat(ctx context.Context, chatID int64, method string, payload, result any) error {
	for attempt := 0; ; attempt++ {
		if c.limiter != nil && chatID != 0 {
			if err := c.limiter.wait(ctx, chatID); err != nil {
				return wrapErr(method, err)
			}
		}
		err := c.call(ctx, method, payload, result)
		wait, is429 := RetryAfter(err)
		if !is429 || attempt > 0 || wait > maxRetryWait {
			return err
		}
		if err := c.clock.orReal().sleep(ctx, wait); err != nil {
			return wrapErr(method, err)
		}
	}
}

// noPreview disables link previews (link_preview_options replaces the
// deprecated disable_web_page_preview flag).
var noPreview = map[string]any{"is_disabled": true}

// maxMessageLen is Telegram's message text limit. It counts characters
// after parsing; comparing raw bytes against it is stricter, so safe.
const maxMessageLen = 4096

// SendMessage sends an HTML-formatted message to a chat. Messages longer
// than Telegram's 4096-char limit are split on line boundaries.
func (c *Client) SendMessage(ctx context.Context, chatID int64, html string) error {
	_, err := c.SendMessageID(ctx, chatID, html)
	return err
}

// SendMessageID sends like SendMessage and returns the message_id of the
// last chunk, used as the anchor for /clear_chat's deletion sweep.
func (c *Client) SendMessageID(ctx context.Context, chatID int64, html string) (int64, error) {
	return c.SendMessageKB(ctx, chatID, html, nil)
}

// SendMessageKB sends a message with an optional inline keyboard attached
// to the last chunk, returning its message_id.
func (c *Client) SendMessageKB(ctx context.Context, chatID int64, html string, kb Keyboard) (int64, error) {
	chunks := splitMessage(html, maxMessageLen)
	var lastID int64
	for i, chunk := range chunks {
		payload := map[string]any{
			"chat_id":              chatID,
			"text":                 chunk,
			"parse_mode":           "HTML",
			"link_preview_options": noPreview,
		}
		if kb != nil && i == len(chunks)-1 {
			payload["reply_markup"] = map[string]any{"inline_keyboard": clampKeyboard(kb)}
		}
		var sent struct {
			MessageID int64 `json:"message_id"`
		}
		if err := c.callChat(ctx, chatID, "sendMessage", payload, &sent); err != nil {
			return 0, err
		}
		lastID = sent.MessageID
	}
	return lastID, nil
}

// truncatedFooter marks an edit that FitEdit had to cut.
const truncatedFooter = "\n… truncated"

// FitEdit returns html cut to fit one message. An edit cannot be split
// into several messages without breaking the one-message view, so text
// over the limit keeps its head, cut by splitMessage's HTML-safe logic
// (tags balanced, never mid-tag, mid-entity or mid-rune), plus a footer.
func FitEdit(html string) string {
	if len(html) <= maxMessageLen {
		return html
	}
	return splitMessage(html, maxMessageLen-len(truncatedFooter))[0] + truncatedFooter
}

// EditMessageKB replaces a message's text and keyboard in place — the
// mechanism behind button navigation and live views. Text over the limit
// is cut by FitEdit. Telegram rejects edits that change nothing; that case
// is reported as success.
func (c *Client) EditMessageKB(ctx context.Context, chatID, messageID int64, html string, kb Keyboard) error {
	payload := map[string]any{
		"chat_id":              chatID,
		"message_id":           messageID,
		"text":                 FitEdit(html),
		"parse_mode":           "HTML",
		"link_preview_options": noPreview,
	}
	if kb != nil {
		payload["reply_markup"] = map[string]any{"inline_keyboard": clampKeyboard(kb)}
	}
	err := c.callChat(ctx, chatID, "editMessageText", payload, nil)
	if isNotModified(err) {
		return nil
	}
	return err
}

// EditMessageMarkup replaces only the inline keyboard of a message, leaving
// its text as sent: an alert keeps its details after a button acts on it.
// A nil kb removes the keyboard. Like EditMessageKB, an edit that changes
// nothing is reported as success.
func (c *Client) EditMessageMarkup(ctx context.Context, chatID, messageID int64, kb Keyboard) error {
	if kb == nil {
		kb = Keyboard{}
	}
	payload := map[string]any{
		"chat_id":      chatID,
		"message_id":   messageID,
		"reply_markup": map[string]any{"inline_keyboard": clampKeyboard(kb)},
	}
	err := c.callChat(ctx, chatID, "editMessageReplyMarkup", payload, nil)
	if isNotModified(err) {
		return nil
	}
	return err
}

// AnswerCallback acknowledges a button press (stops the client spinner).
// text, when non-empty, shows as a small toast.
func (c *Client) AnswerCallback(ctx context.Context, callbackID, text string) error {
	payload := map[string]any{"callback_query_id": callbackID}
	if text != "" {
		payload["text"] = text
	}
	// Answers are not chat messages: no pacing, so the spinner stops fast.
	return c.callChat(ctx, 0, "answerCallbackQuery", payload, nil)
}

// DeleteMessages deletes up to 48h-old messages by ID; IDs that cannot be
// deleted are skipped by the API. Batches of 100 per call (API limit).
func (c *Client) DeleteMessages(ctx context.Context, chatID int64, ids []int64) error {
	for len(ids) > 0 {
		n := len(ids)
		if n > 100 {
			n = 100
		}
		payload := map[string]any{"chat_id": chatID, "message_ids": ids[:n]}
		if err := c.call(ctx, "deleteMessages", payload, nil); err != nil {
			return err
		}
		ids = ids[n:]
	}
	return nil
}

// BotCommand is one entry of the bot's command menu.
type BotCommand struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

// CommandScope selects which chats see a command menu (BotCommandScope).
type CommandScope struct {
	Type   string `json:"type"`
	ChatID int64  `json:"chat_id,omitempty"`
}

// DefaultScope is the menu every chat without a narrower scope sees.
var DefaultScope = CommandScope{Type: "default"}

// ChatScope is the menu of one chat only.
func ChatScope(chatID int64) CommandScope {
	return CommandScope{Type: "chat", ChatID: chatID}
}

// SetMyCommands registers the command menu shown by Telegram clients in
// the given scope.
func (c *Client) SetMyCommands(ctx context.Context, commands []BotCommand, scope CommandScope) error {
	return c.call(ctx, "setMyCommands", map[string]any{"commands": commands, "scope": scope}, nil)
}

// DeleteMyCommands removes the command menu of the given scope, so clients
// fall back to a broader one (none, for the default scope).
func (c *Client) DeleteMyCommands(ctx context.Context, scope CommandScope) error {
	return c.call(ctx, "deleteMyCommands", map[string]any{"scope": scope}, nil)
}

// GetUpdates long-polls for new messages and button presses after offset.
// The caller filters by chat ID.
func (c *Client) GetUpdates(ctx context.Context, offset int64, timeout time.Duration) ([]Update, error) {
	payload := map[string]any{
		"offset":          offset,
		"timeout":         int(timeout.Seconds()),
		"allowed_updates": []string{"message", "callback_query"},
	}
	type chat struct {
		ID   int64  `json:"id"`
		Type string `json:"type"`
	}
	type user struct {
		ID int64 `json:"id"`
	}
	var raw []struct {
		UpdateID int64 `json:"update_id"`
		Message  *struct {
			Text       string          `json:"text"`
			Date       int64           `json:"date"`
			Chat       chat            `json:"chat"`
			From       *user           `json:"from"`
			SenderChat *chat           `json:"sender_chat"`
			ViaBot     *user           `json:"via_bot"`
			Origin     json.RawMessage `json:"forward_origin"`
			// forward_date is the pre-7.0 marker, kept for older servers.
			ForwardDate   int64 `json:"forward_date"`
			AutoForwarded bool  `json:"is_automatic_forward"`
		} `json:"message"`
		CallbackQuery *struct {
			ID      string `json:"id"`
			Data    string `json:"data"`
			From    user   `json:"from"`
			Message *struct {
				MessageID int64 `json:"message_id"`
				// Date is 0 for an InaccessibleMessage.
				Date int64 `json:"date"`
				Chat chat  `json:"chat"`
			} `json:"message"`
		} `json:"callback_query"`
	}
	if err := c.call(ctx, "getUpdates", payload, &raw); err != nil {
		return nil, err
	}
	out := make([]Update, 0, len(raw))
	for _, r := range raw {
		u := Update{ID: r.UpdateID}
		switch {
		case r.Message != nil:
			m := r.Message
			u.ChatID = m.Chat.ID
			u.ChatType = chatType(m.Chat.Type)
			u.Text = m.Text
			if m.Date > 0 {
				u.Date = time.Unix(m.Date, 0)
			}
			if m.From != nil {
				u.FromID = m.From.ID
			}
			u.Forwarded = len(m.Origin) > 0 && string(m.Origin) != "null" ||
				m.ForwardDate != 0 || m.AutoForwarded
			u.ViaBot = m.ViaBot != nil
			u.SenderChat = m.SenderChat != nil
		case r.CallbackQuery != nil:
			q := r.CallbackQuery
			u.Callback = &Callback{
				ID:           q.ID,
				Data:         q.Data,
				FromID:       q.From.ID,
				Inaccessible: q.Message == nil || q.Message.Date == 0,
			}
			if q.Message != nil {
				u.Callback.ChatID = q.Message.Chat.ID
				u.Callback.ChatType = chatType(q.Message.Chat.Type)
				u.Callback.MessageID = q.Message.MessageID
			}
			u.ChatID = u.Callback.ChatID
		}
		out = append(out, u)
	}
	return out, nil
}

// chatType returns chat.type, or "unknown" when Telegram sent none, so a
// parsed update never carries the empty type of one built in code.
func chatType(t string) string {
	if t == "" {
		return "unknown"
	}
	return t
}

// maxCallbackData is Telegram's hard limit on inline-button callback_data.
const maxCallbackData = 64

// clampKeyboard drops any button whose callback_data exceeds maxCallbackData
// so a single oversized button cannot make Telegram reject the entire keyboard.
// Callers should keep data short by construction (hashed snooze keys, indexed
// watch removals); this is a last line of defence.
func clampKeyboard(kb Keyboard) Keyboard {
	if kb == nil {
		return nil
	}
	out := make(Keyboard, 0, len(kb))
	for _, row := range kb {
		nr := make([]Button, 0, len(row))
		for _, btn := range row {
			if len(btn.Data) > maxCallbackData {
				log.Printf("telegram: dropping button %q: callback_data %d bytes > %d", btn.Text, len(btn.Data), maxCallbackData)
				continue
			}
			nr = append(nr, btn)
		}
		if len(nr) > 0 {
			out = append(out, nr)
		}
	}
	return out
}

// htmlSplitTags are the HTML tags this bot emits; splitMessage keeps them
// balanced across chunks so Telegram's HTML parser accepts every piece.
var htmlSplitTags = map[string]bool{
	"b": true, "code": true, "pre": true, "blockquote": true,
}

// splitMessage breaks text into chunks of at most limit characters,
// preferring newline boundaries. Open HTML tags from htmlSplitTags are
// closed at the cut and reopened on the next chunk.
func splitMessage(s string, limit int) []string {
	if limit <= 0 {
		return []string{s}
	}
	if len(s) <= limit {
		return []string{s}
	}
	var chunks []string
	var open []string // tags still open at the start of remaining s
	for len(s) > 0 {
		prefix := openHTML(open)
		if len(prefix)+len(s) <= limit {
			chunk := prefix + s
			if !htmlVisibleEmpty(chunk) {
				chunks = append(chunks, chunk)
			}
			break
		}
		// Reserve room for the reopen prefix and for closing whatever is
		// currently open; content may open more tags, so we shrink below.
		reserve := len(prefix) + len(closeHTML(open))
		budget := limit - reserve
		if budget < 1 {
			budget = 1
		}
		if budget > len(s) {
			budget = len(s)
		}
		cut := budget
		if i := lastIndexByteBefore(s, '\n', cut); i > 0 {
			cut = i
		}
		cut = safeCut(s, cut)
		if cut < 1 {
			// Hard cut: take one full rune so we always make progress.
			_, size := utf8.DecodeRuneInString(s)
			cut = size
			if cut < 1 {
				cut = 1
			}
		}
		newOpen := applyHTMLTags(open, s[:cut])
		closers := closeHTML(newOpen)
		for len(prefix)+cut+len(closers) > limit && cut > 1 {
			prev := cut
			cut--
			if i := lastIndexByteBefore(s, '\n', cut); i > 0 {
				cut = i
			}
			cut = safeCut(s, cut)
			if cut < 1 || cut >= prev {
				// Cannot shrink further without re-growing (e.g. mid-rune).
				_, size := utf8.DecodeRuneInString(s)
				cut = size
				if cut < 1 {
					cut = 1
				}
				newOpen = applyHTMLTags(open, s[:cut])
				closers = closeHTML(newOpen)
				break
			}
			newOpen = applyHTMLTags(open, s[:cut])
			closers = closeHTML(newOpen)
		}
		chunk := prefix + s[:cut] + closers
		if !htmlVisibleEmpty(chunk) {
			chunks = append(chunks, chunk)
		}
		open = newOpen
		s = s[cut:]
	}
	if len(chunks) == 0 {
		return []string{""}
	}
	return chunks
}

func openHTML(tags []string) string {
	var b strings.Builder
	for _, t := range tags {
		b.WriteByte('<')
		b.WriteString(t)
		b.WriteByte('>')
	}
	return b.String()
}

func closeHTML(tags []string) string {
	var b strings.Builder
	for i := len(tags) - 1; i >= 0; i-- {
		b.WriteString("</")
		b.WriteString(tags[i])
		b.WriteByte('>')
	}
	return b.String()
}

// applyHTMLTags returns the open-tag stack after scanning s for the tags
// in htmlSplitTags. Incomplete trailing "<..." is ignored (treated as text).
func applyHTMLTags(open []string, s string) []string {
	out := append([]string(nil), open...)
	for i := 0; i < len(s); {
		if s[i] != '<' {
			i++
			continue
		}
		end := strings.IndexByte(s[i:], '>')
		if end < 0 {
			break
		}
		end += i
		name := s[i+1 : end]
		closing := false
		if len(name) > 0 && name[0] == '/' {
			closing = true
			name = name[1:]
		}
		if sp := strings.IndexAny(name, " \t\n\r"); sp >= 0 {
			name = name[:sp]
		}
		name = strings.ToLower(name)
		if htmlSplitTags[name] {
			if closing {
				for k := len(out) - 1; k >= 0; k-- {
					if out[k] == name {
						out = append(out[:k], out[k+1:]...)
						break
					}
				}
			} else {
				out = append(out, name)
			}
		}
		i = end + 1
	}
	return out
}

// avoidMidTag moves cut to just before an unclosed '<' so we do not split
// inside a tag name.
func avoidMidTag(s string, cut int) int {
	if cut <= 0 || cut > len(s) {
		return cut
	}
	lt := strings.LastIndexByte(s[:cut], '<')
	if lt < 0 {
		return cut
	}
	if strings.IndexByte(s[lt:cut], '>') >= 0 {
		return cut
	}
	if lt == 0 {
		return cut // cannot move; caller may hard-cut
	}
	return lt
}

// avoidMidEntity moves cut to just before an unclosed '&…;' entity.
func avoidMidEntity(s string, cut int) int {
	if cut <= 0 || cut > len(s) {
		return cut
	}
	amp := strings.LastIndexByte(s[:cut], '&')
	if amp < 0 {
		return cut
	}
	if strings.IndexByte(s[amp:cut], ';') >= 0 {
		return cut
	}
	if amp == 0 {
		return cut
	}
	return amp
}

// safeCut backs cut off mid-tag, mid-entity, and mid-UTF-8-rune positions.
func safeCut(s string, cut int) int {
	if cut <= 0 || cut > len(s) {
		return cut
	}
	cut = avoidMidTag(s, cut)
	cut = avoidMidEntity(s, cut)
	for cut > 0 && cut < len(s) && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return cut
}

// htmlVisibleEmpty reports chunks that are only tags/whitespace — Telegram
// rejects those as empty message text.
func htmlVisibleEmpty(s string) bool {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '<' {
			end := strings.IndexByte(s[i:], '>')
			if end < 0 {
				b.WriteString(s[i:])
				break
			}
			i += end + 1
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return strings.TrimSpace(b.String()) == ""
}

func lastIndexByteBefore(s string, b byte, before int) int {
	if before > len(s) {
		before = len(s)
	}
	for i := before - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}
