// Package telegram is a minimal Telegram Bot API client: sendMessage and a
// getUpdates long-poll. No SDK — the agent uses exactly two endpoints and a
// hand-rolled client keeps the binary small (MVP §1).
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Update is one incoming event, reduced to what the bot needs: either a
// text message or a button press (Callback non-nil).
type Update struct {
	ID       int64 // update_id, used as the getUpdates offset cursor
	ChatID   int64
	Text     string
	Callback *Callback
}

// Callback is an inline-keyboard button press.
type Callback struct {
	ID        string // callback_query id, must be answered
	ChatID    int64
	MessageID int64 // the message carrying the keyboard
	Data      string
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
	BaseURL string
}

// New returns a client for the given bot token.
func New(token string) *Client {
	return &Client{
		// Long-poll timeout is 50s server-side; the client must outlive it.
		HTTP:    &http.Client{Timeout: 70 * time.Second},
		BaseURL: "https://api.telegram.org/bot" + token,
	}
}

// apiResponse is the Bot API envelope.
type apiResponse struct {
	OK          bool            `json:"ok"`
	Description string          `json:"description"`
	Result      json.RawMessage `json:"result"`
}

func (c *Client) call(ctx context.Context, method string, payload, result any) error {
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
		return fmt.Errorf("telegram: %s: %w", method, err)
	}
	defer resp.Body.Close()
	var env apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("telegram: %s: %w", method, err)
	}
	if !env.OK {
		return fmt.Errorf("telegram: %s: %s", method, env.Description)
	}
	if result != nil {
		return json.Unmarshal(env.Result, result)
	}
	return nil
}

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
	chunks := splitMessage(html, 4096)
	var lastID int64
	for i, chunk := range chunks {
		payload := map[string]any{
			"chat_id":                  chatID,
			"text":                     chunk,
			"parse_mode":               "HTML",
			"disable_web_page_preview": true,
		}
		if kb != nil && i == len(chunks)-1 {
			payload["reply_markup"] = map[string]any{"inline_keyboard": kb}
		}
		var sent struct {
			MessageID int64 `json:"message_id"`
		}
		if err := c.call(ctx, "sendMessage", payload, &sent); err != nil {
			return 0, err
		}
		lastID = sent.MessageID
	}
	return lastID, nil
}

// EditMessageKB replaces a message's text and keyboard in place — the
// mechanism behind button navigation and live views. Telegram rejects
// edits that change nothing; that case is reported as success.
func (c *Client) EditMessageKB(ctx context.Context, chatID, messageID int64, html string, kb Keyboard) error {
	payload := map[string]any{
		"chat_id":                  chatID,
		"message_id":               messageID,
		"text":                     html,
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	}
	if kb != nil {
		payload["reply_markup"] = map[string]any{"inline_keyboard": kb}
	}
	err := c.call(ctx, "editMessageText", payload, nil)
	if err != nil && strings.Contains(err.Error(), "message is not modified") {
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
	return c.call(ctx, "answerCallbackQuery", payload, nil)
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

// SetMyCommands registers the command menu shown by Telegram clients.
func (c *Client) SetMyCommands(ctx context.Context, commands []BotCommand) error {
	return c.call(ctx, "setMyCommands", map[string]any{"commands": commands}, nil)
}

// GetUpdates long-polls for new messages and button presses after offset.
// The caller filters by chat ID.
func (c *Client) GetUpdates(ctx context.Context, offset int64, timeout time.Duration) ([]Update, error) {
	payload := map[string]any{
		"offset":          offset,
		"timeout":         int(timeout.Seconds()),
		"allowed_updates": []string{"message", "callback_query"},
	}
	var raw []struct {
		UpdateID int64 `json:"update_id"`
		Message  *struct {
			Text string `json:"text"`
			Chat struct {
				ID int64 `json:"id"`
			} `json:"chat"`
		} `json:"message"`
		CallbackQuery *struct {
			ID      string `json:"id"`
			Data    string `json:"data"`
			Message *struct {
				MessageID int64 `json:"message_id"`
				Chat      struct {
					ID int64 `json:"id"`
				} `json:"chat"`
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
			u.ChatID = r.Message.Chat.ID
			u.Text = r.Message.Text
		case r.CallbackQuery != nil && r.CallbackQuery.Message != nil:
			u.Callback = &Callback{
				ID:        r.CallbackQuery.ID,
				Data:      r.CallbackQuery.Data,
				ChatID:    r.CallbackQuery.Message.Chat.ID,
				MessageID: r.CallbackQuery.Message.MessageID,
			}
			u.ChatID = u.Callback.ChatID
		}
		out = append(out, u)
	}
	return out, nil
}

// splitMessage breaks text into chunks of at most limit characters,
// preferring newline boundaries.
func splitMessage(s string, limit int) []string {
	if len(s) <= limit {
		return []string{s}
	}
	var chunks []string
	for len(s) > limit {
		cut := limit
		if i := lastIndexByteBefore(s, '\n', limit); i > 0 {
			cut = i
		}
		chunks = append(chunks, s[:cut])
		s = s[cut:]
		if len(s) > 0 && s[0] == '\n' {
			s = s[1:]
		}
	}
	if s != "" {
		chunks = append(chunks, s)
	}
	return chunks
}

func lastIndexByteBefore(s string, b byte, before int) int {
	for i := before - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}
