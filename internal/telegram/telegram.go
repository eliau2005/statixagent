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
	"time"
)

// Update is one incoming message, reduced to what the bot needs.
type Update struct {
	ID     int64 // update_id, used as the getUpdates offset cursor
	ChatID int64
	Text   string
}

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
	var lastID int64
	for _, chunk := range splitMessage(html, 4096) {
		payload := map[string]any{
			"chat_id":                  chatID,
			"text":                     chunk,
			"parse_mode":               "HTML",
			"disable_web_page_preview": true,
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

// GetUpdates long-polls for new messages after offset. It returns plain
// text messages only; the caller filters by chat ID.
func (c *Client) GetUpdates(ctx context.Context, offset int64, timeout time.Duration) ([]Update, error) {
	payload := map[string]any{
		"offset":          offset,
		"timeout":         int(timeout.Seconds()),
		"allowed_updates": []string{"message"},
	}
	var raw []struct {
		UpdateID int64 `json:"update_id"`
		Message  *struct {
			Text string `json:"text"`
			Chat struct {
				ID int64 `json:"id"`
			} `json:"chat"`
		} `json:"message"`
	}
	if err := c.call(ctx, "getUpdates", payload, &raw); err != nil {
		return nil, err
	}
	out := make([]Update, 0, len(raw))
	for _, r := range raw {
		u := Update{ID: r.UpdateID}
		if r.Message != nil {
			u.ChatID = r.Message.Chat.ID
			u.Text = r.Message.Text
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
