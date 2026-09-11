package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSendMessage(t *testing.T) {
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sendMessage" {
			t.Errorf("path = %s", r.URL.Path)
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		got = append(got, body)
		fmt.Fprint(w, `{"ok":true,"result":{}}`)
	}))
	defer srv.Close()

	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL}
	if err := c.SendMessage(context.Background(), 42, "<b>hi</b>"); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0]["chat_id"].(float64) != 42 || got[0]["parse_mode"] != "HTML" {
		t.Errorf("payload = %+v", got)
	}

	// Long message: must split into multiple sendMessage calls.
	got = nil
	long := strings.Repeat("line of text\n", 600) // ~7800 chars
	if err := c.SendMessage(context.Background(), 42, long); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("long message sent in %d chunks, want 2", len(got))
	}
	for i, m := range got {
		if n := len(m["text"].(string)); n > 4096 {
			t.Errorf("chunk %d is %d chars", i, n)
		}
	}
}

func TestSendMessageAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ok":false,"description":"Bad Request: chat not found"}`)
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL}
	err := c.SendMessage(context.Background(), 1, "x")
	if err == nil || !strings.Contains(err.Error(), "chat not found") {
		t.Errorf("err = %v", err)
	}
}

func TestGetUpdates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["offset"].(float64) != 7 {
			t.Errorf("offset = %v", body["offset"])
		}
		fmt.Fprint(w, `{"ok":true,"result":[
			{"update_id":7,"message":{"text":"/status","chat":{"id":42}}},
			{"update_id":8,"message":{"text":"/cpu","chat":{"id":999}}},
			{"update_id":9}
		]}`)
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL}
	ups, err := c.GetUpdates(context.Background(), 7, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(ups) != 3 {
		t.Fatalf("updates = %d", len(ups))
	}
	if ups[0].ChatID != 42 || ups[0].Text != "/status" || ups[0].ID != 7 {
		t.Errorf("update 0 = %+v", ups[0])
	}
	if ups[2].ChatID != 0 || ups[2].Text != "" {
		t.Errorf("message-less update must be zero-valued: %+v", ups[2])
	}
}

func TestSendMessageIDReturnsID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ok":true,"result":{"message_id":777}}`)
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL}
	id, err := c.SendMessageID(context.Background(), 42, "hi")
	if err != nil || id != 777 {
		t.Errorf("id = %d, err = %v, want 777", id, err)
	}
}

func TestDeleteMessagesBatches(t *testing.T) {
	var batches [][]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/deleteMessages" {
			t.Errorf("path = %s", r.URL.Path)
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		batches = append(batches, body["message_ids"].([]any))
		fmt.Fprint(w, `{"ok":true,"result":true}`)
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL}

	ids := make([]int64, 250)
	for i := range ids {
		ids[i] = int64(i + 1)
	}
	if err := c.DeleteMessages(context.Background(), 42, ids); err != nil {
		t.Fatal(err)
	}
	if len(batches) != 3 || len(batches[0]) != 100 || len(batches[2]) != 50 {
		sizes := []int{}
		for _, b := range batches {
			sizes = append(sizes, len(b))
		}
		t.Errorf("batch sizes = %v, want [100 100 50]", sizes)
	}
}

func TestSetMyCommands(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/setMyCommands" {
			t.Errorf("path = %s", r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&got)
		fmt.Fprint(w, `{"ok":true,"result":true}`)
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL}
	err := c.SetMyCommands(context.Background(), []BotCommand{{Command: "status", Description: "dashboard"}})
	if err != nil {
		t.Fatal(err)
	}
	cmds := got["commands"].([]any)
	first := cmds[0].(map[string]any)
	if first["command"] != "status" || first["description"] != "dashboard" {
		t.Errorf("payload = %+v", got)
	}
}

func TestSplitMessage(t *testing.T) {
	if got := splitMessage("short", 4096); len(got) != 1 || got[0] != "short" {
		t.Errorf("short = %v", got)
	}
	chunks := splitMessage("aaaa\nbbbb\ncccc", 10)
	if len(chunks) != 2 || chunks[0] != "aaaa\nbbbb" || chunks[1] != "cccc" {
		t.Errorf("chunks = %q", chunks)
	}
	// No newline available: hard cut.
	chunks = splitMessage(strings.Repeat("x", 25), 10)
	if len(chunks) != 3 {
		t.Errorf("hard cut = %q", chunks)
	}
}

func TestSplitMessageHTMLPre(t *testing.T) {
	// A <pre> card longer than the limit must yield well-formed chunks:
	// each closes open tags and the next reopens them.
	body := strings.Repeat("line of text inside pre\n", 250) // ~5500 chars
	msg := "<b>Docker</b>\n<pre>" + body + "</pre>"
	if len(msg) < 5000 {
		t.Fatalf("fixture too short: %d", len(msg))
	}
	chunks := splitMessage(msg, 4096)
	if len(chunks) < 2 {
		t.Fatalf("want multiple chunks, got %d", len(chunks))
	}
	for i, c := range chunks {
		if len(c) > 4096 {
			t.Errorf("chunk %d length %d", i, len(c))
		}
		if err := htmlBalanced(c); err != nil {
			t.Errorf("chunk %d not balanced: %v\n%q", i, err, c[:min(80, len(c))])
		}
	}
	// First chunk should close the open <pre>; later chunks should reopen it.
	if !strings.HasSuffix(chunks[0], "</pre>") && !strings.Contains(chunks[0], "</pre>") {
		// Allow closing </b></pre> order — pre must be closed.
		if !strings.Contains(chunks[0], "</pre>") {
			t.Errorf("first chunk missing </pre>: …%q", chunks[0][max(0, len(chunks[0])-40):])
		}
	}
	if len(chunks) > 1 && !strings.Contains(chunks[1], "<pre>") {
		t.Errorf("second chunk missing reopen <pre>: %q", chunks[1][:min(40, len(chunks[1]))])
	}
}

func TestClampKeyboard(t *testing.T) {
	long := strings.Repeat("h", 70)
	kb := Keyboard{{{Text: "x", Data: "cr:" + long}}}
	got := clampKeyboard(kb)
	if n := len(got[0][0].Data); n > maxCallbackData {
		t.Errorf("callback_data length %d, want ≤ %d", n, maxCallbackData)
	}
	if got[0][0].Data != ("cr:"+long)[:maxCallbackData] {
		t.Errorf("truncated = %q", got[0][0].Data)
	}
}

// htmlBalanced checks that tracked tags are properly nested/closed.
func htmlBalanced(s string) error {
	var stack []string
	for i := 0; i < len(s); {
		if s[i] != '<' {
			i++
			continue
		}
		end := strings.IndexByte(s[i:], '>')
		if end < 0 {
			return fmt.Errorf("unclosed < at %d", i)
		}
		end += i
		name := s[i+1 : end]
		closing := false
		if len(name) > 0 && name[0] == '/' {
			closing = true
			name = name[1:]
		}
		if sp := strings.IndexAny(name, " \t"); sp >= 0 {
			name = name[:sp]
		}
		name = strings.ToLower(name)
		if htmlSplitTags[name] {
			if closing {
				if len(stack) == 0 || stack[len(stack)-1] != name {
					return fmt.Errorf("unexpected </%s>", name)
				}
				stack = stack[:len(stack)-1]
			} else {
				stack = append(stack, name)
			}
		}
		i = end + 1
	}
	if len(stack) != 0 {
		return fmt.Errorf("unclosed %v", stack)
	}
	return nil
}
