package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

const fakeToken = "123456789:AAH-fake_TOKEN_value0123456789abcdef"

// unreachableClient points at a closed local port so every request fails
// at dial time with the token-bearing URL.
func unreachableClient() *Client {
	c := New(fakeToken)
	c.BaseURL = "http://127.0.0.1:1/bot" + fakeToken
	return c
}

func assertRedacted(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), fakeToken) || strings.Contains(fmt.Sprintf("%+v", err), fakeToken) {
		t.Errorf("token leaked in error: %v", err)
	}
	if !strings.Contains(err.Error(), "bot<redacted>") {
		t.Errorf("error lost its redacted URL context: %v", err)
	}
}

func TestTransportErrorRedactsToken(t *testing.T) {
	c := unreachableClient()
	ctx := context.Background()
	calls := []struct {
		method string
		run    func() error
	}{
		{"sendMessage", func() error { return c.SendMessage(ctx, 42, "hi") }},
		{"editMessageText", func() error { return c.EditMessageKB(ctx, 42, 1, "hi", nil) }},
		{"answerCallbackQuery", func() error { return c.AnswerCallback(ctx, "cb", "ok") }},
		{"deleteMessages", func() error { return c.DeleteMessages(ctx, 42, []int64{1}) }},
		{"setMyCommands", func() error { return c.SetMyCommands(ctx, []BotCommand{{Command: "status"}}) }},
		{"getUpdates", func() error { _, err := c.GetUpdates(ctx, 0, time.Second); return err }},
	}
	for _, tc := range calls {
		t.Run(tc.method, func(t *testing.T) {
			err := tc.run()
			assertRedacted(t, err)
			if !strings.Contains(err.Error(), tc.method) {
				t.Errorf("error missing method name: %v", err)
			}
		})
	}
}

func TestTransportErrorPreservesType(t *testing.T) {
	err := unreachableClient().SendMessage(context.Background(), 42, "hi")
	assertRedacted(t, err)
	var ue *url.Error
	if !errors.As(err, &ue) {
		t.Fatalf("errors.As(*url.Error) failed for %T: %v", err, err)
	}
	if strings.Contains(ue.URL, fakeToken) {
		t.Errorf("url.Error.URL still has token: %s", ue.URL)
	}
}

func TestCanceledContextRedactsToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ok":true,"result":[]}`)
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL + "/bot" + fakeToken}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.GetUpdates(ctx, 0, time.Second)
	assertRedacted(t, err)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("errors.Is(context.Canceled) = false: %v", err)
	}
}

func TestTimeoutRedactsToken(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	c := &Client{HTTP: &http.Client{Timeout: 50 * time.Millisecond}, BaseURL: srv.URL + "/bot" + fakeToken}
	err := c.SendMessage(context.Background(), 42, "hi")
	assertRedacted(t, err)
	var ue *url.Error
	if !errors.As(err, &ue) || !ue.Timeout() {
		t.Errorf("want timeout *url.Error, got %T: %v", err, err)
	}
}

func TestLoggedErrorRedactsToken(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	_, err := unreachableClient().GetUpdates(context.Background(), 0, time.Second)
	log.Printf("agent: getUpdates: %v", err)
	log.Printf("agent: getUpdates: %+v", err)
	if strings.Contains(buf.String(), fakeToken) {
		t.Errorf("token leaked into log output: %s", buf.String())
	}
}

func TestRedact(t *testing.T) {
	cases := []struct{ in, want string }{
		{`Post "https://api.telegram.org/bot` + fakeToken + `/sendMessage": EOF`,
			`Post "https://api.telegram.org/bot<redacted>/sendMessage": EOF`},
		{"bot" + fakeToken + " and bot" + fakeToken, "bot<redacted> and bot<redacted>"},
		{"dial tcp 127.0.0.1:443: connection refused", "dial tcp 127.0.0.1:443: connection refused"},
		{"robot arm", "robot arm"},
	}
	for _, tc := range cases {
		if got := redact(tc.in); got != tc.want {
			t.Errorf("redact(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSanitizeErrFallback(t *testing.T) {
	if sanitizeErr(nil) != nil {
		t.Error("sanitizeErr(nil) != nil")
	}
	plain := errors.New("no secrets here")
	if sanitizeErr(plain) != plain {
		t.Error("token-free error should be returned unchanged")
	}
	err := sanitizeErr(fmt.Errorf("x bot%s y: %w", fakeToken, io.EOF))
	if strings.Contains(err.Error(), fakeToken) {
		t.Errorf("token leaked: %v", err)
	}
	if !errors.Is(err, io.EOF) {
		t.Errorf("errors.Is(io.EOF) = false: %v", err)
	}
}

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
