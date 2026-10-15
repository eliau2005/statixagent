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
	"unicode/utf8"
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
		{"editMessageReplyMarkup", func() error { return c.EditMessageMarkup(ctx, 42, 1, nil) }},
		{"answerCallbackQuery", func() error { return c.AnswerCallback(ctx, "cb", "ok") }},
		{"deleteMessages", func() error { return c.DeleteMessages(ctx, 42, []int64{1}) }},
		{"setMyCommands", func() error { return c.SetMyCommands(ctx, []BotCommand{{Command: "status"}}, ChatScope(42)) }},
		{"deleteMyCommands", func() error { return c.DeleteMyCommands(ctx, DefaultScope) }},
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

func TestGetUpdatesParsesMessageDate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ok":true,"result":[`+
			`{"update_id":7,"message":{"text":"/status","date":1760000000,"chat":{"id":42}}},`+
			`{"update_id":8,"callback_query":{"id":"cb","data":"status","message":{"message_id":3,"date":1700000000,"chat":{"id":42}}}}]}`)
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL + "/bot" + fakeToken}
	ups, err := c.GetUpdates(context.Background(), 0, time.Second)
	if err != nil || len(ups) != 2 {
		t.Fatalf("GetUpdates = %+v, %v", ups, err)
	}
	if !ups[0].Date.Equal(time.Unix(1760000000, 0)) {
		t.Errorf("message date = %v", ups[0].Date)
	}
	// message.date on a callback is when the keyboard was sent, not the
	// press, so it must not surface as the update's date.
	if !ups[1].Date.IsZero() {
		t.Errorf("callback date = %v, want zero", ups[1].Date)
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
	err := c.SetMyCommands(context.Background(), []BotCommand{{Command: "status", Description: "dashboard"}}, ChatScope(-100))
	if err != nil {
		t.Fatal(err)
	}
	cmds := got["commands"].([]any)
	first := cmds[0].(map[string]any)
	if first["command"] != "status" || first["description"] != "dashboard" {
		t.Errorf("payload = %+v", got)
	}
	scope, _ := got["scope"].(map[string]any)
	if scope["type"] != "chat" || scope["chat_id"] != float64(-100) {
		t.Errorf("scope = %+v", got["scope"])
	}
}

func TestDeleteMyCommandsDefaultScope(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/deleteMyCommands" {
			t.Errorf("path = %s", r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&got)
		fmt.Fprint(w, `{"ok":true,"result":true}`)
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL}
	if err := c.DeleteMyCommands(context.Background(), DefaultScope); err != nil {
		t.Fatal(err)
	}
	scope, _ := got["scope"].(map[string]any)
	if len(scope) != 1 || scope["type"] != "default" {
		t.Errorf("scope = %+v, want only type default", got["scope"])
	}
}

func TestSplitMessage(t *testing.T) {
	if got := splitMessage("short", 4096); len(got) != 1 || got[0] != "short" {
		t.Errorf("short = %v", got)
	}
	chunks := splitMessage("aaaa\nbbbb\ncccc", 10)
	if len(chunks) != 2 || chunks[0] != "aaaa\nbbbb" || chunks[1] != "\ncccc" {
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
	if !strings.Contains(chunks[0], "</pre>") {
		t.Errorf("first chunk missing </pre>: …%q", chunks[0][max(0, len(chunks[0])-40):])
	}
	if len(chunks) > 1 && !strings.Contains(chunks[1], "<pre>") {
		t.Errorf("second chunk missing reopen <pre>: %q", chunks[1][:min(40, len(chunks[1]))])
	}
	// Joining visible text across chunks should recover the original exactly
	// (including newlines at split boundaries).
	var joined strings.Builder
	for _, c := range chunks {
		joined.WriteString(stripHTMLTags(c))
	}
	wantVisible := stripHTMLTags(msg)
	if joined.String() != wantVisible {
		t.Errorf("joined visible text != original\n got: %q\nwant: %q", joined.String()[:min(120, joined.Len())], wantVisible[:min(120, len(wantVisible))])
	}
}

func TestSplitMessageSafeCutUTF8AndEntity(t *testing.T) {
	// Hard-cut path with a multibyte rune near the boundary.
	msg := "<pre>" + strings.Repeat("a", 8) + "é" + strings.Repeat("b", 20) + "</pre>"
	chunks := splitMessage(msg, 20)
	for i, c := range chunks {
		if !utf8.ValidString(c) {
			t.Errorf("chunk %d invalid UTF-8: %q", i, c)
		}
		if err := htmlBalanced(c); err != nil {
			t.Errorf("chunk %d: %v", i, err)
		}
	}
	// Entity must not be split mid-sequence.
	msg = "<pre>" + strings.Repeat("x", 5) + "&amp;" + strings.Repeat("y", 20) + "</pre>"
	chunks = splitMessage(msg, 18)
	for i, c := range chunks {
		if strings.Contains(c, "&am") && !strings.Contains(c, "&amp;") {
			t.Errorf("chunk %d split mid-entity: %q", i, c)
		}
	}
}

func TestSplitMessageSkipsEmptyTagChunks(t *testing.T) {
	// A cut that would produce only reopen/close tags should be omitted.
	chunks := splitMessage("<blockquote></blockquote>hello", 20)
	for i, c := range chunks {
		if htmlVisibleEmpty(c) {
			t.Errorf("empty chunk %d: %q", i, c)
		}
	}
}

func stripHTMLTags(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '<' {
			end := strings.IndexByte(s[i:], '>')
			if end < 0 {
				break
			}
			i += end + 1
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func TestClampKeyboard(t *testing.T) {
	long := strings.Repeat("h", 70)
	kb := Keyboard{{{Text: "x", Data: "cr:" + long}}}
	got := clampKeyboard(kb)
	if len(got) != 0 {
		t.Errorf("oversized button should be dropped, got %+v", got)
	}
}

func TestClampKeyboardDropsLongCopy(t *testing.T) {
	kb := Keyboard{{{Text: "x", Copy: strings.Repeat("é", 257)}, {Text: "y", Copy: strings.Repeat("é", 256)}}}
	got := clampKeyboard(kb)
	if len(got) != 1 || len(got[0]) != 1 || got[0][0].Text != "y" {
		t.Errorf("copy_text over 256 characters should be dropped, got %+v", got)
	}
}

// Buttons marshal to exactly one button type: callback_data, or
// copy_text with no callback_data; style only when set.
func TestButtonJSON(t *testing.T) {
	for _, tc := range []struct {
		b    Button
		want string
	}{
		{Button{Text: "a", Data: "x"}, `{"text":"a","callback_data":"x"}`},
		{Button{Text: "a", Data: "x", Style: "danger"}, `{"text":"a","callback_data":"x","style":"danger"}`},
		{Button{Text: "📋 Copy IP", Copy: "2001:db8::1"}, `{"text":"📋 Copy IP","copy_text":{"text":"2001:db8::1"}}`},
	} {
		got, err := json.Marshal(tc.b)
		if err != nil || string(got) != tc.want {
			t.Errorf("Marshal(%+v) = %s, %v; want %s", tc.b, got, err, tc.want)
		}
	}
}

func TestSendReplyKB(t *testing.T) {
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p map[string]any
		json.NewDecoder(r.Body).Decode(&p)
		got = append(got, p)
		fmt.Fprint(w, `{"ok":true,"result":{"message_id":9}}`)
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL}

	// Only the first chunk of a split message quotes the original.
	long := strings.Repeat("line\n", 1000)
	if _, err := c.SendReplyKB(context.Background(), 42, 7, long, Keyboard{{{Text: "x", Data: "y"}}}); err != nil {
		t.Fatal(err)
	}
	if len(got) < 2 {
		t.Fatalf("want a split message, got %d sends", len(got))
	}
	rp, ok := got[0]["reply_parameters"].(map[string]any)
	if !ok || rp["message_id"].(float64) != 7 || rp["allow_sending_without_reply"] != true {
		t.Errorf("first chunk reply_parameters = %+v", got[0]["reply_parameters"])
	}
	for _, p := range got[1:] {
		if _, ok := p["reply_parameters"]; ok {
			t.Errorf("later chunk quotes the original: %+v", p)
		}
	}

	got = nil
	if _, err := c.SendMessageKB(context.Background(), 42, "hi", nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := got[0]["reply_parameters"]; ok {
		t.Errorf("a plain send must not reply: %+v", got[0])
	}
}

func TestClampKeyboardKeepsShort(t *testing.T) {
	kb := Keyboard{{{Text: "x", Data: "cr:0:abcd1234"}}}
	got := clampKeyboard(kb)
	if len(got) != 1 || got[0][0].Data != "cr:0:abcd1234" {
		t.Errorf("short button = %+v", got)
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

func TestEditMessageMarkup(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/editMessageReplyMarkup" {
			t.Errorf("path = %s", r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&got)
		fmt.Fprint(w, `{"ok":true,"result":{}}`)
	}))
	defer srv.Close()

	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL}
	kb := Keyboard{{{Text: "✅ Trusted 203.0.113.7", Data: "noop"}}}
	if err := c.EditMessageMarkup(context.Background(), 42, 7, kb); err != nil {
		t.Fatal(err)
	}
	if got["chat_id"].(float64) != 42 || got["message_id"].(float64) != 7 {
		t.Errorf("payload = %+v", got)
	}
	if _, hasText := got["text"]; hasText {
		t.Error("a markup edit must not send text: the message keeps its own")
	}
	rows := got["reply_markup"].(map[string]any)["inline_keyboard"].([]any)
	if len(rows) != 1 || rows[0].([]any)[0].(map[string]any)["callback_data"] != "noop" {
		t.Errorf("reply_markup = %+v", got["reply_markup"])
	}

	// nil removes the keyboard: an empty inline_keyboard, never a null.
	if err := c.EditMessageMarkup(context.Background(), 42, 7, nil); err != nil {
		t.Fatal(err)
	}
	if rows := got["reply_markup"].(map[string]any)["inline_keyboard"].([]any); len(rows) != 0 {
		t.Errorf("nil keyboard sent %v", rows)
	}
}

func TestFitEditShortUnchanged(t *testing.T) {
	msg := "<b>CPU</b>\n<pre>load 0.1</pre>"
	if got := FitEdit(msg); got != msg {
		t.Errorf("FitEdit changed a short message: %q", got)
	}
	exact := strings.Repeat("x", maxMessageLen)
	if got := FitEdit(exact); got != exact {
		t.Error("FitEdit cut a message exactly at the limit")
	}
}

func TestFitEditTruncatesBalanced(t *testing.T) {
	// A 10 KB view: the cut lands inside <pre>, among entities and
	// multi-byte runes, and must still parse.
	row := "web &amp; db ✅ <b>up</b> 3h — 12.5%\n"
	msg := "<b>Docker</b>\n<pre>" + strings.Repeat(row, 10240/len(row)+1) + "</pre>"
	if len(msg) < 10240 {
		t.Fatalf("fixture too short: %d", len(msg))
	}
	got := FitEdit(msg)
	if len(got) > maxMessageLen {
		t.Errorf("FitEdit length %d > %d", len(got), maxMessageLen)
	}
	if err := htmlBalanced(got); err != nil {
		t.Errorf("FitEdit result not balanced: %v", err)
	}
	if !utf8.ValidString(got) {
		t.Error("FitEdit cut mid-rune")
	}
	if !strings.HasSuffix(got, "</pre>\n… truncated") {
		t.Errorf("want closed <pre> then the footer, got …%q", got[len(got)-40:])
	}
	if !strings.HasPrefix(msg, strings.TrimSuffix(got, "</pre>\n… truncated")) {
		t.Error("FitEdit must keep the head of the message verbatim")
	}
}

func TestEditMessageKBFitsText(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		fmt.Fprint(w, `{"ok":true,"result":{}}`)
	}))
	defer srv.Close()

	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL}
	msg := "<pre>" + strings.Repeat("0123456789\n", 1000) + "</pre>"
	if err := c.EditMessageKB(context.Background(), 42, 7, msg, nil); err != nil {
		t.Fatal(err)
	}
	text, _ := got["text"].(string)
	if len(text) > maxMessageLen || !strings.HasSuffix(text, "… truncated") {
		t.Errorf("edit text len %d, tail %q", len(text), text[max(0, len(text)-20):])
	}
	if err := htmlBalanced(text); err != nil {
		t.Errorf("edit text not balanced: %v", err)
	}
}

func TestGetUpdatesParsesSender(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ok":true,"result":[
			{"update_id":1,"message":{"text":"/status","date":1,"from":{"id":42},"chat":{"id":42,"type":"private"}}},
			{"update_id":2,"message":{"text":"/update_confirm","date":1,"from":{"id":42},"chat":{"id":42,"type":"private"},
				"forward_origin":{"type":"user","date":1,"sender_user":{"id":9}},"forward_date":1}},
			{"update_id":3,"message":{"text":"/x","date":1,"from":{"id":42},"chat":{"id":42,"type":"private"},"forward_date":1}},
			{"update_id":4,"message":{"text":"/x","date":1,"from":{"id":5},"chat":{"id":-100,"type":"supergroup"},"is_automatic_forward":true}},
			{"update_id":5,"message":{"text":"/x","date":1,"from":{"id":5},"chat":{"id":42,"type":"private"},"via_bot":{"id":8}}},
			{"update_id":6,"message":{"text":"/x","date":1,"from":{"id":1087968824},"chat":{"id":-100,"type":"supergroup"},"sender_chat":{"id":-100,"type":"supergroup"}}},
			{"update_id":7,"message":{"text":"/x","date":1,"chat":{"id":42}}},
			{"update_id":8,"callback_query":{"id":"a","data":"cpu","from":{"id":5},"message":{"message_id":3,"date":1,"chat":{"id":-100,"type":"group"}}}},
			{"update_id":9,"callback_query":{"id":"b","data":"cpu","from":{"id":5},"message":{"message_id":3,"date":0,"chat":{"id":-100,"type":"group"}}}},
			{"update_id":10,"callback_query":{"id":"c","data":"cpu","from":{"id":5},"inline_message_id":"x"}}
		]}`)
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL}
	ups, err := c.GetUpdates(context.Background(), 0, time.Second)
	if err != nil || len(ups) != 10 {
		t.Fatalf("GetUpdates = %+v, %v", ups, err)
	}
	if u := ups[0]; u.FromID != 42 || u.ChatType != "private" || u.Forwarded || u.ViaBot || u.SenderChat {
		t.Errorf("plain message = %+v", u)
	}
	for i := 1; i <= 3; i++ {
		if !ups[i].Forwarded {
			t.Errorf("update %d not marked forwarded: %+v", ups[i].ID, ups[i])
		}
	}
	if !ups[4].ViaBot || ups[4].Forwarded {
		t.Errorf("via_bot = %+v", ups[4])
	}
	if !ups[5].SenderChat {
		t.Errorf("sender_chat = %+v", ups[5])
	}
	// A missing chat.type must not read as an update built in code.
	if ups[6].ChatType != "unknown" || ups[6].FromID != 0 {
		t.Errorf("typeless chat = %+v", ups[6])
	}
	if cb := ups[7].Callback; cb == nil || cb.FromID != 5 || cb.ChatType != "group" || cb.ChatID != -100 || cb.Inaccessible {
		t.Errorf("callback = %+v", cb)
	}
	if cb := ups[8].Callback; cb == nil || !cb.Inaccessible || cb.ChatID != -100 || cb.ID != "b" {
		t.Errorf("inaccessible callback = %+v", cb)
	}
	if cb := ups[9].Callback; cb == nil || !cb.Inaccessible || cb.ChatID != 0 || ups[9].ChatID != 0 || cb.ID != "c" {
		t.Errorf("message-less callback = %+v", cb)
	}
}
