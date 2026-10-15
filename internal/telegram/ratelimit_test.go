package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock advances only when slept on, so pacing and retry waits are
// asserted exactly and no test sleeps for real.
type fakeClock struct {
	mu    sync.Mutex
	t     time.Time
	slept []time.Duration
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func (f *fakeClock) clock() clock { return clock{now: f.now, sleep: f.sleep} }

func (f *fakeClock) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.slept = append(f.slept, d)
	f.t = f.t.Add(d)
	return nil
}

func (f *fakeClock) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

func (f *fakeClock) sleeps() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Duration(nil), f.slept...)
}

func TestChatLimiterBurstThenPaces(t *testing.T) {
	clk := newFakeClock()
	l := newChatLimiter(time.Second, 3, clk.clock())
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := l.wait(ctx, 42); err != nil {
			t.Fatal(err)
		}
	}
	if got := fmt.Sprint(clk.sleeps()); got != "[1s 1s]" {
		t.Errorf("sleeps after a burst of 5 = %s, want [1s 1s]", got)
	}

	// Another chat has its own bucket.
	if err := l.wait(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if n := len(clk.sleeps()); n != 2 {
		t.Errorf("chat 7 waited on chat 42's budget: %v", clk.sleeps())
	}

	// A long idle refills to the burst, not beyond it.
	clk.advance(time.Hour)
	for i := 0; i < 4; i++ {
		if err := l.wait(ctx, 42); err != nil {
			t.Fatal(err)
		}
	}
	if got := fmt.Sprint(clk.sleeps()); got != "[1s 1s 1s]" {
		t.Errorf("sleeps after idle = %s, want one more 1s", got)
	}
}

func TestChatLimiterCanceledWaitRefunds(t *testing.T) {
	clk := newFakeClock()
	l := newChatLimiter(time.Second, 1, clk.clock())
	if err := l.wait(context.Background(), 42); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.wait(ctx, 42); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	// The canceled reservation is returned: the next send waits one
	// interval, not two.
	if err := l.wait(context.Background(), 42); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(clk.sleeps()); got != "[1s]" {
		t.Errorf("sleeps = %s, want [1s]", got)
	}
}

func TestChatLimiterConcurrent(t *testing.T) {
	clk := newFakeClock()
	l := newChatLimiter(time.Second, 3, clk.clock())
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.wait(context.Background(), 42); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	// Every caller gets through, and 20 sends with a burst of 3 at 1/s
	// cannot finish in under 17s of (fake) time.
	var total time.Duration
	for _, d := range clk.sleeps() {
		total += d
	}
	if total < 17*time.Second {
		t.Errorf("20 sends paced over %v, want at least 17s: %v", total, clk.sleeps())
	}
}

// countingServer replies with reply(n) for the n-th request (from 1).
func countingServer(t *testing.T, reply func(n int32, w http.ResponseWriter)) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reply(n.Add(1), w)
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

const tooMany = `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 3","parameters":{"retry_after":3}}`

func write429(w http.ResponseWriter, body string) {
	w.WriteHeader(http.StatusTooManyRequests)
	fmt.Fprint(w, body)
}

func TestClientPacesSendsWithoutDropping(t *testing.T) {
	srv, n := countingServer(t, func(_ int32, w http.ResponseWriter) {
		fmt.Fprint(w, `{"ok":true,"result":{"message_id":1}}`)
	})
	clk := newFakeClock()
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, limiter: newChatLimiter(time.Second, 3, clk.clock())}
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if err := c.SendMessage(ctx, 42, "alert"); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.EditMessageKB(ctx, 42, 1, "view", nil); err != nil {
		t.Fatal(err)
	}
	// Answers are not paced: they only stop the button spinner.
	if err := c.AnswerCallback(ctx, "cb", ""); err != nil {
		t.Fatal(err)
	}
	if n.Load() != 6 {
		t.Errorf("requests = %d, want 6: nothing may be dropped", n.Load())
	}
	if got := fmt.Sprint(clk.sleeps()); got != "[1s 1s]" {
		t.Errorf("sleeps = %s, want [1s 1s]", got)
	}
}

func TestRetryOnceOn429(t *testing.T) {
	ctx := context.Background()
	retried := []struct {
		method string
		run    func(*Client) error
	}{
		{"sendMessage", func(c *Client) error { return c.SendMessage(ctx, 42, "hi") }},
		{"editMessageText", func(c *Client) error { return c.EditMessageKB(ctx, 42, 1, "hi", nil) }},
		{"editMessageReplyMarkup", func(c *Client) error { return c.EditMessageMarkup(ctx, 42, 1, nil) }},
		{"answerCallbackQuery", func(c *Client) error { return c.AnswerCallback(ctx, "cb", "ok") }},
	}
	for _, tc := range retried {
		t.Run(tc.method, func(t *testing.T) {
			srv, n := countingServer(t, func(n int32, w http.ResponseWriter) {
				if n == 1 {
					write429(w, tooMany)
					return
				}
				fmt.Fprint(w, `{"ok":true,"result":{"message_id":5}}`)
			})
			clk := newFakeClock()
			c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, clock: clk.clock()}
			if err := tc.run(c); err != nil {
				t.Fatalf("err = %v, want success after one retry", err)
			}
			if n.Load() != 2 {
				t.Errorf("requests = %d, want 2", n.Load())
			}
			if got := fmt.Sprint(clk.sleeps()); got != "[3s]" {
				t.Errorf("sleeps = %s, want [3s] (retry_after)", got)
			}
		})
	}

	notRetried := []struct {
		method string
		run    func(*Client) error
	}{
		{"getUpdates", func(c *Client) error { _, err := c.GetUpdates(ctx, 0, time.Second); return err }},
		{"deleteMessages", func(c *Client) error { return c.DeleteMessages(ctx, 42, []int64{1}) }},
		{"setMyCommands", func(c *Client) error { return c.SetMyCommands(ctx, []BotCommand{{Command: "status"}}) }},
	}
	for _, tc := range notRetried {
		t.Run(tc.method, func(t *testing.T) {
			srv, n := countingServer(t, func(_ int32, w http.ResponseWriter) { write429(w, tooMany) })
			clk := newFakeClock()
			c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, clock: clk.clock()}
			err := tc.run(c)
			if wait, ok := RetryAfter(err); !ok || wait != 3*time.Second {
				t.Errorf("RetryAfter(%v) = %v, %v; want 3s, true", err, wait, ok)
			}
			if n.Load() != 1 || len(clk.sleeps()) != 0 {
				t.Errorf("requests = %d, sleeps = %v; want 1 and none", n.Load(), clk.sleeps())
			}
		})
	}
}

func TestRetryOn429Limits(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		requests int32
		sleeps   string
	}{
		{"second 429 is returned", tooMany, 2, "[3s]"},
		{"flood ban is not waited out", `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 600","parameters":{"retry_after":600}}`, 1, "[]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, n := countingServer(t, func(_ int32, w http.ResponseWriter) { write429(w, tc.body) })
			clk := newFakeClock()
			c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, clock: clk.clock()}
			err := c.SendMessage(context.Background(), 42, "hi")
			var ae *APIError
			if !errors.As(err, &ae) || ae.Code != 429 {
				t.Fatalf("err = %v, want a 429 *APIError", err)
			}
			if n.Load() != tc.requests || fmt.Sprint(clk.sleeps()) != tc.sleeps {
				t.Errorf("requests = %d, sleeps = %v; want %d, %s", n.Load(), clk.sleeps(), tc.requests, tc.sleeps)
			}
		})
	}
}

func TestAPIErrorFields(t *testing.T) {
	srv, _ := countingServer(t, func(_ int32, w http.ResponseWriter) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`)
	})
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL}
	err := c.SendMessage(context.Background(), 1, "x")
	if err == nil || err.Error() != "telegram: sendMessage: Bad Request: chat not found" {
		t.Errorf("err = %v, want the same text as before APIError", err)
	}
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != 400 || ae.RetryAfter != 0 {
		t.Errorf("APIError = %+v", ae)
	}
	if _, ok := RetryAfter(err); ok {
		t.Error("a 400 is not a 429")
	}
}

func TestIsMessageNotFound(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{&APIError{Code: 400, Description: "Bad Request: message to edit not found"}, true},
		{fmt.Errorf("telegram: editMessageText: %w", &APIError{Code: 400, Description: "Bad Request: message not found"}), true},
		{&APIError{Code: 400, Description: "Bad Request: MESSAGE_ID_INVALID"}, true},
		{&APIError{Code: 400, Description: "Bad Request: chat not found"}, false},
		{&APIError{Code: 429, Description: "Too Many Requests: retry after 3"}, false},
		{errors.New("Bad Request: message to edit not found"), false},
		{nil, false},
	}
	for _, tc := range cases {
		if got := IsMessageNotFound(tc.err); got != tc.want {
			t.Errorf("IsMessageNotFound(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestEditNotModifiedIsSuccess(t *testing.T) {
	srv, _ := countingServer(t, func(_ int32, w http.ResponseWriter) {
		fmt.Fprint(w, `{"ok":false,"error_code":400,"description":"Bad Request: message is not modified: specified new message content and reply markup are exactly the same"}`)
	})
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL}
	if err := c.EditMessageKB(context.Background(), 42, 1, "same", nil); err != nil {
		t.Errorf("EditMessageKB = %v", err)
	}
	if err := c.EditMessageMarkup(context.Background(), 42, 1, nil); err != nil {
		t.Errorf("EditMessageMarkup = %v", err)
	}
}

func TestLinkPreviewOptions(t *testing.T) {
	var mu sync.Mutex
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		got = append(got, body)
		mu.Unlock()
		fmt.Fprint(w, `{"ok":true,"result":{}}`)
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL}
	ctx := context.Background()
	if err := c.SendMessage(ctx, 42, "https://example.com"); err != nil {
		t.Fatal(err)
	}
	if err := c.EditMessageKB(ctx, 42, 1, "https://example.com", nil); err != nil {
		t.Fatal(err)
	}
	for i, body := range got {
		if _, old := body["disable_web_page_preview"]; old {
			t.Errorf("request %d still sends the deprecated flag", i)
		}
		opts, _ := body["link_preview_options"].(map[string]any)
		if opts["is_disabled"] != true {
			t.Errorf("request %d link_preview_options = %v", i, body["link_preview_options"])
		}
	}
}

// TestErrorPathsRedactToken covers the error exits that do not involve a
// transport failure (those are in TestTransportErrorRedactsToken).
func TestErrorPathsRedactToken(t *testing.T) {
	cases := []struct {
		name  string
		reply func(w http.ResponseWriter)
	}{
		{"api error echoing the token", func(w http.ResponseWriter) {
			fmt.Fprintf(w, `{"ok":false,"error_code":400,"description":"Bad Request: bot%s"}`, fakeToken)
		}},
		{"non-JSON body", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, "<html>bad gateway bot%s</html>", fakeToken)
		}},
		{"malformed result", func(w http.ResponseWriter) { fmt.Fprint(w, `{"ok":true,"result":"x"}`) }},
		{"429 after the retry", func(w http.ResponseWriter) { write429(w, tooMany) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := countingServer(t, func(_ int32, w http.ResponseWriter) { tc.reply(w) })
			clk := newFakeClock()
			c := &Client{HTTP: srv.Client(), BaseURL: srv.URL + "/bot" + fakeToken, clock: clk.clock()}
			_, err := c.SendMessageID(context.Background(), 42, "hi")
			if err == nil {
				t.Fatal("expected an error")
			}
			if strings.Contains(err.Error(), fakeToken) || strings.Contains(fmt.Sprintf("%+v", err), fakeToken) {
				t.Errorf("token leaked: %v", err)
			}
			if !strings.HasPrefix(err.Error(), "telegram: sendMessage: ") {
				t.Errorf("error missing method context: %v", err)
			}
			var ae *APIError
			if errors.As(err, &ae) && strings.Contains(ae.Description, fakeToken) {
				t.Errorf("APIError.Description leaked the token: %q", ae.Description)
			}
		})
	}
}
