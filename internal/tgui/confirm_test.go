package tgui

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeClock is a settable clock for token expiry.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newTestTokens() (*Tokens, *fakeClock) {
	clk := &fakeClock{t: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	return NewTokens(clk.now, rand.Reader), clk
}

var testIntent = Intent{Action: "fw_close", Target: "22/tcp", ActorID: 7, ChatID: 42, MessageID: 5}

// yesArg mints a token for in and returns its Yes argument.
func yesArg(t *testing.T, tk *Tokens, in Intent) (arg, nonce string) {
	t.Helper()
	nonce, err := tk.Mint(in)
	if err != nil {
		t.Fatal(err)
	}
	return tk.Yes(nonce).Args[0], nonce
}

func TestTokenFormat(t *testing.T) {
	tk, _ := newTestTokens()
	arg, nonce := yesArg(t, tk, testIntent)
	if len(tk.Epoch()) != 4 || strings.Trim(tk.Epoch(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") != "" {
		t.Errorf("epoch %q is not 4 base32 characters", tk.Epoch())
	}
	if len(nonce) != 12 || arg != tk.Epoch()+nonce || Nonce(arg) != nonce {
		t.Errorf("arg %q nonce %q", arg, nonce)
	}
	for _, c := range []Call{tk.Yes(nonce), No(nonce)} {
		data, err := Encode(c)
		if err != nil || len(data) > 48 {
			t.Fatalf("Encode(%+v) = %q, %v", c, data, err)
		}
		if back, err := Decode(data); err != nil || back.Act != c.Act || back.Args[0] != c.Args[0] {
			t.Errorf("round trip of %q = %+v, %v", data, back, err)
		}
	}
	if other, _ := yesArg(t, tk, testIntent); other == arg {
		t.Error("two mints gave the same token")
	}
}

// TestClaim is the token suite of docs §4.4: only the asker, on the
// message it was shown on, within the TTL, once, in this boot.
func TestClaim(t *testing.T) {
	prev, _ := newTestTokens() // a previous boot
	cases := []struct {
		name  string
		press func(tk *Tokens, clk *fakeClock, arg string) (Intent, Check)
		want  Check
	}{
		{"asker on its message", func(tk *Tokens, _ *fakeClock, arg string) (Intent, Check) {
			return tk.Claim(arg, 7, 42, 5)
		}, Confirmed},
		{"just before expiry", func(tk *Tokens, clk *fakeClock, arg string) (Intent, Check) {
			clk.t = clk.t.Add(TokenTTL - time.Second)
			return tk.Claim(arg, 7, 42, 5)
		}, Confirmed},
		{"expired", func(tk *Tokens, clk *fakeClock, arg string) (Intent, Check) {
			clk.t = clk.t.Add(TokenTTL)
			return tk.Claim(arg, 7, 42, 5)
		}, Expired},
		{"wrong actor", func(tk *Tokens, _ *fakeClock, arg string) (Intent, Check) {
			return tk.Claim(arg, 8, 42, 5)
		}, WrongActor},
		{"wrong message", func(tk *Tokens, _ *fakeClock, arg string) (Intent, Check) {
			return tk.Claim(arg, 7, 42, 6)
		}, Stale},
		{"wrong chat", func(tk *Tokens, _ *fakeClock, arg string) (Intent, Check) {
			return tk.Claim(arg, 7, 43, 5)
		}, Stale},
		{"previous boot's epoch", func(tk *Tokens, _ *fakeClock, arg string) (Intent, Check) {
			other := "B" + tk.Epoch()[1:] // a live nonce under another epoch
			if tk.Epoch()[0] == 'B' {
				other = "A" + tk.Epoch()[1:]
			}
			return tk.Claim(other+Nonce(arg), 7, 42, 5)
		}, Stale},
		{"token of a previous boot", func(tk *Tokens, _ *fakeClock, _ string) (Intent, Check) {
			old, _ := yesArg(t, prev, testIntent)
			return tk.Claim(old, 7, 42, 5)
		}, Stale},
		{"unknown nonce", func(tk *Tokens, _ *fakeClock, _ string) (Intent, Check) {
			return tk.Claim(tk.Epoch()+"AAAAAAAAAAAA", 7, 42, 5)
		}, Stale},
		{"malformed", func(tk *Tokens, _ *fakeClock, arg string) (Intent, Check) {
			return tk.Claim(arg[:10], 7, 42, 5)
		}, Stale},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tk, clk := newTestTokens()
			arg, _ := yesArg(t, tk, testIntent)
			in, got := tc.press(tk, clk, arg)
			if got != tc.want {
				t.Fatalf("Claim = %v, want %v", got, tc.want)
			}
			if got == Confirmed && in != testIntent {
				t.Errorf("intent = %+v", in)
			}
		})
	}
}

// TestClaimSingleUse: the second tap never runs the action again, and a
// press by someone else leaves the token to its owner.
func TestClaimSingleUse(t *testing.T) {
	tk, clk := newTestTokens()
	arg, nonce := yesArg(t, tk, testIntent)
	if _, c := tk.Claim(arg, 8, 42, 5); c != WrongActor {
		t.Fatalf("stranger = %v", c)
	}
	if _, c := tk.Claim(arg, 7, 42, 5); c != Confirmed {
		t.Fatalf("owner after stranger = %v", c)
	}
	if _, c := tk.Claim(arg, 7, 42, 5); c != Running {
		t.Errorf("tap while running = %v", c)
	}
	if _, c := tk.Cancel(nonce, 7, 42, 5); c != Running {
		t.Errorf("cancel while running = %v", c)
	}
	tk.Finish(nonce)
	if _, c := tk.Claim(arg, 7, 42, 5); c != Done {
		t.Errorf("tap after finish = %v", c)
	}
	clk.t = clk.t.Add(TokenTTL)
	if _, c := tk.Claim(arg, 7, 42, 5); c != Expired {
		t.Errorf("tap after expiry = %v", c)
	}
	if _, c := tk.Claim(arg, 7, 42, 5); c != Stale {
		t.Errorf("expired token was kept: %v", c)
	}
}

func TestCancel(t *testing.T) {
	tk, _ := newTestTokens()
	arg, nonce := yesArg(t, tk, testIntent)
	if _, c := tk.Cancel(nonce, 8, 42, 5); c != WrongActor {
		t.Errorf("stranger cancel = %v", c)
	}
	if in, c := tk.Cancel(nonce, 7, 42, 5); c != Confirmed || in != testIntent {
		t.Fatalf("cancel = %+v, %v", in, c)
	}
	if _, c := tk.Claim(arg, 7, 42, 5); c != Stale {
		t.Errorf("Yes after cancel = %v, want Stale", c)
	}
	if _, c := tk.Cancel("short", 7, 42, 5); c != Stale {
		t.Errorf("malformed cancel = %v", c)
	}
}

func TestRebind(t *testing.T) {
	tk, _ := newTestTokens()
	in := testIntent
	in.MessageID = 0 // a typed command's prompt, not sent yet
	arg, nonce := yesArg(t, tk, in)
	if _, c := tk.Claim(arg, 7, 42, 0); c != Stale {
		t.Fatalf("claim before the prompt was bound = %v", c)
	}
	tk.Rebind(nonce, 99)
	if _, c := tk.Claim(arg, 7, 42, 5); c != Stale {
		t.Errorf("claim on the old message = %v", c)
	}
	if _, c := tk.Claim(arg, 7, 42, 99); c != Confirmed {
		t.Errorf("claim on the rebound message = %v", c)
	}
}

func TestEvictionCap(t *testing.T) {
	tk, clk := newTestTokens()
	first, _ := yesArg(t, tk, testIntent)
	clk.t = clk.t.Add(TokenTTL) // the first one expires
	second, _ := yesArg(t, tk, testIntent)
	for range maxTokens - 2 {
		yesArg(t, tk, testIntent)
	}
	if len(tk.tokens) != maxTokens || len(tk.order) != maxTokens {
		t.Fatalf("store holds %d/%d, want %d", len(tk.tokens), len(tk.order), maxTokens)
	}
	// Full: the expired token goes first, then the oldest live one.
	yesArg(t, tk, testIntent)
	if _, c := tk.Claim(first, 7, 42, 5); c != Stale {
		t.Errorf("expired token survived eviction: %v", c)
	}
	if _, c := tk.Claim(second, 7, 42, 5); c != Confirmed {
		t.Errorf("live token evicted while an expired one was there: %v", c)
	}
	yesArg(t, tk, testIntent)
	if _, c := tk.Claim(second, 7, 42, 5); c != Stale {
		t.Errorf("oldest token not evicted at the cap: %v", c)
	}
	if len(tk.tokens) != maxTokens || len(tk.order) != maxTokens {
		t.Errorf("store holds %d/%d after eviction", len(tk.tokens), len(tk.order))
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func TestMintFailure(t *testing.T) {
	tk := NewTokens(time.Now, failingReader{})
	if _, err := tk.Mint(testIntent); err == nil {
		t.Error("Mint succeeded without randomness")
	}
}

func TestMintRefusesReusedNonce(t *testing.T) {
	tk := NewTokens(time.Now, strings.NewReader(strings.Repeat("\x00", 64)))
	if _, err := tk.Mint(testIntent); err != nil {
		t.Fatal(err)
	}
	if _, err := tk.Mint(testIntent); err == nil {
		t.Error("a repeated nonce replaced a pending token")
	}
}

func TestMintTTL(t *testing.T) {
	tk, clk := newTestTokens()
	nonce, err := tk.MintTTL(testIntent, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	arg := tk.Yes(nonce).Args[0]
	clk.t = clk.t.Add(TokenTTL + time.Minute)
	if _, c := tk.Claim(arg, 7, 42, 5); c != Confirmed {
		t.Errorf("long-lived token past TokenTTL = %v, want Confirmed", c)
	}
	nonce, _ = tk.MintTTL(testIntent, 10*time.Minute)
	clk.t = clk.t.Add(10 * time.Minute)
	if _, c := tk.Claim(tk.Yes(nonce).Args[0], 7, 42, 5); c != Expired {
		t.Errorf("token past its own TTL = %v, want Expired", c)
	}
}
