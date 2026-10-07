package sshwatch

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 6, 12, 17, 0, 0, 0, time.UTC)

func TestParseLine(t *testing.T) {
	cases := []struct {
		line string
		want Event
	}{
		{
			"Jun 12 17:00:01 vps sshd[3211]: Accepted publickey for root from 203.0.113.7 port 51234 ssh2: ED25519 SHA256:abcDEF123",
			Event{Kind: EventLogin, Method: "publickey", User: "root", IP: "203.0.113.7", Port: 51234, KeyPrint: "SHA256:abcDEF123", Root: true},
		},
		{
			"Accepted password for alice from 198.51.100.3 port 40022 ssh2",
			Event{Kind: EventLogin, Method: "password", User: "alice", IP: "198.51.100.3", Port: 40022},
		},
		{
			"Jun 12 17:00:05 vps sshd-session[99]: Failed password for bob from 198.51.100.9 port 40100 ssh2",
			Event{Kind: EventFailed, Method: "password", User: "bob", IP: "198.51.100.9", Port: 40100},
		},
		{
			"Failed password for invalid user admin from 192.0.2.4 port 33000 ssh2",
			Event{Kind: EventFailed, Method: "password", User: "admin", IP: "192.0.2.4", Port: 33000, InvalidUser: true},
		},
		{
			"Invalid user oracle from 192.0.2.4 port 33001",
			Event{Kind: EventInvalidUser, User: "oracle", IP: "192.0.2.4", Port: 33001, InvalidUser: true},
		},
		{
			"Disconnected from user alice 198.51.100.3 port 40022",
			Event{Kind: EventDisconnect, User: "alice", IP: "198.51.100.3", Port: 40022},
		},
	}
	for _, tc := range cases {
		got, ok := ParseLine(tc.line, t0)
		if !ok {
			t.Errorf("ParseLine(%q) not recognized", tc.line)
			continue
		}
		tc.want.At = t0
		if got != tc.want {
			t.Errorf("ParseLine(%q)\n got %+v\nwant %+v", tc.line, got, tc.want)
		}
	}
}

func TestParseLineIgnoresNoise(t *testing.T) {
	noise := []string{
		"Jun 12 17:00:01 vps sshd[3211]: pam_unix(sshd:session): session opened for user alice",
		"Jun 12 17:00:01 vps CRON[99]: pam_unix(cron:session): session opened",
		"Server listening on 0.0.0.0 port 22.",
		"",
	}
	for _, line := range noise {
		if e, ok := ParseLine(line, t0); ok {
			t.Errorf("ParseLine(%q) = %+v, want ignored", line, e)
		}
	}
}

func TestHistory(t *testing.T) {
	h := NewHistory(3)
	for i := 0; i < 5; i++ {
		h.Add(Event{Kind: EventFailed, Port: i, At: t0.Add(time.Duration(i) * time.Minute)})
	}
	all := h.Recent(10, nil)
	if len(all) != 3 {
		t.Fatalf("ring kept %d, want 3", len(all))
	}
	if all[0].Port != 4 || all[2].Port != 2 {
		t.Errorf("order wrong: %+v", all)
	}
	fails := h.Recent(10, func(e Event) bool { return e.Port%2 == 0 })
	if len(fails) != 2 {
		t.Errorf("filtered = %+v", fails)
	}
}

func TestHistoryConcurrentAccess(t *testing.T) {
	h := NewHistory(32)
	start := make(chan struct{})
	var wg sync.WaitGroup

	for worker := 0; worker < 4; worker++ {
		wg.Add(2)
		go func(worker int) {
			defer wg.Done()
			<-start
			for i := 0; i < 1_000; i++ {
				h.Add(Event{Kind: EventFailed, Port: worker*1_000 + i})
			}
		}(worker)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 1_000; i++ {
				_ = h.Recent(16, func(e Event) bool { return e.Kind == EventFailed })
			}
		}()
	}

	close(start)
	wg.Wait()

	if got := len(h.Recent(100, nil)); got != 32 {
		t.Fatalf("ring kept %d events, want 32", got)
	}
}

func TestBruteDetector(t *testing.T) {
	b := NewBruteDetector(time.Minute, 5)
	ip := "192.0.2.4"
	for i := 0; i < 4; i++ {
		if b.Record(ip, t0.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("fired at attempt %d, threshold is 5", i+1)
		}
	}
	if !b.Record(ip, t0.Add(4*time.Second)) {
		t.Fatal("attempt 5 within window must fire")
	}
	if b.Record(ip, t0.Add(5*time.Second)) {
		t.Fatal("ongoing attack must not re-fire inside quiet period")
	}
	if b.Count(ip, t0.Add(5*time.Second)) != 6 {
		t.Errorf("count = %d, want 6", b.Count(ip, t0.Add(5*time.Second)))
	}
	// 10 minutes later the window is empty; a fresh burst fires again.
	later := t0.Add(10 * time.Minute)
	for i := 0; i < 4; i++ {
		b.Record(ip, later.Add(time.Duration(i)*time.Second))
	}
	if !b.Record(ip, later.Add(4*time.Second)) {
		t.Error("new attack after quiet period must fire again")
	}
	if b.Record("198.51.100.9", later) {
		t.Error("independent IP with one attempt must not fire")
	}
}

func TestBruteDetectorForgetsIdleIPs(t *testing.T) {
	b := NewBruteDetector(time.Minute, 5)
	// A scan: thousands of IPs, each failing once or twice, one of which
	// crosses the threshold.
	for i := 0; i < 5000; i++ {
		ip := fmt.Sprintf("203.0.%d.%d", i/256, i%256)
		at := t0.Add(time.Duration(i) * time.Millisecond)
		b.Record(ip, at)
		b.Record(ip, at)
	}
	attacker := "198.51.100.66"
	for i := 0; i < 5; i++ {
		b.Record(attacker, t0.Add(5*time.Second))
	}

	// Long after the scan, a single new attempt sweeps everything idle.
	later := t0.Add(time.Hour)
	b.Record("192.0.2.1", later)
	b.mu.Lock()
	attempts, fired := len(b.attempts), len(b.fired)
	b.mu.Unlock()
	if attempts != 1 || fired != 0 {
		t.Fatalf("after the window: %d IPs with attempts, %d with fired state; want 1 and 0", attempts, fired)
	}

	// Forgetting must not change behaviour: the attacker fires afresh.
	for i := 0; i < 4; i++ {
		if b.Record(attacker, later.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("fired at attempt %d after being forgotten", i+1)
		}
	}
	if !b.Record(attacker, later.Add(4*time.Second)) {
		t.Error("a new burst from a forgotten IP must fire")
	}
}

func TestBruteDetectorPruneOutOfOrder(t *testing.T) {
	b := NewBruteDetector(time.Minute, 3)
	ip := "198.51.100.42"
	sec := func(n int) time.Time { return t0.Add(time.Duration(n) * time.Second) }

	// Seed another IP so the first Record establishes lastSweep.
	b.Record("192.0.2.1", sec(0))
	// Fresh attempt, then an older one appended out of order so the slice's last
	// element is outside the upcoming sweep window while the max is still inside.
	b.Record(ip, sec(50))
	b.Record(ip, sec(5))

	// Sweep at 70s: cutoff is 10s. Last element (5s) is outside; max (50s) is not.
	// Using last-element prune would drop the IP; max-based prune must keep it.
	b.Record("192.0.2.2", sec(70))
	if b.Count(ip, sec(70)) != 1 {
		t.Fatalf("Count after out-of-order prune = %d, want 1 (the in-window attempt)", b.Count(ip, sec(70)))
	}
	b.Record(ip, sec(72))
	if !b.Record(ip, sec(74)) {
		t.Fatal("third in-window attempt must fire; prune must not have dropped the IP")
	}
}

func TestBruteDetectorKeepsActiveIPs(t *testing.T) {
	b := NewBruteDetector(time.Minute, 3)
	ip, other := "198.51.100.7", "192.0.2.1"
	sec := func(n int) time.Time { return t0.Add(time.Duration(n) * time.Second) }
	b.Record(other, sec(0)) // first sweep
	b.Record(ip, sec(40))
	b.Record(ip, sec(50))
	b.Record(other, sec(60)) // a full window later: sweeps, ip is still inside the window
	if !b.Record(ip, sec(70)) {
		t.Fatal("third attempt inside the window must fire across a sweep")
	}
	// Still attacking, inside the quiet period. The Record at 120s sweeps
	// again; it must not drop the fired time and allow a re-fire.
	for _, n := range []int{100, 110, 120, 130} {
		if b.Record(ip, sec(n)) {
			t.Fatalf("ongoing attack re-fired at %ds", n)
		}
	}
}

func TestParseUtmp(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(EncodeUtmpRecord(2, "", "~", "reboot", t0.Add(-time.Hour))) // BOOT_TIME, skipped
	buf.Write(EncodeUtmpRecord(7, "alice", "pts/0", "203.0.113.7", t0.Add(-30*time.Minute)))
	buf.Write(EncodeUtmpRecord(7, "root", "pts/1", "198.51.100.3", t0.Add(-time.Minute)))
	buf.Write(EncodeUtmpRecord(8, "", "pts/2", "", t0)) // DEAD_PROCESS, skipped

	sessions, err := ParseUtmp(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 {
		t.Fatalf("sessions = %+v", sessions)
	}
	if sessions[0].User != "alice" || sessions[0].TTY != "pts/0" || sessions[0].Host != "203.0.113.7" {
		t.Errorf("session 0 = %+v", sessions[0])
	}
	if !sessions[1].Since.Equal(t0.Add(-time.Minute).Truncate(time.Second)) {
		t.Errorf("since = %s", sessions[1].Since)
	}
}

func TestParseUtmpTruncated(t *testing.T) {
	if _, err := ParseUtmp(bytes.NewReader(make([]byte, 100))); err == nil {
		t.Error("truncated utmp must error")
	}
}

func TestKeysWatcher(t *testing.T) {
	dir := t.TempDir()
	keys := filepath.Join(dir, "authorized_keys")
	os.WriteFile(keys, []byte("ssh-ed25519 AAAA... user@host\n"), 0o600)
	missing := filepath.Join(dir, "ghost_keys")

	w := NewKeysWatcher([]string{keys, missing})
	if ch := w.Poll(); len(ch) != 0 {
		t.Fatalf("first poll seeds baseline, got %+v", ch)
	}
	if ch := w.Poll(); len(ch) != 0 {
		t.Fatalf("no change, got %+v", ch)
	}
	os.WriteFile(keys, []byte("ssh-ed25519 BBBB... attacker@evil\n"), 0o600)
	os.WriteFile(missing, []byte("ssh-rsa CCC...\n"), 0o600)
	ch := w.Poll()
	if len(ch) != 2 {
		t.Fatalf("changes = %+v", ch)
	}
	kinds := map[string]string{}
	for _, c := range ch {
		kinds[c.Path] = c.Kind
	}
	if kinds[keys] != "modified" || kinds[missing] != "created" {
		t.Errorf("kinds = %v", kinds)
	}
	os.Remove(keys)
	ch = w.Poll()
	if len(ch) != 1 || ch[0].Kind != "removed" {
		t.Errorf("removal = %+v", ch)
	}
}

func TestGeoResolver(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		fmt.Fprint(w, `{"status":"success","country":"Germany","city":"Falkenstein","isp":"Hetzner"}`)
	}))
	defer srv.Close()

	g := NewGeoResolver()
	g.BaseURL = srv.URL
	g.Client = srv.Client()

	info := g.Lookup(context.Background(), "203.0.113.7")
	if info.Country != "Germany" || info.City != "Falkenstein" {
		t.Errorf("info = %+v", info)
	}
	if got := info.String(); got != "Falkenstein, Germany (Hetzner)" {
		t.Errorf("String() = %q", got)
	}
	g.Lookup(context.Background(), "203.0.113.7")
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (cached)", calls)
	}
	if info := g.Lookup(context.Background(), "192.168.1.10"); info.Country != "local network" {
		t.Errorf("private IP = %+v, want local network", info)
	}
	if calls != 1 {
		t.Errorf("private IP must not hit the network")
	}
}

func TestGeoResolverCacheIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"success","country":"Germany"}`)
	}))
	defer srv.Close()

	g := NewGeoResolver()
	g.BaseURL = srv.URL
	g.Client = srv.Client()
	for i := 0; i < geoCacheMax+10; i++ {
		g.Lookup(context.Background(), fmt.Sprintf("203.0.%d.%d", i/256, i%256))
	}
	g.mu.Lock()
	n := len(g.cache)
	g.mu.Unlock()
	if n > geoCacheMax {
		t.Errorf("cache holds %d entries, cap is %d", n, geoCacheMax)
	}
}

func TestGeoResolverFailureIsQuiet(t *testing.T) {
	g := NewGeoResolver()
	g.BaseURL = "http://127.0.0.1:1"
	if info := g.Lookup(context.Background(), "203.0.113.99"); info != (GeoInfo{}) {
		t.Errorf("unreachable service must yield zero info, got %+v", info)
	}
}
