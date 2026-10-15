package services

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

type fakeRunner map[string]string // unit name → systemctl show output

func (f fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	// The unit always comes last, after "--", so it cannot be an option.
	if name != "systemctl" || len(args) < 3 || args[0] != "show" || args[len(args)-2] != "--" {
		return "", errors.New("unexpected command")
	}
	out, ok := f[args[len(args)-1]]
	if !ok {
		return "", errors.New("systemctl failed")
	}
	return out, nil
}

type recordingRunner struct{ calls [][]string }

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	return "ActiveState=active\nSubState=running\n", nil
}

func TestCmdEnvIsMinimal(t *testing.T) {
	t.Setenv("LC_ALL", "fr_FR.UTF-8")
	t.Setenv("LANG", "fr_FR.UTF-8")
	t.Setenv("LANGUAGE", "fr_FR:fr")
	t.Setenv("TELEGRAM_TOKEN", "123:secret")
	t.Setenv("PATH", "/usr/sbin:/usr/bin")

	// ufw ships translations; a parser reading "Statut : actif" reports a
	// healthy firewall as unreadable. Python's gettext reads LANGUAGE
	// before LC_ALL and does not suppress it for a C locale, so it must be
	// cleared too. Nothing else from the agent's environment is passed on.
	want := []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C", "LANG=C", "LANGUAGE="}
	if got := cmdEnv(); !slices.Equal(got, want) {
		t.Errorf("cmdEnv = %q, want %q", got, want)
	}

	t.Setenv("PATH", "")
	if got := cmdEnv()[0]; got != "PATH="+defaultPath {
		t.Errorf("cmdEnv without PATH = %q, want the default", got)
	}
}

func TestValidUnitName(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"nginx.service", true},
		{"getty@tty1.service", true},
		{"systemd-journald.socket", true},
		{"apt-daily.timer", true},
		{"user-1000.slice:x.service", true},
		{"--host=x.service", false},
		{"-H.service", false},
		{"--host=x", false},
		{"nginx", false},
		{"nginx.mount", false},
		{"", false},
		{".service", false},
		{"a b.service", false},
		{"a/b.service", false},
		{"nginx.service\n", false},
		{strings.Repeat("a", 251) + ".service", true},
		{strings.Repeat("a", 252) + ".service", false},
	} {
		if got := ValidUnitName(tc.name); got != tc.want {
			t.Errorf("ValidUnitName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCheckSystemdUnits(t *testing.T) {
	r := fakeRunner{
		"nginx.service":    "ActiveState=active\nSubState=running\nNRestarts=0\n",
		"postgres.service": "ActiveState=failed\nSubState=failed\nNRestarts=4\n",
		"flaky.service":    "ActiveState=active\nSubState=running\nNRestarts=7\n",
	}
	got := CheckSystemdUnits(context.Background(), r,
		[]string{"nginx.service", "postgres.service", "flaky.service", "gone.service"})
	want := map[string]State{
		"nginx.service":    StateOK,
		"postgres.service": StateDown,
		"flaky.service":    StateOK,
		"gone.service":     StateUnknown,
	}
	for _, res := range got {
		if res.State != want[res.Name] {
			t.Errorf("%s = %s (%s), want %s", res.Name, res.State, res.Detail, want[res.Name])
		}
	}
	for _, res := range got {
		if res.Name == "flaky.service" && !strings.Contains(res.Detail, "restarts=7") {
			t.Errorf("flaky detail = %q, want restart count surfaced", res.Detail)
		}
	}
}

func TestCheckSystemdUnitsRejectsInvalidNames(t *testing.T) {
	r := &recordingRunner{}
	got := CheckSystemdUnits(context.Background(), r, []string{"--host=x", "nginx.service"})
	if len(got) != 2 {
		t.Fatalf("got %d results, want 2", len(got))
	}
	// An invalid name already in the config is reported, not executed.
	if got[0].State != StateUnknown || got[0].Detail != "invalid unit name" {
		t.Errorf("--host=x = %+v, want unknown/invalid unit name", got[0])
	}
	if got[1].State != StateOK {
		t.Errorf("nginx.service = %+v, want ok", got[1])
	}
	want := [][]string{{"systemctl", "show",
		"--property=ActiveState,SubState,NRestarts", "--no-pager", "--no-ask-password", "--", "nginx.service"}}
	if len(r.calls) != 1 || !slices.Equal(r.calls[0], want[0]) {
		t.Errorf("calls = %q, want %q", r.calls, want)
	}
}

func TestCheckSystemdUnitsBareName(t *testing.T) {
	r := &recordingRunner{}
	got := CheckSystemdUnits(context.Background(), r, []string{"nginx"})
	// A bare name from a hand-edited config is queried as a .service, as
	// systemctl itself would, and still reported under the configured name.
	if len(got) != 1 || got[0].Name != "nginx" || got[0].State != StateOK {
		t.Fatalf("got %+v, want nginx ok", got)
	}
	want := []string{"systemctl", "show",
		"--property=ActiveState,SubState,NRestarts", "--no-pager", "--no-ask-password", "--", "nginx.service"}
	if len(r.calls) != 1 || !slices.Equal(r.calls[0], want) {
		t.Errorf("calls = %q, want %q", r.calls, want)
	}
}

func TestCheckProcesses(t *testing.T) {
	proc := fstest.MapFS{
		"1/comm":    {Data: []byte("systemd\n")},
		"422/comm":  {Data: []byte("nginx\n")},
		"423/comm":  {Data: []byte("nginx\n")},
		"9001/comm": {Data: []byte("longprocessname\n")}, // comm truncates at 15
		"foo/comm":  {Data: []byte("notapid\n")},         // non-numeric, ignored by glob
	}
	got := CheckProcesses(proc, []string{"nginx", "postgres", "longprocessnametruncated"})
	byName := map[string]Result{}
	for _, r := range got {
		byName[r.Name] = r
	}
	if r := byName["nginx"]; r.State != StateOK || r.Detail != "2 running" {
		t.Errorf("nginx = %+v", r)
	}
	if r := byName["postgres"]; r.State != StateDown {
		t.Errorf("postgres = %+v", r)
	}
	if r := byName["longprocessnametruncated"]; r.State != StateOK {
		t.Errorf("truncated comm match failed: %+v", r)
	}
}

func TestCheckPorts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	openPort := ln.Addr().(*net.TCPAddr).Port

	var d net.Dialer
	got := CheckPorts(context.Background(), d.DialContext, []PortSpec{
		{Port: openPort, Label: "test-listener"},
		{Port: 1}, // nothing listens on tcpmux
	})
	if got[0].State != StateOK || got[0].Name != "test-listener" {
		t.Errorf("open port = %+v", got[0])
	}
	if got[1].State != StateDown || got[1].Name != "port 1" {
		t.Errorf("closed port = %+v", got[1])
	}
}

func TestCheckHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(200)
		case "/redirect":
			http.Redirect(w, r, "/ok", http.StatusMovedPermanently)
		case "/teapot":
			w.WriteHeader(418)
		}
	}))
	defer srv.Close()

	got := CheckHTTP(context.Background(), srv.Client(), []HTTPSpec{
		{URL: srv.URL + "/ok"},
		{URL: srv.URL + "/redirect", ExpectStatus: http.StatusMovedPermanently},
		{URL: srv.URL + "/redirect", ExpectStatus: http.StatusOK},
		{URL: srv.URL + "/teapot", ExpectStatus: 418},
		{URL: srv.URL + "/teapot", ExpectStatus: 200},
		{URL: "http://127.0.0.1:9/down", Timeout: 2 * time.Second},
	})
	wantStates := []State{StateOK, StateOK, StateDegraded, StateOK, StateDegraded, StateDown}
	for i, w := range wantStates {
		if got[i].State != w {
			t.Errorf("check %d (%s) = %s (%s), want %s", i, got[i].Name, got[i].State, got[i].Detail, w)
		}
	}
	if !strings.Contains(got[2].Detail, "got 301, want 200") {
		t.Errorf("redirect mismatch detail = %q", got[2].Detail)
	}
	if !strings.Contains(got[4].Detail, "got 418, want 200") {
		t.Errorf("mismatch detail = %q", got[4].Detail)
	}

	// Nil client should default safely without panic.
	nilClientGot := CheckHTTP(context.Background(), nil, []HTTPSpec{
		{URL: srv.URL + "/ok"},
	})
	if len(nilClientGot) != 1 || nilClientGot[0].State != StateOK {
		t.Errorf("nil client check failed: %+v", nilClientGot)
	}
}
