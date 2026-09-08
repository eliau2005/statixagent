package services

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

type fakeRunner map[string]string // unit name → systemctl show output

func (f fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	if name != "systemctl" || len(args) < 2 {
		return "", errors.New("unexpected command")
	}
	out, ok := f[args[1]]
	if !ok {
		return "", errors.New("systemctl failed")
	}
	return out, nil
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
