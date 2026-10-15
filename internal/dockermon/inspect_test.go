package dockermon

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// List makes the one list request and no per-container inspect.
func TestListWithoutInspect(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.RequestURI())
		mu.Unlock()
		fmt.Fprint(w, listJSON)
	}))
	t.Cleanup(srv.Close)
	cts, err := New(srv.Client(), srv.URL).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cts) != 2 || cts[0].Name != "web" || cts[1].State != "restarting" || cts[1].RestartCount != 0 {
		t.Errorf("containers = %+v", cts)
	}
	if len(paths) != 1 || paths[0] != "/containers/json?all=true" {
		t.Errorf("requests = %q, want the list only", paths)
	}
}

func TestInspect(t *testing.T) {
	const id = "3f2a9b7c1d0e"
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path != "/containers/"+id+"/json" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"Id":"3f2a9b7c1d0e","RestartCount":7,"Config":{"Image":"ghcr.io/acme/web:1.4"},
			"State":{"Status":"exited","ExitCode":1,"StartedAt":"2026-10-15T12:00:00.5Z","FinishedAt":"2026-10-15T14:00:00Z",
			"Health":{"Status":"unhealthy"}}}`)
	}))
	t.Cleanup(srv.Close)
	c := New(srv.Client(), srv.URL)
	in, err := c.Inspect(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	want := Inspection{Image: "ghcr.io/acme/web:1.4", State: "exited", ExitCode: 1, Health: "unhealthy",
		StartedAt: time.Date(2026, 10, 15, 12, 0, 0, 5e8, time.UTC), FinishedAt: time.Date(2026, 10, 15, 14, 0, 0, 0, time.UTC), RestartCount: 7}
	if !in.StartedAt.Equal(want.StartedAt) || !in.FinishedAt.Equal(want.FinishedAt) {
		t.Errorf("times = %v %v", in.StartedAt, in.FinishedAt)
	}
	in.StartedAt, in.FinishedAt, want.StartedAt, want.FinishedAt = time.Time{}, time.Time{}, time.Time{}, time.Time{}
	if in != want {
		t.Errorf("inspection = %+v", in)
	}

	// Only hex IDs reach the fixed path template.
	for _, bad := range []string{"", "abc", "../../info", "3f2a9b7c1d0e/stop", strings.Repeat("a", 65), "3F2A9B7C1D0E"} {
		if _, err := c.Inspect(context.Background(), bad); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
	if len(paths) != 1 {
		t.Errorf("requests = %q", paths)
	}
}

// A container that never stopped has no FinishedAt.
func TestInspectZeroTimes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"State":{"Status":"running","StartedAt":"2026-10-15T12:00:00Z","FinishedAt":"0001-01-01T00:00:00Z"}}`)
	}))
	t.Cleanup(srv.Close)
	in, err := New(srv.Client(), srv.URL).Inspect(context.Background(), "3f2a9b7c1d0e")
	if err != nil || !in.FinishedAt.IsZero() || in.StartedAt.IsZero() || in.Health != "" {
		t.Errorf("inspection = %+v, %v", in, err)
	}
}
