package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/eliau2005/statixagent/internal/dockermon"
)

// fakeDocker is a mutable Docker Engine API: one container whose state and
// restart count tests flip between polls.
type fakeDocker struct {
	mu       sync.Mutex
	state    string
	status   string
	restarts int
}

func (f *fakeDocker) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/containers/json":
			json.NewEncoder(w).Encode([]map[string]any{{
				"Id": "abc123", "Names": []string{"/web"}, "Image": "nginx",
				"State": f.state, "Status": f.status,
			}})
		case "/containers/abc123/json":
			fmt.Fprintf(w, `{"RestartCount": %d}`, f.restarts)
		default:
			http.NotFound(w, r)
		}
	})
}

func TestDockerWatchAlerts(t *testing.T) {
	fd := &fakeDocker{state: "running", status: "Up 3 hours"}
	srv := httptest.NewServer(fd.handler())
	defer srv.Close()

	send := &fakeSender{}
	a := testAgent(send)
	a.src.Docker = dockermon.New(srv.Client(), srv.URL)
	ctx := context.Background()

	// First poll seeds the baseline silently.
	a.checkContainers(ctx)
	if got := send.all(); len(got) != 0 {
		t.Fatalf("baseline poll alerted: %v", got)
	}

	// running → exited: critical down alert.
	fd.mu.Lock()
	fd.state, fd.status = "exited", "Exited (1) 5 seconds ago"
	fd.mu.Unlock()
	a.checkContainers(ctx)
	if !send.find("Container down") || !send.find("web is exited") {
		t.Fatalf("no down alert: %v", send.all())
	}

	// exited → running: recovery notice.
	fd.mu.Lock()
	fd.state, fd.status = "running", "Up 2 seconds"
	fd.mu.Unlock()
	a.checkContainers(ctx)
	if !send.find("web is running again") {
		t.Fatalf("no up notice: %v", send.all())
	}

	// Restart count growth: restart-loop warning.
	fd.mu.Lock()
	fd.restarts = 3
	fd.mu.Unlock()
	a.checkContainers(ctx)
	if !send.find("Container restarting") || !send.find("count 3") {
		t.Fatalf("no restart alert: %v", send.all())
	}

	// A stable poll stays silent.
	before := len(send.all())
	a.checkContainers(ctx)
	if after := len(send.all()); after != before {
		t.Fatalf("stable poll alerted: %d -> %d", before, after)
	}
}
