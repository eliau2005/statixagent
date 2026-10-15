package dockermon

import (
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// recorder answers every request with status and body, recording
// "METHOD uri".
type recorder struct {
	mu     sync.Mutex
	status int
	body   []byte
	reqs   []string
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, req.Method+" "+req.URL.RequestURI())
	w.WriteHeader(r.status)
	w.Write(r.body)
}

func newRecorder(t *testing.T, status int, body []byte) (*Client, *recorder) {
	t.Helper()
	rec := &recorder{status: status, body: body}
	srv := httptest.NewServer(rec)
	t.Cleanup(srv.Close)
	return New(srv.Client(), srv.URL), rec
}

const actID = "3f2a9b7c1d0e"

func TestAct(t *testing.T) {
	for _, tc := range []struct {
		verb, want string
		status     int
		wantErr    string
	}{
		{"start", "POST /containers/3f2a9b7c1d0e/start", 204, ""},
		{"start", "POST /containers/3f2a9b7c1d0e/start", 304, ""},
		{"stop", "POST /containers/3f2a9b7c1d0e/stop?t=10", 204, ""},
		{"restart", "POST /containers/3f2a9b7c1d0e/restart?t=10", 204, ""},
		{"restart", "POST /containers/3f2a9b7c1d0e/restart?t=10", 500, "cannot restart <it>"},
	} {
		c, rec := newRecorder(t, tc.status, []byte(`{"message":"cannot restart <it>"}`))
		err := c.Act(context.Background(), actID, tc.verb)
		if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("%s (%d): err = %v, want %q", tc.verb, tc.status, err, tc.wantErr)
		}
		if !slices.Equal(rec.reqs, []string{tc.want}) {
			t.Errorf("%s: requests %q, want %q", tc.verb, rec.reqs, tc.want)
		}
	}
}

// Only the fixed templates, with a hex ID, are ever posted.
func TestActRefusesBadInput(t *testing.T) {
	c, rec := newRecorder(t, 204, nil)
	for _, tc := range [][2]string{
		{actID, "kill"}, {actID, "remove"}, {actID, "start?x=1"}, {actID, ""},
		{"web", "start"}, {"3F2A9B7C1D0E", "start"}, {"3f2a9b7c1d0", "start"},
		{"3f2a9b7c1d0e/../../images", "start"}, {actID + "?force=1", "stop"},
	} {
		if err := c.Act(context.Background(), tc[0], tc[1]); err == nil {
			t.Errorf("Act(%q, %q) succeeded", tc[0], tc[1])
		}
	}
	if len(rec.reqs) != 0 {
		t.Errorf("requests %q, want none", rec.reqs)
	}
}

// frame is one multiplexed log frame of stream (1 stdout, 2 stderr).
func frame(stream byte, s string) []byte {
	h := make([]byte, 8, 8+len(s))
	h[0] = stream
	binary.BigEndian.PutUint32(h[4:], uint32(len(s)))
	return append(h, s...)
}

func TestLogs(t *testing.T) {
	framed := slices.Concat(frame(1, "started\n"), frame(2, "oops <b>\n"), frame(1, "ready\n"))
	for _, tc := range []struct {
		name string
		body []byte
		want string
	}{
		{"framed", framed, "started\noops <b>\nready\n"},
		{"tty", []byte("raw tty output\n"), "raw tty output\n"},
		{"cut frame", append(frame(1, "a\n"), frame(2, "partial line")[:12]...), "a\npart"},
		{"empty", nil, ""},
	} {
		c, rec := newRecorder(t, 200, tc.body)
		got, err := c.Logs(context.Background(), actID)
		if err != nil || got != tc.want {
			t.Errorf("%s: Logs = %q, %v; want %q", tc.name, got, err, tc.want)
		}
		if want := "GET /containers/3f2a9b7c1d0e/logs?stdout=true&stderr=true&tail=30"; !slices.Equal(rec.reqs, []string{want}) {
			t.Errorf("%s: requests %q", tc.name, rec.reqs)
		}
	}
	c, rec := newRecorder(t, 200, nil)
	if _, err := c.Logs(context.Background(), "../images"); err == nil || len(rec.reqs) != 0 {
		t.Errorf("an invalid ID was requested: %v %q", err, rec.reqs)
	}
}

func TestSelfID(t *testing.T) {
	id := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		name  string
		texts []string
		want  string
	}{
		{"cgroup v1", []string{"12:memory:/docker/" + id + "\n0::/\n"}, id},
		{"systemd driver", []string{"0::/system.slice/docker-" + id + ".scope\n"}, id},
		{"mountinfo", []string{"0::/\n", "123 98 8:1 /var/lib/docker/containers/" + id + "/hostname /etc/hostname rw - ext4\n"}, id},
		{"host", []string{"0::/system.slice/statix-agent.service\n", "22 1 8:1 / / rw - ext4 /dev/sda1\n"}, ""},
		{"short ID only", []string{"0::/docker/3f2a9b7c1d0e\n"}, ""},
	} {
		if got := SelfID(tc.texts...); got != tc.want {
			t.Errorf("%s: SelfID = %q, want %q", tc.name, got, tc.want)
		}
	}
}
