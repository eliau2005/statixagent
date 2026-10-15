package dockermon

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Container actions (docs/telegram-ux-redesign.md §6). The only POSTs the
// client makes go to these fixed templates, with a hex container ID: no
// name, query or body from the user ever reaches the daemon.
var actionPaths = map[string]string{
	"start":   "/containers/%s/start",
	"stop":    "/containers/%s/stop?t=10",
	"restart": "/containers/%s/restart?t=10",
}

const (
	// actTimeout bounds one action: the 10 s stop grace plus 30 s.
	actTimeout = 40 * time.Second
	// maxLogs caps the log bytes read; the view shows far fewer.
	maxLogs = 64 << 10
	// logTail is how many lines Logs asks for.
	logTail = 30
)

// ActionPath is the request path of verb on the container with ID id;
// ok is false for any other verb or a malformed ID.
func ActionPath(id, verb string) (path string, ok bool) {
	tmpl, ok := actionPaths[verb]
	if !ok || !idRE.MatchString(id) {
		return "", false
	}
	return fmt.Sprintf(tmpl, id), true
}

// Act starts, stops or restarts the container with ID id. Docker answers
// 304 when there is nothing to do (starting a running container), which
// is success too.
func (c *Client) Act(ctx context.Context, id, verb string) error {
	path, ok := ActionPath(id, verb)
	if !ok {
		return fmt.Errorf("docker: refusing %q on container %q", verb, id)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, nil)
	if err != nil {
		return err
	}
	// A stop waits up to 10 s for the container: longer than reads may.
	hc := *c.http
	hc.Timeout = actTimeout
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("docker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		return nil
	}
	return fmt.Errorf("docker: %s %s", resp.Status, daemonMessage(resp.Body))
}

// daemonMessage is the "message" of a Docker error body, short.
func daemonMessage(body io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(body, 512))
	var e struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(b, &e) == nil && e.Message != "" {
		return e.Message
	}
	return strings.TrimSpace(string(b))
}

// Logs reads the last lines a container wrote to stdout and stderr.
func (c *Client) Logs(ctx context.Context, id string) (string, error) {
	if !idRE.MatchString(id) {
		return "", fmt.Errorf("docker: invalid container ID")
	}
	path := fmt.Sprintf("/containers/%s/logs?stdout=true&stderr=true&tail=%d", id, logTail)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("docker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("docker: logs returned %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxLogs))
	if err != nil {
		return "", fmt.Errorf("docker: %w", err)
	}
	return demux(raw), nil
}

// demux strips the 8-byte frame headers Docker puts on the logs of a
// container without a TTY (stream, three zero bytes, big-endian size).
// A TTY container's logs are raw, and pass through as they are.
func demux(raw []byte) string {
	var out bytes.Buffer
	for b := raw; len(b) > 0; {
		if len(b) < 8 || b[0] > 2 || b[1] != 0 || b[2] != 0 || b[3] != 0 {
			if out.Len() == 0 {
				return string(raw) // not framed at all
			}
			out.Write(b) // a frame cut by maxLogs
			break
		}
		n := int(binary.BigEndian.Uint32(b[4:8]))
		b = b[8:]
		n = min(n, len(b))
		out.Write(b[:n])
		b = b[n:]
	}
	return out.String()
}

// selfRE finds a container ID in /proc/self/cgroup ("…/docker/<id>",
// "docker-<id>.scope") or /proc/self/mountinfo (".../containers/<id>/").
var selfRE = regexp.MustCompile(`(?:docker[-/]|/containers/)([a-f0-9]{64})\b`)

// SelfID returns the full ID of the container the agent runs in, read
// from the text of /proc/self/cgroup and /proc/self/mountinfo, or "" when
// it runs on the host.
func SelfID(procTexts ...string) string {
	for _, s := range procTexts {
		if m := selfRE.FindStringSubmatch(s); m != nil {
			return m[1]
		}
	}
	return ""
}
