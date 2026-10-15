package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/eliau2005/statixagent/internal/dockermon"
	"github.com/eliau2005/statixagent/internal/services"
	"github.com/eliau2005/statixagent/internal/sshwatch"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// slowOutcome checks that slow press id was answered exactly once, with
// "Working…", and returns the last edit, which carries the outcome.
func slowOutcome(t *testing.T, send *fakeSender, id string) string {
	t.Helper()
	send.mu.Lock()
	defer send.mu.Unlock()
	var answers []string
	for _, a := range send.answered {
		if strings.HasPrefix(a, id+":") {
			answers = append(answers, a)
		}
	}
	if len(answers) != 1 || answers[0] != id+":Working…" {
		t.Errorf("slow press %s answers = %v, want one Working…", id, answers)
	}
	if len(send.edits) == 0 {
		t.Fatalf("slow press %s left no edit", id)
	}
	return send.edits[len(send.edits)-1].html
}

// eventRunner logs each command into the sender's event log, so tests see
// whether the press was answered before the slow work ran.
type eventRunner struct {
	send  *fakeSender
	inner services.Runner
}

func (r eventRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	r.send.mu.Lock()
	r.send.events = append(r.send.events, "run")
	r.send.mu.Unlock()
	return r.inner.Run(ctx, name, args...)
}

func (f *fakeSender) eventLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

func TestFastViewAnsweredAfterEdit(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.handleCallback(context.Background(), &telegram.Callback{ID: "c1", ChatID: 42, MessageID: 5, Data: "cpu"})
	if got := send.eventLog(); !slices.Equal(got, []string{"edit", "answer"}) {
		t.Errorf("events = %v, want edit then answer", got)
	}
}

func TestCallbackEditFailureFallsBackToSend(t *testing.T) {
	send := &fakeSender{editErr: errors.New("Bad Request: message to edit not found")}
	a := testAgent(send)
	a.handleCallback(context.Background(), &telegram.Callback{ID: "c1", ChatID: 42, MessageID: 5, Data: "cpu"})

	if got := send.eventLog(); !slices.Equal(got, []string{"edit", "send", "answer"}) {
		t.Errorf("events = %v, want edit, send, answer", got)
	}
	send.mu.Lock()
	defer send.mu.Unlock()
	if len(send.sent) != 1 || !strings.Contains(send.sent[0], "<b>CPU</b>") {
		t.Fatalf("fallback must send the same view: %v", send.sent)
	}
	if kb := send.keyboards[0]; kb == nil || kb[len(kb)-1][2].Data != "~1v|cpu" {
		t.Errorf("fallback must keep the view's keyboard: %+v", kb)
	}
	if want := []string{"c1:" + editFailedToast}; !slices.Equal(send.answered, want) {
		t.Errorf("answered = %v, want %v", send.answered, want)
	}
}

func TestCallbackEditFailureKeepsHandlerToast(t *testing.T) {
	send := &fakeSender{editErr: errors.New("Bad Request: message to edit not found")}
	a := testAgent(send)
	live := sshTestSessions()[:1]
	a.src.Sessions = sessionsFrom(&live)
	a.handleCallback(context.Background(), &telegram.Callback{ID: "c1", ChatID: 42, MessageID: 5, Data: "sk:1"})
	send.mu.Lock()
	defer send.mu.Unlock()
	if len(send.sent) != 1 || len(send.answered) != 1 || send.answered[0] != "c1:List refreshed" {
		t.Errorf("sent = %v, answered = %v", send.sent, send.answered)
	}
}

// TestSlowCallbacksAnswerBeforeWork: a confirmed action is answered
// before its command runs, exactly once.
func TestSlowCallbacksAnswerBeforeWork(t *testing.T) {
	cases := []struct {
		name  string
		data  string // the button that opens the confirm screen
		setup func(a *Agent, send *fakeSender)
	}{
		{"firewall apply", "fw_close_ask", func(a *Agent, send *fakeSender) {
			a.src.Runner = eventRunner{send, failingUFW{}}
			allowFw(t, a)
		}},
		{"ssh kick", sessionCallbackData("sk:", 1, sshTestSessions()[0]), func(a *Agent, send *fakeSender) {
			a.src.Runner = eventRunner{send, &kickRunner{}}
			a.src.Sessions = func() ([]sshwatch.Session, error) { return sshTestSessions()[:1], nil }
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			send := &fakeSender{}
			a := testAgent(send)
			tc.setup(a, send)
			ctx := context.Background()
			a.handleCallback(ctx, &telegram.Callback{ID: "ask", ChatID: 42, MessageID: 5, Data: tc.data})
			// Both cases are double confirmed; the first Yes runs nothing.
			a.handleCallback(ctx, &telegram.Callback{ID: "yes1", ChatID: 42, MessageID: 5, Data: tokenData(lastEditKB(send), tgui.ActYes)})
			if slices.Contains(send.eventLog(), "run") {
				t.Fatalf("a confirm screen ran a command: %v", send.eventLog())
			}
			yes := tokenData(lastEditKB(send), tgui.ActYes)
			send.mu.Lock()
			send.events = nil
			send.mu.Unlock()
			a.handleCallback(ctx, &telegram.Callback{ID: "c1", ChatID: 42, MessageID: 5, Data: yes})

			events := send.eventLog()
			run := slices.Index(events, "run")
			if len(events) == 0 || events[0] != "answer" || run < 0 {
				t.Fatalf("events = %v, want the answer before any command", events)
			}
			if n := strings.Count(strings.Join(events, ","), "answer"); n != 1 {
				t.Errorf("answered %d times: %v", n, events)
			}
			slowOutcome(t, send, "c1")
		})
	}
}

func TestDockerViewAnsweredBeforeAPICall(t *testing.T) {
	send := &fakeSender{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		send.mu.Lock()
		send.events = append(send.events, "run")
		send.mu.Unlock()
		w.Write([]byte("[]"))
	}))
	defer srv.Close()
	a := testAgent(send)
	a.src.Docker = dockermon.New(srv.Client(), srv.URL)
	a.cfg.Monitors.Docker = true

	a.handleCallback(context.Background(), &telegram.Callback{ID: "c1", ChatID: 42, MessageID: 5, Data: "docker"})
	if got := send.eventLog(); len(got) < 3 || got[0] != "answer" || got[1] != "run" || got[len(got)-1] != "edit" {
		t.Errorf("events = %v, want answer, API call, edit", got)
	}
	send.mu.Lock()
	defer send.mu.Unlock()
	if !slices.Equal(send.answered, []string{"c1:"}) {
		t.Errorf("answered = %v", send.answered)
	}
}

// TestSlowOutcomeBecomesBanner: a slow action's result can no longer be a
// toast, so it heads the edited view; values in it are escaped.
func TestSlowOutcomeBecomesBanner(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	s := sshTestSessions()[0]
	s.User = "<evil>"
	a.src.Sessions = func() ([]sshwatch.Session, error) { return []sshwatch.Session{s, sshTestSessions()[1]}, nil }
	a.src.Runner = &kickRunner{}
	id := confirmThrough(t, a, send, sessionCallbackData("sk:", 1, s), 5)
	out := slowOutcome(t, send, id)
	if !strings.HasPrefix(out, "🧾 &lt;evil&gt; disconnected · &lt;evil&gt; pts/0 from 10.0.0.5 · ") {
		t.Errorf("outcome receipt = %q", out)
	}
}

// TestEveryCallbackAnsweredOnce covers each routing branch, with the edit
// both working and failing.
func TestEveryCallbackAnsweredOnce(t *testing.T) {
	datas := []string{
		"cpu", "status", "ssh", "sk:1", "skk:1:zzzzzzzzzzzzzzzz", "firewall", "fw_close_ask",
		"fw_close", "settings", "watching", "dismiss", "live_stop", "snz:d:cpu", "snz:h:",
		"docker", "no_such_action", "noop", "update_confirm", cbUpdateYes, cbClearYes, cbClearNo,
		"~1y|AAAAAAAAAAAAAAAA", "~1y|short", "~1y", "~1n|AAAAAAAAAAAA", "~1n",
	}
	for _, editErr := range []error{nil, errors.New("Bad Request: message to edit not found")} {
		for _, data := range datas {
			send := &fakeSender{editErr: editErr}
			a := testAgent(send)
			a.src.Runner = failingUFW{}
			a.handleCallback(context.Background(), &telegram.Callback{ID: "c1", ChatID: 42, MessageID: 5, Data: data})
			send.mu.Lock()
			if len(send.answered) != 1 {
				t.Errorf("%q (editErr=%v): answered %v, want exactly once", data, editErr, send.answered)
			}
			send.mu.Unlock()
		}
	}
}
