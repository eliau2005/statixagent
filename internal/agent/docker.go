package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/eliau2005/statixagent/internal/alert"
)

// Container watching: /docker showed state only when asked, so a container
// dying at 3am went unnoticed until morning. dockerLoop polls once a minute
// and alerts on running→stopped, stopped→running, and restart loops.

// dockerLoop polls container state while the agent runs.
func (a *Agent) dockerLoop(ctx context.Context) {
	tick := time.NewTicker(a.dockerPoll)
	defer tick.Stop()
	a.checkContainers(ctx) // seed the baseline immediately
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			a.checkContainers(ctx)
		}
	}
}

// checkContainers diffs container states against the previous poll.
func (a *Agent) checkContainers(ctx context.Context) {
	cts, err := a.src.Docker.ListContainers(ctx)
	if err != nil {
		return // an unreachable daemon is /docker's answer, not an alert storm
	}
	now := time.Now()

	cur := make(map[string]string, len(cts))
	for _, ct := range cts {
		cur[ct.ID] = ct.State
	}
	a.mu.Lock()
	prev := a.prevContainers
	a.prevContainers = cur
	a.mu.Unlock()

	var alerts []*alert.Alert
	if prev != nil {
		for _, ct := range cts {
			was, seen := prev[ct.ID]
			switch {
			case !seen:
				// new container: baseline only
			case was == "running" && ct.State != "running":
				alerts = append(alerts, a.engine.Event("docker:"+ct.Name, "Container down",
					ct.Name+" is "+ct.State+" — "+ct.Status, alert.Critical, now, time.Minute))
			case was != "running" && ct.State == "running":
				alerts = append(alerts, a.engine.Event("docker-up:"+ct.Name, "Container up",
					ct.Name+" is running again", alert.Info, now, time.Minute))
			}
		}
	}
	for _, ct := range a.src.Docker.RestartLoops(cts) {
		alerts = append(alerts, a.engine.Event("docker-restart:"+ct.Name, "Container restarting",
			fmt.Sprintf("%s restarted (count %d) — %s", ct.Name, ct.RestartCount, ct.Status),
			alert.Warning, now, 10*time.Minute))
	}
	for _, al := range alerts {
		if al != nil {
			a.pushAlert(ctx, *al)
		}
	}
}
