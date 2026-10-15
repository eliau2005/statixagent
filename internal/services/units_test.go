package services

import (
	"context"
	"slices"
	"testing"
	"time"
)

// listRunner answers list-units with list and show with show, recording
// every call.
type listRunner struct {
	list, show string
	calls      [][]string
}

func (r *listRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	if args[0] == "list-units" {
		return r.list, nil
	}
	return r.show, nil
}

func TestListUnits(t *testing.T) {
	r := &listRunner{list: "" +
		"cron.service loaded active running Regular background program processing daemon\n" +
		"● postgresql.service loaded failed failed PostgreSQL RDBMS\n" +
		"systemd-fsck@dev-disk-by\\x2duuid-1.service loaded inactive dead File System Check\n" +
		"--host=evil.service loaded active running forged\n" +
		"truncated.serv\n"}
	units, err := ListUnits(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	want := []Unit{
		{Name: "cron.service", Load: "loaded", Active: "active", Sub: "running", Description: "Regular background program processing daemon"},
		{Name: "postgresql.service", Load: "loaded", Active: "failed", Sub: "failed", Description: "PostgreSQL RDBMS"},
		{Name: `systemd-fsck@dev-disk-by\x2duuid-1.service`, Load: "loaded", Active: "inactive", Sub: "dead", Description: "File System Check"},
	}
	if !slices.Equal(units, want) {
		t.Errorf("units = %+v", units)
	}
	// One call, argv only, with nothing a unit name could inject into.
	if len(r.calls) != 1 || !slices.Equal(r.calls[0], []string{"systemctl", "list-units", "--all",
		"--type=service,socket,timer", "--no-legend", "--plain", "--no-pager", "--no-ask-password"}) {
		t.Errorf("calls = %q", r.calls)
	}
}

func TestShowUnit(t *testing.T) {
	r := &listRunner{show: "LoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\n" +
		"UnitFileState=enabled\nStateChangeTimestamp=Thu 2026-10-15 12:41:00 UTC\nNRestarts=3\nMemoryCurrent=[not set]\n"}
	d, err := ShowUnit(context.Background(), r, "postgresql.service")
	if err != nil {
		t.Fatal(err)
	}
	if d.Active != "failed" || d.Result != "exit-code" || d.UnitFile != "enabled" || d.Restarts != "3" || d.MemoryOK ||
		!d.Since.Equal(time.Date(2026, 10, 15, 12, 41, 0, 0, time.UTC)) {
		t.Errorf("detail = %+v", d)
	}
	if args := r.calls[0]; args[len(args)-2] != "--" || args[len(args)-1] != "postgresql.service" {
		t.Errorf("unit must follow --: %q", args)
	}

	r.show = "ActiveState=active\nMemoryCurrent=18446744073709551615\nStateChangeTimestamp=\n"
	if d, _ := ShowUnit(context.Background(), r, "a.service"); d.MemoryOK || !d.Since.IsZero() {
		t.Errorf("unaccounted = %+v", d)
	}
	r.show = "MemoryCurrent=12582912\n"
	if d, _ := ShowUnit(context.Background(), r, "a.service"); !d.MemoryOK || d.Memory != 12<<20 {
		t.Errorf("memory = %+v", d)
	}

	r.calls = nil
	for _, name := range []string{"--host=x.service", `a\x2db.service`, "nginx", ""} {
		if _, err := ShowUnit(context.Background(), r, name); err == nil {
			t.Errorf("%q: accepted", name)
		}
	}
	if len(r.calls) != 0 {
		t.Errorf("invalid names reached systemctl: %q", r.calls)
	}
}
