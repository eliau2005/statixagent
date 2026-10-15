package services

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestExecRunnerEnvironmentIsMinimal(t *testing.T) {
	t.Setenv("TELEGRAM_TOKEN", "123:secret")
	t.Setenv("LANGUAGE", "fr_FR:fr")
	out, err := ExecRunner{}.Run(context.Background(), "env")
	if err != nil {
		t.Fatalf("env: %v (%s)", err, out)
	}
	var keys []string
	for line := range strings.SplitSeq(out, "\n") {
		k, _, _ := strings.Cut(line, "=")
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if want := []string{"LANG", "LANGUAGE", "LC_ALL", "PATH"}; !slices.Equal(keys, want) {
		t.Errorf("child environment keys = %q, want %q", keys, want)
	}
	if strings.Contains(out, "secret") {
		t.Errorf("child environment leaked the token: %q", out)
	}
}

func TestExecRunnerKillsGrandchildrenOnTimeout(t *testing.T) {
	// sh forks sleep (the trailing ":" stops it exec'ing in place), so
	// killing sh alone leaves sleep holding the output pipe for 30s, and
	// WaitDelay alone would only give up 2s later. The bound below needs
	// the whole process group killed at the timeout.
	start := time.Now()
	_, err := ExecRunner{Timeout: 200 * time.Millisecond}.Run(context.Background(), "sh", "-c", "sleep 30; :")
	if err == nil {
		t.Fatal("want an error from the killed command")
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Errorf("Run returned after %s, want about the 200ms timeout", elapsed)
	}
}

func TestExecRunnerCapsOutput(t *testing.T) {
	// 200 KiB of output; the child must still exit cleanly.
	out, err := ExecRunner{}.Run(context.Background(), "sh", "-c", "head -c 204800 /dev/zero | tr '\\0' x")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(out) != maxOutput {
		t.Errorf("output = %d bytes, want capped at %d", len(out), maxOutput)
	}
}

func TestExecRunnerRefusesRelativePaths(t *testing.T) {
	for _, name := range []string{"./tool", "bin/tool"} {
		if _, err := (ExecRunner{}).Run(context.Background(), name); err == nil ||
			!strings.Contains(err.Error(), "not an absolute path") {
			t.Errorf("Run(%q) err = %v, want refusal", name, err)
		}
	}
}

func TestCappedBuffer(t *testing.T) {
	b := &cappedBuffer{max: 5}
	for _, s := range []string{"abc", "defg", "hij"} {
		if n, err := b.Write([]byte(s)); n != len(s) || err != nil {
			t.Errorf("Write(%q) = %d, %v; want full length, nil", s, n, err)
		}
	}
	if got := b.String(); got != "abcde" {
		t.Errorf("String() = %q, want %q", got, "abcde")
	}
}
