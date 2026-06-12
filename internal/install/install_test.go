package install

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eliau2005/statixagent/internal/config"
)

type recordingRunner struct{ calls [][]string }

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	return "", nil
}

func testOptions(t *testing.T) Options {
	t.Helper()
	prefix := t.TempDir()
	srcBin := filepath.Join(prefix, "downloaded-agent")
	if err := os.WriteFile(srcBin, []byte("ELF fake binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Telegram.Token = "123:ABC"
	cfg.Telegram.ChatID = 99
	return Options{Prefix: prefix, AgentBinary: srcBin, Config: cfg}
}

func TestInstall(t *testing.T) {
	o := testOptions(t)
	r := &recordingRunner{}
	o.Runner = r

	res, err := Install(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(res.BinaryPath); string(got) != "ELF fake binary" {
		t.Errorf("binary = %q", got)
	}
	if _, err := config.Load(res.ConfigPath); err != nil {
		t.Errorf("written config does not load: %v", err)
	}
	unit, _ := os.ReadFile(res.UnitPath)
	// The binary dir must be in ReadWritePaths or in-place self-update
	// fails with "read-only file system" under ProtectSystem=full.
	binDirRW := "ReadWritePaths=" + filepath.Dir(res.ConfigPath) + " " + filepath.Dir(res.BinaryPath)
	for _, want := range []string{"Restart=always", "--config " + res.ConfigPath, res.BinaryPath, binDirRW} {
		if !strings.Contains(string(unit), want) {
			t.Errorf("unit missing %q:\n%s", want, unit)
		}
	}
	if len(r.calls) != 2 || r.calls[0][1] != "daemon-reload" || r.calls[1][1] != "enable" {
		t.Errorf("systemctl calls = %v", r.calls)
	}
	if !res.Started {
		t.Error("Started must be true with a runner")
	}

	// Idempotency: a second run succeeds and overwrites.
	if _, err := Install(context.Background(), o); err != nil {
		t.Errorf("re-install failed: %v", err)
	}
}

func TestInstallWithoutRunner(t *testing.T) {
	o := testOptions(t)
	res, err := Install(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Started {
		t.Error("no runner must mean not started")
	}
}

func TestInstallRejectsInvalidConfig(t *testing.T) {
	o := testOptions(t)
	o.Config.Telegram.Token = "" // invalid
	if _, err := Install(context.Background(), o); err == nil {
		t.Error("invalid config must fail install")
	}
}
