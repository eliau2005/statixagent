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

func TestInstallKeepsExistingSSHSettings(t *testing.T) {
	o := testOptions(t)
	cfgPath := filepath.Join(o.Prefix, ConfigPath)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		t.Fatal(err)
	}
	existing := "[telegram]\ntoken = \"old\"\nchat_id = 1\n[ssh]\ntrusted_ips = [\"203.0.113.7\", \"2001:db8::/32\"]\n"
	if err := os.WriteFile(cfgPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Install(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Telegram.Token != "123:ABC" {
		t.Errorf("token = %q, want the wizard's answer", cfg.Telegram.Token)
	}
	if got := cfg.SSH.TrustedIPs; len(got) != 2 || got[0].String() != "203.0.113.7/32" || got[1].String() != "2001:db8::/32" {
		t.Errorf("trusted_ips = %v, want the existing file's entries", got)
	}
}

func TestInstallFreshHasNoTrustedIPs(t *testing.T) {
	o := testOptions(t)
	res, err := Install(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.SSH.TrustedIPs) != 0 {
		t.Errorf("trusted_ips = %v, want empty on a fresh install", cfg.SSH.TrustedIPs)
	}
}

func TestInstallRefusesUnreadableExistingConfig(t *testing.T) {
	o := testOptions(t)
	cfgPath := filepath.Join(o.Prefix, ConfigPath)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		t.Fatal(err)
	}
	broken := "[ssh]\ntrusted_ips = [\"0.0.0.0/0\"]\n"
	if err := os.WriteFile(cfgPath, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Install(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), "existing config") {
		t.Fatalf("err = %v, want an existing-config error", err)
	}
	// Nothing was touched: the binary is not installed, the file is as it was.
	if _, err := os.Stat(filepath.Join(o.Prefix, BinDir, BinName)); !os.IsNotExist(err) {
		t.Errorf("binary installed despite the error: %v", err)
	}
	if got, _ := os.ReadFile(cfgPath); string(got) != broken {
		t.Errorf("existing config rewritten:\n%s", got)
	}
}
