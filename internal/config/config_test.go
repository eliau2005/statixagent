package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func validConfig() Config {
	c := Default()
	c.Telegram.Token = "123456:ABC-test"
	c.Telegram.ChatID = 42
	return c
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "config.toml")
	in := validConfig()
	in.Watch.Services = []string{"nginx.service", "postgresql.service"}
	in.Watch.Ports = []PortCheck{{Port: 443, Label: "https"}}
	in.Watch.HTTPChecks = []HTTPCheck{{URL: "https://example.com/health", ExpectStatus: 200, Timeout: Duration{5 * time.Second}}}
	in.SampleInterval = Duration{30 * time.Second}

	if err := Save(path, in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if out.Telegram != in.Telegram {
		t.Errorf("telegram mismatch: got %+v want %+v", out.Telegram, in.Telegram)
	}
	if out.SampleInterval.Duration != 30*time.Second {
		t.Errorf("sample_interval = %s, want 30s", out.SampleInterval)
	}
	if len(out.Watch.Services) != 2 || out.Watch.Services[0] != "nginx.service" {
		t.Errorf("services = %v", out.Watch.Services)
	}
	if len(out.Watch.HTTPChecks) != 1 || out.Watch.HTTPChecks[0].Timeout.Duration != 5*time.Second {
		t.Errorf("http_checks = %+v", out.Watch.HTTPChecks)
	}
}

func TestSavePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits not meaningful on windows")
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := Save(path, validConfig()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o, want 600", perm)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	content := `
sample_interval = "15s"
[telegram]
token = "t"
chat_id = 1
[telegrm]
typo = true
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "unknown keys") {
		t.Errorf("err = %v, want unknown-keys error", err)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantSub string
	}{
		{"missing token", func(c *Config) { c.Telegram.Token = "" }, "telegram.token"},
		{"missing chat id", func(c *Config) { c.Telegram.ChatID = 0 }, "telegram.chat_id"},
		{"interval too small", func(c *Config) { c.SampleInterval = Duration{time.Millisecond} }, "sample_interval"},
		{"bad port", func(c *Config) { c.Watch.Ports = []PortCheck{{Port: 70000}} }, "out of range"},
		{"http check without url", func(c *Config) { c.Watch.HTTPChecks = []HTTPCheck{{}} }, "missing url"},
		{"auto update too frequent", func(c *Config) {
			c.Update.Auto = true
			c.Update.CheckInterval = Duration{time.Second}
		}, "check_interval"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.mutate(&c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("err = %v, want substring %q", err, tc.wantSub)
			}
		})
	}
	if err := validConfig().Validate(); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

func TestDefaultsAreSane(t *testing.T) {
	d := Default()
	if !d.Monitors.System || !d.Monitors.SSH {
		t.Error("core monitors must default on")
	}
	if d.Update.Auto {
		t.Error("auto-update must default off (MVP §5)")
	}
}

func TestParseTrustedIP(t *testing.T) {
	cases := []struct {
		in   string
		want string // canonical prefix; "" means an error is expected
	}{
		{"203.0.113.7", "203.0.113.7/32"},
		{" 203.0.113.7 ", "203.0.113.7/32"},
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"10.1.2.3/8", "10.0.0.0/8"},
		{"0.0.0.0/0", "0.0.0.0/0"},
		{"192.168.1.1/32", "192.168.1.1/32"},
		{"2001:db8::1", "2001:db8::1/128"},
		{"2001:db8::/32", "2001:db8::/32"},
		{"::/0", "::/0"},
		{"::ffff:198.51.100.4", "198.51.100.4/32"},
		{"::ffff:198.51.100.0/120", "198.51.100.0/24"},
		{"", ""},
		{"not-an-ip", ""},
		{"203.0.113", ""},
		{"256.1.1.1", ""},
		{"10.0.0.0/33", ""},
		{"2001:db8::/129", ""},
		{"10.0.0.0/", ""},
		{"fe80::1%eth0", ""},
		{"example.com", ""},
	}
	for _, c := range cases {
		got, err := ParseTrustedIP(c.in)
		if c.want == "" {
			if err == nil {
				t.Errorf("ParseTrustedIP(%q) = %v, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseTrustedIP(%q): %v", c.in, err)
			continue
		}
		if got.String() != c.want {
			t.Errorf("ParseTrustedIP(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestValidateTrustedIPs(t *testing.T) {
	c := validConfig()
	if len(c.SSH.TrustedIPs) != 0 {
		t.Fatalf("default trusted_ips = %v, want empty", c.SSH.TrustedIPs)
	}
	c.SSH.TrustedIPs = []string{"203.0.113.7", "10.0.0.0/8", "2001:db8::/32"}
	if err := c.Validate(); err != nil {
		t.Errorf("valid trusted_ips rejected: %v", err)
	}
	c.SSH.TrustedIPs = []string{"10.0.0.0/8", "10.0.0.300"}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "ssh.trusted_ips[1]") || !strings.Contains(err.Error(), "10.0.0.300") {
		t.Errorf("invalid entry error = %v, want index and value", err)
	}
}

func TestLoadTrustedIPs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	base := "[telegram]\ntoken = \"t\"\nchat_id = 42\n"
	if err := os.WriteFile(path, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load without [ssh]: %v", err)
	}
	if len(cfg.SSH.TrustedIPs) != 0 {
		t.Errorf("trusted_ips = %v, want empty when [ssh] is absent", cfg.SSH.TrustedIPs)
	}

	withSSH := base + "[ssh]\ntrusted_ips = [\"203.0.113.7\", \"2001:db8::/32\"]\n"
	if err := os.WriteFile(path, []byte(withSSH), 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg, err = Load(path); err != nil {
		t.Fatalf("Load with trusted_ips: %v", err)
	}
	if len(cfg.SSH.TrustedIPs) != 2 {
		t.Errorf("trusted_ips = %v", cfg.SSH.TrustedIPs)
	}

	bad := base + "[ssh]\ntrusted_ips = [\"10.0.0.0/40\"]\n"
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "ssh.trusted_ips[0]") {
		t.Errorf("Load with bad CIDR: err = %v", err)
	}
}
