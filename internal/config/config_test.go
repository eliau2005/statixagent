package config

import (
	"net/netip"
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
		in      string
		want    string // canonical prefix; "" means an error is expected
		errPart string // substring the error must contain
	}{
		{in: "203.0.113.7", want: "203.0.113.7/32"},
		{in: " 203.0.113.7 ", want: "203.0.113.7/32"},
		{in: "10.0.0.0/8", want: "10.0.0.0/8"},
		{in: "10.1.2.3/8", want: "10.0.0.0/8"},
		{in: "128.0.0.0/1", want: "128.0.0.0/1"}, // shortest accepted IPv4
		{in: "192.168.1.1/32", want: "192.168.1.1/32"},
		{in: "2001:db8::1", want: "2001:db8::1/128"},
		{in: "2001:db8::/32", want: "2001:db8::/32"},
		{in: "8000::/1", want: "8000::/1"}, // shortest accepted IPv6
		{in: "::ffff:198.51.100.4", want: "198.51.100.4/32"},
		{in: "::ffff:198.51.100.0/120", want: "198.51.100.0/24"},
		{in: "::ffff:10.0.0.0/104", want: "10.0.0.0/8"},
		{in: "0.0.0.0/0", errPart: "trusts every address"},
		{in: "::/0", errPart: "trusts every address"},
		{in: "10.0.0.0/0", errPart: "trusts every address"},
		{in: "::ffff:0.0.0.0/96", errPart: "trusts every address"},
		{in: "::ffff:10.0.0.0/64", errPart: "ambiguous IPv4-mapped range"},
		{in: "::ffff:10.0.0.0/95", errPart: "ambiguous IPv4-mapped range"},
		{in: "", errPart: "invalid IP address"},
		{in: "not-an-ip", errPart: "invalid IP address"},
		{in: "203.0.113", errPart: "invalid IP address"},
		{in: "256.1.1.1", errPart: "invalid IP address"},
		{in: "10.0.0.0/33", errPart: "invalid CIDR range"},
		{in: "2001:db8::/129", errPart: "invalid CIDR range"},
		{in: "10.0.0.0/", errPart: "invalid CIDR range"},
		{in: "fe80::1%eth0", errPart: "invalid IP address"},
		{in: "example.com", errPart: "invalid IP address"},
	}
	for _, c := range cases {
		got, err := ParseTrustedIP(c.in)
		if c.want == "" {
			if err == nil || !strings.Contains(err.Error(), c.errPart) {
				t.Errorf("ParseTrustedIP(%q) = %v, %v; want error containing %q", c.in, got, err, c.errPart)
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
	c.SSH.TrustedIPs = MustTrustedIPs("203.0.113.7", "10.0.0.0/8", "2001:db8::/32")
	if err := c.Validate(); err != nil {
		t.Errorf("valid trusted_ips rejected: %v", err)
	}
	// Configs built in code bypass the decoder; Validate still guards them.
	cases := []struct {
		entry   TrustedIP
		errPart string
	}{
		{TrustedIP{}, "ssh.trusted_ips[1] is empty"},
		{TrustedIP{netip.MustParsePrefix("0.0.0.0/0")}, "ssh.trusted_ips[1] 0.0.0.0/0 trusts every address"},
		{TrustedIP{netip.MustParsePrefix("::/0")}, "ssh.trusted_ips[1] ::/0 trusts every address"},
	}
	for _, tc := range cases {
		c.SSH.TrustedIPs = append(MustTrustedIPs("10.0.0.0/8"), tc.entry)
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), tc.errPart) {
			t.Errorf("Validate(%v) = %v, want error containing %q", tc.entry, err, tc.errPart)
		}
	}
}

func TestLoadTrustedIPs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	base := "[telegram]\ntoken = \"t\"\nchat_id = 42\n"
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write(base)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load without [ssh]: %v", err)
	}
	if len(cfg.SSH.TrustedIPs) != 0 {
		t.Errorf("trusted_ips = %v, want empty when [ssh] is absent", cfg.SSH.TrustedIPs)
	}

	write(base + "[ssh]\ntrusted_ips = [\"203.0.113.7\", \"2001:db8::/32\"]\n")
	if cfg, err = Load(path); err != nil {
		t.Fatalf("Load with trusted_ips: %v", err)
	}
	if got := cfg.SSH.TrustedIPs; len(got) != 2 || got[0].String() != "203.0.113.7/32" || got[1].String() != "2001:db8::/32" {
		t.Errorf("trusted_ips = %v", got)
	}

	for _, bad := range []struct{ entry, errPart string }{
		{"10.0.0.0/40", `invalid CIDR range "10.0.0.0/40"`},
		{"10.0.0.300", `invalid IP address "10.0.0.300"`},
		{"0.0.0.0/0", "trusts every address"},
		{"::ffff:10.0.0.0/64", "ambiguous IPv4-mapped range"},
	} {
		write(base + "[ssh]\ntrusted_ips = [\"10.0.0.0/8\", \"" + bad.entry + "\"]\n")
		_, err := Load(path)
		if err == nil || !strings.Contains(err.Error(), "ssh.trusted_ips") || !strings.Contains(err.Error(), bad.errPart) {
			t.Errorf("Load with %q: err = %v, want %q", bad.entry, err, bad.errPart)
		}
	}
}

func TestTrustedIPsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	in := validConfig()
	in.SSH.TrustedIPs = MustTrustedIPs("203.0.113.7", "10.1.2.3/8", "2001:db8::1", "2001:db8::/32")
	if err := Save(path, in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, _ := os.ReadFile(path)
	// Single hosts are written back the way users type them.
	if !strings.Contains(string(raw), `trusted_ips = ["203.0.113.7", "10.0.0.0/8", "2001:db8::1", "2001:db8::/32"]`) {
		t.Errorf("saved [ssh] table not as expected:\n%s", raw)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(out.SSH.TrustedIPs) != 4 {
		t.Fatalf("trusted_ips = %v", out.SSH.TrustedIPs)
	}
	for i := range in.SSH.TrustedIPs {
		if out.SSH.TrustedIPs[i] != in.SSH.TrustedIPs[i] {
			t.Errorf("trusted_ips[%d] = %v, want %v", i, out.SSH.TrustedIPs[i], in.SSH.TrustedIPs[i])
		}
	}
}

func TestLoadSSH(t *testing.T) {
	dir := t.TempDir()
	got, err := LoadSSH(filepath.Join(dir, "missing.toml"))
	if err != nil || len(got.TrustedIPs) != 0 {
		t.Errorf("missing file: %v, %v; want zero and no error", got, err)
	}

	// Other tables, even ones Load would reject, do not matter here.
	path := filepath.Join(dir, "config.toml")
	body := "[telegram]\nchat_id = 0\n[future]\nkey = 1\n[ssh]\ntrusted_ips = [\"10.0.0.0/8\"]\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = LoadSSH(path)
	if err != nil || len(got.TrustedIPs) != 1 || got.TrustedIPs[0].String() != "10.0.0.0/8" {
		t.Errorf("LoadSSH = %v, %v", got, err)
	}

	if err := os.WriteFile(path, []byte("[ssh]\ntrusted_ips = [\"::/0\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSSH(path); err == nil {
		t.Error("LoadSSH must reject an invalid trusted_ips entry")
	}
}
