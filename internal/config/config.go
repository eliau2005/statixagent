// Package config defines the agent configuration file: schema, defaults,
// load, validation, and secure save. The file holds the Telegram bot token,
// so Save always writes with 0600 permissions.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// DefaultPath is where the installer writes the config on the target system.
const DefaultPath = "/etc/statix-agent/config.toml"

// Config is the root of the agent configuration.
type Config struct {
	Telegram   Telegram   `toml:"telegram"`
	Monitors   Monitors   `toml:"monitors"`
	Thresholds Thresholds `toml:"thresholds"`
	Watch      Watch      `toml:"watch"`
	Update     Update     `toml:"update"`
	Digest     Digest     `toml:"digest"`
	SSH        SSH        `toml:"ssh"`

	// SampleInterval is the metrics sampling period.
	SampleInterval Duration `toml:"sample_interval"`
}

// Telegram identifies the per-server private bot.
type Telegram struct {
	Token  string `toml:"token"`
	ChatID int64  `toml:"chat_id"`
}

// Monitors toggles whole categories on/off.
type Monitors struct {
	System  bool `toml:"system"`  // CPU/mem/disk/net/uptime
	Thermal bool `toml:"thermal"` // temperatures, fans, throttling
	Power   bool `toml:"power"`   // battery, AC state
	Docker  bool `toml:"docker"`  // containers
	SSH     bool `toml:"ssh"`     // logins, brute force, sessions
}

// Thresholds are the alert trigger levels.
type Thresholds struct {
	CPUPercent     float64 `toml:"cpu_percent"`
	MemPercent     float64 `toml:"mem_percent"`
	DiskPercent    float64 `toml:"disk_percent"`
	TempCelsius    float64 `toml:"temp_celsius"`
	BatteryPercent float64 `toml:"battery_percent"` // alert when below
}

// Watch lists the specific things to check beyond category defaults.
type Watch struct {
	// Services are systemd unit names. They are checked where they are used
	// (services.ValidUnitName), not here: an invalid entry in an existing
	// file is reported as unknown rather than stopping the agent, and Save
	// must keep working so the user can remove it from Telegram.
	Services   []string    `toml:"services"`
	Processes  []string    `toml:"processes"` // executable names (e.g. nginx)
	Ports      []PortCheck `toml:"ports"`
	HTTPChecks []HTTPCheck `toml:"http_checks"`
	SSLHosts   []string    `toml:"ssl_hosts"` // host[:port] for cert expiry
}

// PortCheck is a local TCP listen check.
type PortCheck struct {
	Port  int    `toml:"port"`
	Label string `toml:"label"`
}

// HTTPCheck probes an endpoint and expects a status code.
type HTTPCheck struct {
	URL          string   `toml:"url"`
	ExpectStatus int      `toml:"expect_status"`
	Timeout      Duration `toml:"timeout"`
}

// Update controls self-updating. Automatic checks are opt-in (MVP §5).
type Update struct {
	Auto          bool     `toml:"auto"`
	CheckInterval Duration `toml:"check_interval"`
	Repo          string   `toml:"repo"` // owner/name on GitHub
}

// Digest controls the daily summary message: a once-a-day recap of peaks,
// SSH activity, and alert counts, so a healthy server is heard from too.
type Digest struct {
	Enabled bool `toml:"enabled"`
	Hour    int  `toml:"hour"` // local hour (0-23) to send at
}

// SSH tunes SSH login monitoring.
type SSH struct {
	// TrustedIPs are source addresses (single IPs or CIDR ranges, IPv4 or
	// IPv6) whose successful non-root logins do not push an alert, unless
	// the same source failed to authenticate recently. They are still
	// recorded in history and the digest, and their failed attempts still
	// count toward brute-force detection.
	TrustedIPs []TrustedIP `toml:"trusted_ips"`
}

// TrustedIP is one ssh.trusted_ips entry, parsed once when the config is
// decoded so the agent never re-parses (and never has to drop) an entry.
type TrustedIP struct{ netip.Prefix }

// UnmarshalText implements encoding.TextUnmarshaler.
func (t *TrustedIP) UnmarshalText(b []byte) error {
	p, err := ParseTrustedIP(string(b))
	if err != nil {
		return fmt.Errorf("ssh.trusted_ips: %w", err)
	}
	t.Prefix = p
	return nil
}

// MarshalText implements encoding.TextMarshaler. Single hosts are written
// as bare addresses, the way users usually type them.
func (t TrustedIP) MarshalText() ([]byte, error) {
	if !t.IsValid() {
		return nil, errors.New("ssh.trusted_ips: empty entry")
	}
	if t.IsSingleIP() {
		return t.Addr().MarshalText()
	}
	return t.Prefix.MarshalText()
}

// MustTrustedIPs parses entries with ParseTrustedIP and panics on error.
// It is meant for tests and literals, not user input.
func MustTrustedIPs(entries ...string) []TrustedIP {
	out := make([]TrustedIP, 0, len(entries))
	for _, e := range entries {
		p, err := ParseTrustedIP(e)
		if err != nil {
			panic(err)
		}
		out = append(out, TrustedIP{p})
	}
	return out
}

// trustedIPHint is appended to every parse error so the fix is obvious.
const trustedIPHint = "want an IP like 203.0.113.7 or a CIDR like 10.0.0.0/8"

// ParseTrustedIP parses one ssh.trusted_ips entry: a bare address (treated
// as a single-host prefix) or a CIDR range. The result is masked so
// "10.1.2.3/8" and "10.0.0.0/8" mean the same range, and IPv4-mapped IPv6
// forms are reduced to plain IPv4 so they match what sshd logs.
//
// Two shapes are rejected outright: a /0 range, which would silently
// trust every source and turn login alerts off, and an IPv4-mapped CIDR
// shorter than /96, which spans beyond the mapped space and has no clear
// IPv4 meaning.
func ParseTrustedIP(entry string) (netip.Prefix, error) {
	s := strings.TrimSpace(entry)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR range %q (%s)", entry, trustedIPHint)
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return netip.Prefix{}, fmt.Errorf("ambiguous IPv4-mapped range %q: prefix must be /96 or longer, or write the IPv4 CIDR directly", entry)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		if p.Bits() == 0 {
			return netip.Prefix{}, fmt.Errorf("range %q trusts every address and would disable all login alerts", entry)
		}
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil || addr.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("invalid IP address %q (%s)", entry, trustedIPHint)
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// Duration wraps time.Duration for TOML strings like "30s".
type Duration struct{ time.Duration }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) {
	return []byte(d.Duration.String()), nil
}

// Default returns the configuration preselected by the installer:
// core system + services on, hardware categories on, auto-update off.
func Default() Config {
	return Config{
		Monitors: Monitors{
			System:  true,
			Thermal: true,
			Power:   true,
			Docker:  true,
			SSH:     true,
		},
		Thresholds: Thresholds{
			CPUPercent:     90,
			MemPercent:     90,
			DiskPercent:    85,
			TempCelsius:    85,
			BatteryPercent: 15,
		},
		Update: Update{
			Auto:          false,
			CheckInterval: Duration{6 * time.Hour},
			Repo:          "eliau2005/statixagent",
		},
		Digest: Digest{
			Enabled: true,
			Hour:    9,
		},
		SampleInterval: Duration{15 * time.Second},
	}
}

// Load reads and validates a config file.
func Load(path string) (Config, error) {
	cfg := Default()
	meta, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	if un := meta.Undecoded(); len(un) > 0 {
		return Config{}, fmt.Errorf("config: unknown keys: %v", un)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// LoadSSH reads only the [ssh] table of an existing config file, ignoring
// every other key, so the installer can carry hand-edited SSH settings
// over a re-install. A missing file yields the zero SSH and no error.
func LoadSSH(path string) (SSH, error) {
	var partial struct {
		SSH SSH `toml:"ssh"`
	}
	if _, err := toml.DecodeFile(path, &partial); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return SSH{}, nil
		}
		return SSH{}, fmt.Errorf("config: %w", err)
	}
	return partial.SSH, nil
}

// Validate checks invariants that would make the agent misbehave at runtime.
func (c Config) Validate() error {
	var errs []error
	if c.Telegram.Token == "" {
		errs = append(errs, errors.New("telegram.token is required"))
	}
	if c.Telegram.ChatID == 0 {
		errs = append(errs, errors.New("telegram.chat_id is required"))
	}
	if c.SampleInterval.Duration < time.Second {
		errs = append(errs, fmt.Errorf("sample_interval %s is below 1s", c.SampleInterval))
	}
	for _, p := range c.Watch.Ports {
		if p.Port < 1 || p.Port > 65535 {
			errs = append(errs, fmt.Errorf("port %d out of range", p.Port))
		}
	}
	for _, h := range c.Watch.HTTPChecks {
		if h.URL == "" {
			errs = append(errs, errors.New("http_checks entry missing url"))
		}
	}
	if c.Digest.Hour < 0 || c.Digest.Hour > 23 {
		errs = append(errs, fmt.Errorf("digest.hour %d out of range 0-23", c.Digest.Hour))
	}
	// Entries are parsed on decode; this only guards configs built in code.
	for i, ip := range c.SSH.TrustedIPs {
		switch {
		case !ip.IsValid():
			errs = append(errs, fmt.Errorf("ssh.trusted_ips[%d] is empty (%s)", i, trustedIPHint))
		case ip.Bits() == 0:
			errs = append(errs, fmt.Errorf("ssh.trusted_ips[%d] %s trusts every address", i, ip.Prefix))
		}
	}
	if c.Update.Auto && c.Update.CheckInterval.Duration < time.Minute {
		errs = append(errs, fmt.Errorf("update.check_interval %s is below 1m", c.Update.CheckInterval))
	}
	return errors.Join(errs...)
}

// Save writes the config atomically with owner-only permissions: the file
// contains the bot token (MVP §7). It creates the parent directory if needed.
func Save(path string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(c); err != nil {
		return fmt.Errorf("config: encode: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".config-*.toml")
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("config: %w", err)
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return fmt.Errorf("config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	return nil
}
