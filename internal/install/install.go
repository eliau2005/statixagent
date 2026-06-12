// Package install performs the system-side half of the installer (MVP §4
// step 6): place the agent binary, write the config and systemd unit, and
// enable the service. Paths are prefix-relative and systemctl runs through
// the services.Runner interface, so everything tests in a temp dir.
package install

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/services"
)

// Options controls one installation.
type Options struct {
	// Prefix is prepended to all paths ("" = real root). Tests use a temp dir.
	Prefix string
	// AgentBinary is the statix-agent executable to install (source path).
	AgentBinary string
	// Config is the validated configuration collected by the wizard.
	Config config.Config
	// Runner executes systemctl; nil skips service activation (for tests
	// and for systems without systemd).
	Runner services.Runner
}

// Paths within the prefix.
const (
	BinDir     = "/usr/local/bin"
	BinName    = "statix-agent"
	UnitPath   = "/etc/systemd/system/statix-agent.service"
	ConfigPath = config.DefaultPath
)

// Result reports what Install did, for the wizard's summary screen.
type Result struct {
	BinaryPath string
	ConfigPath string
	UnitPath   string
	Started    bool
}

// Install performs all steps. It is idempotent: re-running overwrites the
// binary, config, and unit.
func Install(ctx context.Context, o Options) (Result, error) {
	var res Result

	// 1. Binary.
	dstBin := filepath.Join(o.Prefix, BinDir, BinName)
	if err := copyFile(o.AgentBinary, dstBin, 0o755); err != nil {
		return res, fmt.Errorf("install: binary: %w", err)
	}
	res.BinaryPath = dstBin

	// 2. Config (Save enforces 0600 and creates the directory).
	cfgPath := filepath.Join(o.Prefix, ConfigPath)
	if err := config.Save(cfgPath, o.Config); err != nil {
		return res, fmt.Errorf("install: config: %w", err)
	}
	res.ConfigPath = cfgPath

	// 3. systemd unit.
	unitPath := filepath.Join(o.Prefix, UnitPath)
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o755); err != nil {
		return res, fmt.Errorf("install: unit: %w", err)
	}
	unit := UnitFile(filepath.Join(o.Prefix, BinDir, BinName), cfgPath)
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return res, fmt.Errorf("install: unit: %w", err)
	}
	res.UnitPath = unitPath

	// 4. Enable + start.
	if o.Runner != nil {
		for _, args := range [][]string{
			{"daemon-reload"},
			{"enable", "--now", "statix-agent.service"},
		} {
			if out, err := o.Runner.Run(ctx, "systemctl", args...); err != nil {
				return res, fmt.Errorf("install: systemctl %v: %v (%s)", args, err, out)
			}
		}
		res.Started = true
	}
	return res, nil
}

// UnitFile renders the systemd unit for the given binary and config paths.
// Writable carve-outs through the ProtectSystem sandbox: the binary's
// directory (self-update swaps the executable in place, MVP §5) and ufw's
// rule directories (the /firewall command edits rules; "-" prefix skips
// them when ufw is not installed).
func UnitFile(execPath, cfgPath string) string {
	return fmt.Sprintf(`[Unit]
Description=StatixAgent VPS/laptop monitoring agent
Documentation=https://github.com/eliau2005/statixagent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s --config %s
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectHome=read-only
ProtectSystem=full
ReadWritePaths=%s %s -/etc/ufw -/lib/ufw
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
MemoryMax=128M

[Install]
WantedBy=multi-user.target
`, execPath, cfgPath, filepath.Dir(cfgPath), filepath.Dir(execPath))
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}
