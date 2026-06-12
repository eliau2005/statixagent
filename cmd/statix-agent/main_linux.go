//go:build linux

// statix-agent is the monitoring daemon (MVP §2): one static binary that
// samples the system, watches sshd, and serves a private Telegram bot.
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/eliau2005/statixagent/internal/agent"
	"github.com/eliau2005/statixagent/internal/collect"
	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/dockermon"
	"github.com/eliau2005/statixagent/internal/procfs"
	"github.com/eliau2005/statixagent/internal/services"
	"github.com/eliau2005/statixagent/internal/sshwatch"
	"github.com/eliau2005/statixagent/internal/sysfs"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/update"
)

// version and pubKeyHex are stamped by the release build:
// -ldflags "-X main.version=v1.2.3 -X main.pubKeyHex=<ed25519 hex>"
var (
	version   = "dev"
	pubKeyHex = ""
)

func main() {
	cfgPath := flag.String("config", config.DefaultPath, "path to config.toml")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("statix-agent: %v", err)
	}

	// Crash-loop rollback (MVP §5): if this binary keeps dying right after
	// start and a .prev exists, restore it and let systemd run that instead.
	if exe, err := os.Executable(); err == nil {
		guard := update.RollbackGuard{
			StatePath:  filepath.Join(filepath.Dir(*cfgPath), "starts"),
			BinaryPath: exe,
		}
		if rolledBack, err := guard.Check(time.Now()); err != nil {
			log.Printf("statix-agent: rollback guard: %v", err)
		} else if rolledBack {
			log.Printf("statix-agent: crash loop detected — rolled back to previous binary, exiting for restart")
			os.Exit(1)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	tg := telegram.New(cfg.Telegram.Token)
	src := buildSources(ctx, cfg, *cfgPath)

	if up := buildUpdater(cfg); up != nil {
		src.UpdateCheck = up.Check
		src.UpdateApply = up.Apply
		if cfg.Update.Auto {
			go autoUpdateLoop(ctx, up, cfg.Update.CheckInterval.Duration)
		}
	}

	a := agent.New(cfg, tg, tg, src)
	if err := a.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("statix-agent: %v", err)
	}
}

// buildUpdater returns nil when the build carries no signing key — /update
// then reports self-update as unavailable rather than risking an
// unverified install (MVP §7).
func buildUpdater(cfg config.Config) *update.Updater {
	key, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	return &update.Updater{
		Repo:       cfg.Update.Repo,
		Current:    version,
		BinaryPath: exe,
		AssetName:  fmt.Sprintf("statix-agent_%s_%s", runtime.GOOS, runtime.GOARCH),
		PublicKey:  ed25519.PublicKey(key),
		Restart: func(ctx context.Context) error {
			// systemd restarts us; exiting after the swap is enough, but an
			// explicit restart returns immediately under systemd-run units.
			cmd := exec.CommandContext(ctx, "systemctl", "restart", "statix-agent.service")
			go func() {
				time.Sleep(2 * time.Second)
				cmd.Run()
			}()
			return nil
		},
	}
}

func autoUpdateLoop(ctx context.Context, up *update.Updater, interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if _, ok, err := up.Check(ctx); err == nil && ok {
				if err := up.Apply(ctx); err != nil {
					log.Printf("statix-agent: auto-update: %v", err)
				}
			}
		}
	}
}

func buildSources(ctx context.Context, cfg config.Config, cfgPath string) agent.Sources {
	hostname, _ := os.Hostname()
	src := agent.Sources{
		Hostname: hostname,
		Sample:   sampleLinux,
		Thermal:  func() (sysfs.Thermal, error) { return sysfs.ReadThermal(os.DirFS("/sys")) },
		Power:    func() (sysfs.Power, error) { return sysfs.ReadPower(os.DirFS("/sys")) },
		Sessions: readSessions,
		Runner:   services.ExecRunner{},
		ProcFS: func(names []string) ([]services.Result, error) {
			return services.CheckProcesses(os.DirFS("/proc"), names), nil
		},
		KeyPaths:      findAuthorizedKeys(),
		ConfigPath:    cfgPath,
		ListListeners: listListeners,
	}
	if cfg.Monitors.SSH {
		src.AuthLines = tailAuthLog(ctx)
	}
	if cfg.Monitors.Docker {
		if _, err := os.Stat("/var/run/docker.sock"); err == nil {
			src.Docker = dockermon.NewUnixSocket("/var/run/docker.sock")
		}
	}
	return src
}

func sampleLinux(ctx context.Context) (collect.Sample, error) {
	s := collect.Sample{At: time.Now()}

	if err := withFile("/proc/stat", func(f *os.File) (err error) {
		s.Stat, err = procfs.ParseStat(f)
		return
	}); err != nil {
		return s, err
	}
	if err := withFile("/proc/meminfo", func(f *os.File) (err error) {
		s.Mem, err = procfs.ParseMemInfo(f)
		return
	}); err != nil {
		return s, err
	}
	withFile("/proc/loadavg", func(f *os.File) (err error) { s.Load, err = procfs.ParseLoadAvg(f); return })
	withFile("/proc/uptime", func(f *os.File) (err error) { s.Uptime, err = procfs.ParseUptime(f); return })
	withFile("/proc/net/dev", func(f *os.File) (err error) { s.Net, err = procfs.ParseNetDev(f); return })
	withFile("/proc/diskstats", func(f *os.File) (err error) {
		all, err := procfs.ParseDiskStats(f)
		if err != nil {
			return err
		}
		names := make([]string, len(all))
		for i, d := range all {
			names[i] = d.Name
		}
		for _, d := range all {
			if !collect.IsPartition(d.Name, names) && !strings.HasPrefix(d.Name, "loop") {
				s.Disks = append(s.Disks, d)
			}
		}
		return nil
	})
	withFile("/proc/sys/fs/file-nr", func(f *os.File) (err error) { s.FileNR, err = procfs.ParseFileNR(f); return })

	if pids, err := filepath.Glob("/proc/[0-9]*"); err == nil {
		s.NumProc = len(pids)
	}
	if mounts, err := collect.ReadMountUsage(); err == nil {
		s.Mounts = mounts
	}
	return s, nil
}

func withFile(path string, f func(*os.File) error) error {
	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fh.Close()
	return f(fh)
}

// readSessions lists live sessions from utmp when it exists, falling back
// to systemd-logind on distros that dropped the utmp file (Ubuntu 24.10+).
func readSessions() ([]sshwatch.Session, error) {
	if sessions, err := readUtmpSessions("/var/run/utmp"); err == nil && len(sessions) > 0 {
		return sessions, nil
	}
	runner := services.ExecRunner{}
	return sshwatch.SessionsFromLoginctl(context.Background(), runner.Run)
}

func readUtmpSessions(path string) ([]sshwatch.Session, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return sshwatch.ParseUtmp(f)
}

// tailAuthLog streams sshd log lines: journalctl when available, otherwise
// tail -F /var/log/auth.log. The reader goroutine restarts the source if it
// exits while the agent is still running.
func tailAuthLog(ctx context.Context) <-chan string {
	ch := make(chan string, 64)
	go func() {
		defer close(ch)
		for ctx.Err() == nil {
			if err := runTail(ctx, ch); err != nil && ctx.Err() == nil {
				log.Printf("statix-agent: auth log tail: %v (retrying in 10s)", err)
				select {
				case <-time.After(10 * time.Second):
				case <-ctx.Done():
				}
			}
		}
	}()
	return ch
}

func runTail(ctx context.Context, ch chan<- string) error {
	var cmd *exec.Cmd
	if _, err := exec.LookPath("journalctl"); err == nil {
		cmd = exec.CommandContext(ctx, "journalctl", "-f", "-n", "0", "_COMM=sshd", "_COMM=sshd-session", "--output", "cat")
	} else {
		cmd = exec.CommandContext(ctx, "tail", "-F", "-n", "0", "/var/log/auth.log")
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	for sc.Scan() {
		select {
		case ch <- sc.Text():
		case <-ctx.Done():
		}
	}
	return cmd.Wait()
}

// listListeners merges LISTEN-state ports from /proc/net/tcp and tcp6.
func listListeners() ([]int, error) {
	var all []int
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		err := withFile(path, func(f *os.File) error {
			ports, err := procfs.ParseTCPListeners(f)
			all = append(all, ports...)
			return err
		})
		if err != nil && path == "/proc/net/tcp" {
			return nil, err // v4 must exist; v6 may not
		}
	}
	return all, nil
}

// findAuthorizedKeys collects the key files of root and every /home user.
func findAuthorizedKeys() []string {
	paths := []string{"/root/.ssh/authorized_keys"}
	homes, _ := filepath.Glob("/home/*/.ssh/authorized_keys")
	return append(paths, homes...)
}
