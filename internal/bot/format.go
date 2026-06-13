package bot

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/eliau2005/statixagent/internal/alert"
	"github.com/eliau2005/statixagent/internal/collect"
	"github.com/eliau2005/statixagent/internal/dockermon"
	"github.com/eliau2005/statixagent/internal/services"
	"github.com/eliau2005/statixagent/internal/sshwatch"
	"github.com/eliau2005/statixagent/internal/sysfs"
)

// Messages are "dashboard cards": a header line with the entity in <b>,
// then a <pre> block with monospace-aligned rows. <pre> gives alignment
// and stops Telegram from turning paths like /boot into bot-command links.

const divider = "────────────────────────────"

// Bytes renders a byte count with binary units ("7.7 GiB").
func Bytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// BytesShort renders a compact byte count for tight columns ("7.7G").
func BytesShort(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c", float64(n)/float64(div), "KMGTPE"[exp])
}

// Rate renders bytes/second compactly ("1.0M/s").
func Rate(bps float64) string {
	return BytesShort(uint64(bps)) + "/s"
}

// Dur renders a duration compactly: "3d 4h", "2h 5m", "42s".
func Dur(d time.Duration) string {
	d = d.Round(time.Second)
	day := 24 * time.Hour
	switch {
	case d >= day:
		return fmt.Sprintf("%dd %dh", d/day, (d%day)/time.Hour)
	case d >= time.Hour:
		return fmt.Sprintf("%dh %dm", d/time.Hour, (d%time.Hour)/time.Minute)
	case d >= time.Minute:
		return fmt.Sprintf("%dm %ds", d/time.Minute, (d%time.Minute)/time.Second)
	default:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
}

func esc(s string) string { return html.EscapeString(s) }

// Spark renders values as a one-line sparkline scaled to maxVal
// (maxVal <= 0 autoscales to the series peak).
func Spark(vals []float64, maxVal float64) string {
	if len(vals) == 0 {
		return ""
	}
	if maxVal <= 0 {
		for _, v := range vals {
			if v > maxVal {
				maxVal = v
			}
		}
		if maxVal == 0 {
			maxVal = 1
		}
	}
	levels := []rune("▁▂▃▄▅▆▇█")
	var b strings.Builder
	for _, v := range vals {
		idx := int(v / maxVal * float64(len(levels)))
		if idx >= len(levels) {
			idx = len(levels) - 1
		}
		if idx < 0 {
			idx = 0
		}
		b.WriteRune(levels[idx])
	}
	return b.String()
}

// bar renders a 10-segment usage bar.
func bar(percent float64) string {
	filled := int(percent/10 + 0.5)
	if filled > 10 {
		filled = 10
	}
	if filled < 0 {
		filled = 0
	}
	return strings.Repeat("▰", filled) + strings.Repeat("▱", 10-filled)
}

// pad right-pads (positive n) or left-pads (negative n) to a width,
// truncating long values so columns never shift.
func pad(s string, n int) string {
	left := n < 0
	if left {
		n = -n
	}
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	fill := strings.Repeat(" ", n-len(r))
	if left {
		return fill + s
	}
	return s + fill
}

// card assembles header + <pre> body lines.
func card(header string, lines []string) string {
	body := esc(strings.Join(lines, "\n"))
	return header + "\n<pre>" + body + "</pre>"
}

// activeNet filters interfaces that have ever moved traffic.
func activeNet(all []collect.NetRate) []collect.NetRate {
	var out []collect.NetRate
	for _, n := range all {
		if n.RxTotal > 0 || n.TxTotal > 0 {
			out = append(out, n)
		}
	}
	return out
}

// Status renders the /status dashboard.
func Status(hostname string, s collect.Snapshot, th sysfs.Thermal, pw sysfs.Power) string {
	header := fmt.Sprintf("🖥 <b>%s</b> — ⏱ %s", esc(hostname), Dur(s.Uptime))
	var L []string
	L = append(L, divider)
	L = append(L, fmt.Sprintf(" %s %s %s", pad("CPU", 5), bar(s.CPUTotal.Percent), pad(fmt.Sprintf("%.0f%%", s.CPUTotal.Percent), -4)))
	L = append(L, fmt.Sprintf(" %s %s %s  %s/%s", pad("RAM", 5), bar(s.Mem.UsedPercent()),
		pad(fmt.Sprintf("%.0f%%", s.Mem.UsedPercent()), -4),
		BytesShort(s.Mem.Total-s.Mem.Available), BytesShort(s.Mem.Total)))
	if used := s.Mem.SwapTotal - s.Mem.SwapFree; s.Mem.SwapTotal > 0 && used > s.Mem.SwapTotal/100 {
		pct := 100 * float64(used) / float64(s.Mem.SwapTotal)
		L = append(L, fmt.Sprintf(" %s %s %s  %s/%s", pad("SWAP", 5), bar(pct),
			pad(fmt.Sprintf("%.0f%%", pct), -4), BytesShort(used), BytesShort(s.Mem.SwapTotal)))
	}
	label := "DISK"
	for _, m := range s.Mounts {
		L = append(L, fmt.Sprintf(" %s %s %s  %s", pad(label, 5), bar(m.UsedPercent),
			pad(fmt.Sprintf("%.0f%%", m.UsedPercent), -4), m.MountPoint))
		label = ""
	}
	L = append(L, divider)
	for _, n := range activeNet(s.Net) {
		L = append(L, fmt.Sprintf(" 🌐 %s ↓%s ↑%s", pad(n.Name, 10), pad(Rate(n.RxBytesPerSec), -8), pad(Rate(n.TxBytesPerSec), -8)))
	}
	hw := ""
	if len(th.Sensors) > 0 {
		hw = fmt.Sprintf(" 🌡 %.0f°C", th.MaxCelsius())
		if th.Throttled {
			hw += " ⚠️"
		}
	}
	if pw.HasBattery && len(pw.Batteries) > 0 {
		b := pw.Batteries[0]
		hw += fmt.Sprintf("  🔋 %.0f%%", b.Percent)
		if pw.OnBattery() && b.TimeToEmpty > 0 {
			hw += " ⚡" + Dur(b.TimeToEmpty)
		}
	}
	if hw != "" {
		L = append(L, hw)
	}
	L = append(L, divider)
	L = append(L, fmt.Sprintf(" %d procs · %d fds · load %.2f", s.NumProc, s.FileNR.Allocated, s.Load.Load1))
	return card(header, L)
}

// CPU renders /cpu. trend is a pre-rendered sparkline ("" = omit).
func CPU(s collect.Snapshot, trend string) string {
	header := fmt.Sprintf("🖥 <b>CPU</b> %.1f%% — load %.2f %.2f %.2f",
		s.CPUTotal.Percent, s.Load.Load1, s.Load.Load5, s.Load.Load15)
	var L []string
	if trend != "" {
		L = append(L, " trend "+trend, divider)
	}
	for _, c := range s.PerCore {
		L = append(L, fmt.Sprintf(" %s %s %s", pad(c.Name, 5), bar(c.Percent), pad(fmt.Sprintf("%.0f%%", c.Percent), -4)))
	}
	if len(L) == 0 {
		L = append(L, " no per-core data yet")
	}
	return card(header, L)
}

// Mem renders /mem. trend is a pre-rendered sparkline ("" = omit).
func Mem(s collect.Snapshot, trend string) string {
	m := s.Mem
	header := fmt.Sprintf("🧠 <b>Memory</b> %.1f%%", m.UsedPercent())
	L := []string{
		fmt.Sprintf(" %s %s of %s", bar(m.UsedPercent()), BytesShort(m.Total-m.Available), BytesShort(m.Total)),
	}
	if trend != "" {
		L = append(L, " trend "+trend)
	}
	L = append(L,
		divider,
		fmt.Sprintf(" %s %s", pad("used", 11), BytesShort(m.Total-m.Available)),
		fmt.Sprintf(" %s %s", pad("available", 11), BytesShort(m.Available)),
		fmt.Sprintf(" %s %s", pad("buff/cache", 11), BytesShort(m.Buffers+m.Cached)),
	)
	if m.SwapTotal > 0 {
		L = append(L, fmt.Sprintf(" %s %s of %s", pad("swap", 11), BytesShort(m.SwapTotal-m.SwapFree), BytesShort(m.SwapTotal)))
	}
	return card(header, L)
}

// Disk renders /disk.
func Disk(s collect.Snapshot) string {
	var L []string
	width := 5
	for _, m := range s.Mounts {
		if len(m.MountPoint) > width && len(m.MountPoint) <= 12 {
			width = len(m.MountPoint)
		}
	}
	for _, m := range s.Mounts {
		L = append(L, fmt.Sprintf(" %s %s %s", pad(m.MountPoint, width), bar(m.UsedPercent),
			pad(fmt.Sprintf("%.0f%%", m.UsedPercent), -4)))
		L = append(L, fmt.Sprintf(" %s %s free of %s", pad("", width), BytesShort(m.FreeBytes), BytesShort(m.TotalBytes)))
	}
	busy := false
	for _, d := range s.Disks {
		if d.ReadBytesPerSec > 0 || d.WriteBytesPerSec > 0 {
			if !busy {
				L = append(L, divider)
				busy = true
			}
			L = append(L, fmt.Sprintf(" %s r %s w %s %.0f iops",
				pad(d.Name, 8), pad(Rate(d.ReadBytesPerSec), -7), pad(Rate(d.WriteBytesPerSec), -7), d.IOPS))
		}
	}
	if len(L) == 0 {
		L = append(L, " no mounts found")
	}
	return card("💾 <b>Disk</b>", L)
}

// Net renders /net. rxTrend and txTrend are pre-rendered sparklines of
// recent aggregate rates ("" = omit).
func Net(s collect.Snapshot, rxTrend, txTrend string) string {
	var L []string
	var idle []string
	if rxTrend != "" || txTrend != "" {
		L = append(L, " ↓ "+rxTrend, " ↑ "+txTrend, divider)
	}
	for _, n := range s.Net {
		if n.RxTotal == 0 && n.TxTotal == 0 {
			idle = append(idle, n.Name)
			continue
		}
		L = append(L, fmt.Sprintf(" %s ↓%s ↑%s", pad(n.Name, 11), pad(Rate(n.RxBytesPerSec), -8), pad(Rate(n.TxBytesPerSec), -8)))
		L = append(L, fmt.Sprintf(" %s Σ↓%s Σ↑%s", pad("", 11), pad(BytesShort(n.RxTotal), -7), pad(BytesShort(n.TxTotal), -7)))
	}
	if len(idle) > 0 {
		L = append(L, divider, " idle: "+strings.Join(idle, ", "))
	}
	if len(L) == 0 {
		L = append(L, " no interfaces found")
	}
	return card("🌐 <b>Network</b>", L)
}

// NetTrendVals converts per-interface rates into the aggregate point the
// trend ring stores for sparklines.
func NetTrendVals(rates []collect.NetRate) (rx, tx float64) {
	for _, n := range rates {
		rx += n.RxBytesPerSec
		tx += n.TxBytesPerSec
	}
	return rx, tx
}

// Temp renders /temp: junk sensors (≤0°C) dropped, hwmon duplicates of a
// zone reading collapsed, hottest first.
func Temp(th sysfs.Thermal) string {
	sensors := cleanSensors(th.Sensors)
	if len(sensors) == 0 && len(th.Fans) == 0 {
		return "🌡 No thermal sensors found (normal on a VPS)."
	}
	header := fmt.Sprintf("🌡 <b>Temperatures</b> — max %.0f°C", th.MaxCelsius())
	var L []string
	for i, s := range sensors {
		if i >= 12 {
			L = append(L, fmt.Sprintf(" … %d more", len(sensors)-12))
			break
		}
		mark := "  "
		if i == 0 {
			mark = "🔥"
		}
		L = append(L, fmt.Sprintf(" %s %s %s", mark, pad(s.Label, 14), pad(fmt.Sprintf("%.0f°C", s.Celsius), -5)))
	}
	for _, f := range th.Fans {
		L = append(L, fmt.Sprintf("    %s %s", pad(f.Label, 14), pad(fmt.Sprintf("%d RPM", f.RPM), -8)))
	}
	if th.Throttled {
		L = append(L, divider, " ⚠️ thermal throttling active")
	}
	return card(header, L)
}

// cleanSensors drops non-readings and duplicates, hottest first.
func cleanSensors(in []sysfs.TempSensor) []sysfs.TempSensor {
	var out []sysfs.TempSensor
	seen := map[string]bool{} // "<stem>:<rounded>" of accepted sensors
	for _, s := range in {
		if s.Celsius <= 0 {
			continue
		}
		stem, _, _ := strings.Cut(s.Label, "/")
		key := fmt.Sprintf("%s:%.0f", stem, s.Celsius)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Celsius > out[j].Celsius })
	return out
}

// Battery renders /battery.
func Battery(pw sysfs.Power) string {
	if !pw.HasBattery {
		return "🔋 No battery found (normal on a VPS)."
	}
	var parts []string
	for _, b := range pw.Batteries {
		header := fmt.Sprintf("🔋 <b>%s</b> — %s", esc(b.Name), esc(b.Status))
		L := []string{
			fmt.Sprintf(" %s %s %.0f%%", pad("charge", 7), bar(b.Percent), b.Percent),
		}
		if b.HealthPercent > 0 {
			L = append(L, fmt.Sprintf(" %s %s %.0f%% of design", pad("health", 7), bar(b.HealthPercent), b.HealthPercent))
		}
		if b.Watts > 0 {
			L = append(L, fmt.Sprintf(" %s %.1f W", pad("draw", 7), b.Watts))
		}
		if b.TimeToEmpty > 0 {
			L = append(L, fmt.Sprintf(" %s ~%s", pad("left", 7), Dur(b.TimeToEmpty)))
		}
		parts = append(parts, card(header, L))
	}
	if pw.HasAC {
		if pw.ACOnline {
			parts = append(parts, "🔌 plugged in")
		} else {
			parts = append(parts, "⚡ on battery")
		}
	}
	return strings.Join(parts, "\n")
}

// ServiceResults renders /services, healthy first.
func ServiceResults(results []services.Result) string {
	if len(results) == 0 {
		return "🧩 No services configured. Re-run the installer to add some."
	}
	order := func(s services.State) int {
		switch s {
		case services.StateOK:
			return 0
		case services.StateDegraded:
			return 1
		case services.StateDown:
			return 2
		default:
			return 3
		}
	}
	sorted := append([]services.Result(nil), results...)
	sort.SliceStable(sorted, func(i, j int) bool { return order(sorted[i].State) < order(sorted[j].State) })
	up := 0
	for _, r := range results {
		if r.State == services.StateOK {
			up++
		}
	}
	header := fmt.Sprintf("🧩 <b>Services</b> — %d/%d up", up, len(results))
	var L []string
	for _, r := range sorted {
		icon := map[services.State]string{
			services.StateOK:       "✅",
			services.StateDegraded: "⚠️",
			services.StateDown:     "❌",
			services.StateUnknown:  "❔",
		}[r.State]
		L = append(L, fmt.Sprintf(" %s %s %s", icon, pad(r.Name, 16), r.Detail))
	}
	return card(header, L)
}

// Docker renders /docker.
func Docker(cts []dockermon.Container) string {
	if len(cts) == 0 {
		return "🐳 No containers (or Docker is not running)."
	}
	running := 0
	for _, c := range cts {
		if c.State == "running" {
			running++
		}
	}
	header := fmt.Sprintf("🐳 <b>Containers</b> — %d/%d running", running, len(cts))
	var L []string
	for _, c := range cts {
		icon := "✅"
		if c.State != "running" {
			icon = "❌"
		}
		L = append(L, fmt.Sprintf(" %s %s %s", icon, pad(c.Name, 12), c.Image))
		if c.State == "running" && c.MemLimit > 0 {
			L = append(L, fmt.Sprintf("    cpu %.1f%%  mem %s/%s", c.CPUPercent, BytesShort(c.MemUsage), BytesShort(c.MemLimit)))
		} else if c.State != "running" {
			L = append(L, "    "+c.Status)
		}
		if c.RestartCount > 0 {
			L = append(L, fmt.Sprintf("    ↻ restarts: %d", c.RestartCount))
		}
	}
	return card(header, L)
}

// Top renders /top: the heaviest processes by CPU and by memory.
func Top(procs []collect.Proc, memTotal uint64) string {
	if len(procs) == 0 {
		return "🔝 No process data — try again in a moment."
	}
	byCPU := append([]collect.Proc(nil), procs...)
	sort.SliceStable(byCPU, func(i, j int) bool { return byCPU[i].CPUPercent > byCPU[j].CPUPercent })
	byMem := append([]collect.Proc(nil), procs...)
	sort.SliceStable(byMem, func(i, j int) bool { return byMem[i].RSSBytes > byMem[j].RSSBytes })

	const n = 5
	var L []string
	L = append(L, " by CPU")
	for _, p := range byCPU[:min(n, len(byCPU))] {
		L = append(L, fmt.Sprintf(" %s %s pid %d", pad(p.Comm, 15),
			pad(fmt.Sprintf("%.1f%%", p.CPUPercent), -6), p.PID))
	}
	L = append(L, divider, " by memory")
	for _, p := range byMem[:min(n, len(byMem))] {
		share := ""
		if memTotal > 0 {
			share = fmt.Sprintf(" %.0f%%", 100*float64(p.RSSBytes)/float64(memTotal))
		}
		L = append(L, fmt.Sprintf(" %s %s%s", pad(p.Comm, 15),
			pad(BytesShort(p.RSSBytes), -6), share))
	}
	header := fmt.Sprintf("🔝 <b>Top processes</b> — %d running", len(procs))
	return card(header, L)
}

// Sessions renders /ssh: live sessions with geo info.
func Sessions(sessions []sshwatch.Session, geo map[string]sshwatch.GeoInfo, now time.Time) string {
	if len(sessions) == 0 {
		return "👥 No active SSH sessions."
	}
	header := fmt.Sprintf("👥 <b>Active sessions</b> — %d", len(sessions))
	var L []string
	for i, s := range sessions {
		if i > 0 {
			L = append(L, "")
		}
		L = append(L, fmt.Sprintf(" %s %s %s", pad(s.User, 9), pad(s.TTY, 6), Dur(now.Sub(s.Since))))
		L = append(L, "   from "+s.Host)
		if g, ok := geo[s.Host]; ok && g.String() != "" {
			L = append(L, "   📍 "+g.String())
		}
	}
	return card(header, L)
}

// SSHEvents renders /ssh history and /ssh fails as an aligned table.
func SSHEvents(title string, events []sshwatch.Event) string {
	if len(events) == 0 {
		return "🔐 Nothing recorded yet."
	}
	header := "🔐 <b>" + esc(title) + "</b>"
	var L []string
	for _, e := range events {
		icon := map[sshwatch.EventKind]string{
			sshwatch.EventLogin:       "✅",
			sshwatch.EventFailed:      "❌",
			sshwatch.EventInvalidUser: "🚫",
			sshwatch.EventDisconnect:  "👋",
		}[e.Kind]
		detail := e.Method
		if e.InvalidUser {
			detail = "invalid user"
		}
		L = append(L, fmt.Sprintf(" %s %s %s %s", icon, e.At.Format("Jan02 15:04"), pad(e.User, 9), detail))
		L = append(L, "    "+e.IP)
	}
	return card(header, L)
}

// AlertMsg renders a push alert as a severity banner.
func AlertMsg(hostname string, a alert.Alert) string {
	icon := "ℹ️"
	switch {
	case a.Resolved:
		icon = "✅"
	case a.Severity == alert.Critical:
		icon = "🚨"
	case a.Severity == alert.Warning:
		icon = "⚠️"
	}
	return fmt.Sprintf("%s <b>%s</b> · %s\n<blockquote>%s</blockquote>",
		icon, esc(a.Title), esc(hostname), esc(a.Body))
}
