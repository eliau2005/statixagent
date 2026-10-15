package bot

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/eliau2005/statixagent/internal/alert"
	"github.com/eliau2005/statixagent/internal/collect"
	"github.com/eliau2005/statixagent/internal/sshwatch"
	"github.com/eliau2005/statixagent/internal/sysfs"
)

// Messages are "dashboard cards": a header line with the entity in <b>,
// then a <pre> block with monospace-aligned rows. <pre> gives alignment
// and stops Telegram from turning paths like /boot into bot-command links.

const divider = "────────────────────────────"

// PreCols is the widest a <pre> row may be: wider rows wrap on a phone.
const PreCols = 32

// Width is the number of monospace columns s takes on a phone: emoji
// count as two, variation selectors and joiners as none.
func Width(s string) int {
	n := 0
	for _, r := range s {
		n += runeWidth(r)
	}
	return n
}

func runeWidth(r rune) int {
	switch {
	case r == 0xFE0F || r == 0x200D || (r >= 0x0300 && r <= 0x036F):
		return 0
	case r >= 0x1F000,
		r >= 0x2600 && r <= 0x27BF, // ✅ ❌ ⚠ ⚡ …
		r >= 0x2B00 && r <= 0x2BFF, // ⬅ ⬇ ⭐
		r == 0x231A || r == 0x231B, // ⌚ ⌛
		r >= 0x23E9 && r <= 0x23FA: // ⏩ … ⏺
		return 2
	}
	return 1
}

// Clip cuts s to at most cols columns, marking a cut with "…".
func Clip(s string, cols int) string {
	if Width(s) <= cols {
		return s
	}
	var b strings.Builder
	w := 0
	for _, r := range s {
		if w+runeWidth(r) > cols-1 {
			break
		}
		b.WriteRune(r)
		w += runeWidth(r)
	}
	return b.String() + "…"
}

// Wrap breaks a <pre> row wider than PreCols into rows that fit, at a
// space when one is near the edge; continuation rows are indented.
// Nothing is dropped: a long address or path stays whole across rows.
func Wrap(line string) []string {
	const indent = "    "
	var out []string
	for Width(line) > PreCols {
		cut, w, lastSpace := 0, 0, -1
		for i, r := range line {
			if w+runeWidth(r) > PreCols {
				break
			}
			if r == ' ' && w > PreCols/2 {
				lastSpace = i
			}
			w += runeWidth(r)
			cut = i + len(string(r))
		}
		if lastSpace > 0 {
			cut = lastSpace
		}
		out = append(out, strings.TrimRight(line[:cut], " "))
		line = indent + strings.TrimLeft(line[cut:], " ")
	}
	return append(out, line)
}

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
	filled := min(max(int(percent/10+0.5), 0), 10)
	return strings.Repeat("▰", filled) + strings.Repeat("▱", 10-filled)
}

// Pad fits s to exactly cols columns, counting emoji as two: longer text
// is clipped with "…", shorter is filled with spaces on the right, or on
// the left when cols is negative (numbers). Columns never shift.
func Pad(s string, cols int) string {
	left := cols < 0
	if left {
		cols = -cols
	}
	s = Clip(s, cols)
	fill := strings.Repeat(" ", max(0, cols-Width(s)))
	if left {
		return fill + s
	}
	return s + fill
}

// itemCols is the name column of a list row: a state emoji and a space
// before it, a space and the status after it, 32 columns in all.
const itemCols = 16

// ItemRow is one row of a services list in 32 columns: a state emoji, the
// name and a short status, as in "❌ postgresql       failed". Long names
// and statuses are clipped with "…".
func ItemRow(icon, name, status string) string {
	row := icon + " " + Pad(name, itemCols) + " " + Clip(status, PreCols-Width(icon)-itemCols-2)
	return strings.TrimRight(row, " ")
}

// ItemRows is a list item whose status needs a line of its own (a URL,
// a certificate's expiry): the emoji and name, then the note indented.
func ItemRows(icon, name, note string) []string {
	rows := []string{icon + " " + Clip(name, PreCols-Width(icon)-1)}
	if note != "" {
		rows = append(rows, "   "+Clip(note, PreCols-3))
	}
	return rows
}

// HubRow is one kind on the services hub: its label, how many there are
// and a mark for their state, "Units          12  ❌ 1".
func HubRow(label, count, mark string) string {
	return strings.TrimRight(Pad(label, 12)+Pad(count, -5)+"  "+mark, " ")
}

// kvGutter is the label column of a detail screen; kvRows is the most
// rows one value may take.
const (
	kvGutter = 9
	kvRows   = 3
)

// KV is one field of a detail screen: the label in a 9-column gutter and
// the value after it, continued under it when it is too wide (an image
// name) and clipped with "…" past three rows. An empty value is "—".
func KV(label, value string) []string {
	if value == "" {
		value = "—"
	}
	prefix := Pad(label, kvGutter)
	var rows []string
	for value != "" {
		if len(rows) == kvRows-1 {
			return append(rows, prefix+Clip(value, PreCols-kvGutter))
		}
		head, rest := cut(value, PreCols-kvGutter)
		rows = append(rows, prefix+head)
		prefix, value = strings.Repeat(" ", kvGutter), rest
	}
	return rows
}

// cut splits s after at most cols columns.
func cut(s string, cols int) (head, rest string) {
	w := 0
	for i, r := range s {
		if w+runeWidth(r) > cols {
			return s[:i], s[i:]
		}
		w += runeWidth(r)
	}
	return s, ""
}

// Age renders how long ago something happened in one unit, for tight
// rows: "45s", "2m", "3h", "12d".
func Age(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d >= time.Hour:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d >= time.Minute:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return fmt.Sprintf("%ds", max(0, int(d/time.Second)))
}

// PreRows returns the rows of every <pre> block in html, unescaped, so
// tests can measure them.
func PreRows(html string) []string {
	unesc := strings.NewReplacer("&lt;", "<", "&gt;", ">", "&amp;", "&", "&#34;", `"`, "&#39;", "'", "&quot;", `"`)
	var rows []string
	for {
		_, rest, ok := strings.Cut(html, "<pre>")
		if !ok {
			return rows
		}
		body, after, _ := strings.Cut(rest, "</pre>")
		rows = append(rows, strings.Split(unesc.Replace(body), "\n")...)
		html = after
	}
}

// card assembles header + <pre> body lines, wrapped to PreCols.
func card(header string, lines []string) string {
	var rows []string
	for _, l := range lines {
		rows = append(rows, Wrap(l)...)
	}
	body := esc(strings.Join(rows, "\n"))
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
	L = append(L, fmt.Sprintf(" %s %s %s", Pad("CPU", 5), bar(s.CPUTotal.Percent), Pad(fmt.Sprintf("%.0f%%", s.CPUTotal.Percent), -4)))
	L = append(L, fmt.Sprintf(" %s %s %s %s/%s", Pad("RAM", 5), bar(s.Mem.UsedPercent()),
		Pad(fmt.Sprintf("%.0f%%", s.Mem.UsedPercent()), -4),
		BytesShort(s.Mem.Total-s.Mem.Available), BytesShort(s.Mem.Total)))
	if used := s.Mem.SwapTotal - s.Mem.SwapFree; s.Mem.SwapTotal > 0 && used > s.Mem.SwapTotal/100 {
		pct := 100 * float64(used) / float64(s.Mem.SwapTotal)
		L = append(L, fmt.Sprintf(" %s %s %s %s/%s", Pad("SWAP", 5), bar(pct),
			Pad(fmt.Sprintf("%.0f%%", pct), -4), BytesShort(used), BytesShort(s.Mem.SwapTotal)))
	}
	label := "DISK"
	for _, m := range s.Mounts {
		L = append(L, fmt.Sprintf(" %s %s %s  %s", Pad(label, 5), bar(m.UsedPercent),
			Pad(fmt.Sprintf("%.0f%%", m.UsedPercent), -4), m.MountPoint))
		label = ""
	}
	L = append(L, divider)
	for _, n := range activeNet(s.Net) {
		L = append(L, fmt.Sprintf(" 📶 %s ↓%s ↑%s", Pad(n.Name, 8), Pad(Rate(n.RxBytesPerSec), -8), Pad(Rate(n.TxBytesPerSec), -8)))
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
	L = append(L, fmt.Sprintf(" %d procs · %d fds", s.NumProc, s.FileNR.Allocated),
		fmt.Sprintf(" load %.2f %.2f %.2f", s.Load.Load1, s.Load.Load5, s.Load.Load15))
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
		L = append(L, fmt.Sprintf(" %s %s %s", Pad(c.Name, 5), bar(c.Percent), Pad(fmt.Sprintf("%.0f%%", c.Percent), -4)))
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
		fmt.Sprintf(" %s %s", Pad("used", 11), BytesShort(m.Total-m.Available)),
		fmt.Sprintf(" %s %s", Pad("available", 11), BytesShort(m.Available)),
		fmt.Sprintf(" %s %s", Pad("buff/cache", 11), BytesShort(m.Buffers+m.Cached)),
	)
	if m.SwapTotal > 0 {
		L = append(L, fmt.Sprintf(" %s %s of %s", Pad("swap", 11), BytesShort(m.SwapTotal-m.SwapFree), BytesShort(m.SwapTotal)))
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
		L = append(L, fmt.Sprintf(" %s %s %s", Pad(m.MountPoint, width), bar(m.UsedPercent),
			Pad(fmt.Sprintf("%.0f%%", m.UsedPercent), -4)))
		L = append(L, fmt.Sprintf(" %s %s free of %s", Pad("", width), BytesShort(m.FreeBytes), BytesShort(m.TotalBytes)))
	}
	busy := false
	for _, d := range s.Disks {
		if d.ReadBytesPerSec > 0 || d.WriteBytesPerSec > 0 {
			if !busy {
				L = append(L, divider)
				busy = true
			}
			L = append(L, fmt.Sprintf(" %s r%s w%s", Pad(d.Name, 8), Pad(Rate(d.ReadBytesPerSec), -9), Pad(Rate(d.WriteBytesPerSec), -9)),
				fmt.Sprintf(" %s %.0f iops", Pad("", 8), d.IOPS))
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
		L = append(L, fmt.Sprintf(" %s ↓%s ↑%s", Pad(n.Name, 11), Pad(Rate(n.RxBytesPerSec), -8), Pad(Rate(n.TxBytesPerSec), -8)))
		L = append(L, fmt.Sprintf(" %s Σ↓%s Σ↑%s", Pad("", 11), Pad(BytesShort(n.RxTotal), -7), Pad(BytesShort(n.TxTotal), -7)))
	}
	if len(idle) > 0 {
		L = append(L, divider, " idle: "+strings.Join(idle, ", "))
	}
	if len(L) == 0 {
		L = append(L, " no interfaces found")
	}
	return card("📶 <b>Network</b>", L)
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
		L = append(L, fmt.Sprintf(" %s %s %s", mark, Pad(s.Label, 14), Pad(fmt.Sprintf("%.0f°C", s.Celsius), -5)))
	}
	for _, f := range th.Fans {
		L = append(L, fmt.Sprintf("    %s %s", Pad(f.Label, 14), Pad(fmt.Sprintf("%d RPM", f.RPM), -8)))
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
			fmt.Sprintf(" %s %s %.0f%%", Pad("charge", 7), bar(b.Percent), b.Percent),
		}
		if b.HealthPercent > 0 {
			L = append(L, fmt.Sprintf(" %s %s %.0f%%", Pad("health", 7), bar(b.HealthPercent), b.HealthPercent),
				fmt.Sprintf(" %s of design capacity", Pad("", 7)))
		}
		if b.Watts > 0 {
			L = append(L, fmt.Sprintf(" %s %.1f W", Pad("draw", 7), b.Watts))
		}
		if b.TimeToEmpty > 0 {
			L = append(L, fmt.Sprintf(" %s ~%s", Pad("left", 7), Dur(b.TimeToEmpty)))
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
		L = append(L, fmt.Sprintf(" %s %s pid %d", Pad(p.Comm, 14),
			Pad(fmt.Sprintf("%.1f%%", p.CPUPercent), -6), p.PID))
	}
	L = append(L, divider, " by memory")
	for _, p := range byMem[:min(n, len(byMem))] {
		share := ""
		if memTotal > 0 {
			share = fmt.Sprintf(" %.0f%%", 100*float64(p.RSSBytes)/float64(memTotal))
		}
		L = append(L, fmt.Sprintf(" %s %s%s", Pad(p.Comm, 14),
			Pad(BytesShort(p.RSSBytes), -6), share))
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
		L = append(L, fmt.Sprintf(" %s %s %s", Pad(s.User, 9), Pad(s.TTY, 6), Dur(now.Sub(s.Since))))
		L = append(L, "   from "+s.Host)
		if g, ok := geo[s.Host]; ok && g.String() != "" {
			L = append(L, "   📍 "+g.String())
		}
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
