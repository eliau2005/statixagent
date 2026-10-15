package agent

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// Settings view: alert thresholds tuned with −5/+5 buttons, persisted to
// the config like every other bot-driven change. The buttons carry the
// value they set, not the step (§6 idempotency): a replayed or doubled
// press sets the same value again and changes nothing.

// thresholdSpec describes one tunable threshold.
type thresholdSpec struct {
	key   string // callback token
	label string
	unit  string
	min   float64
	max   float64
	get   func(*config.Thresholds) *float64
}

var thresholdSpecs = []thresholdSpec{
	{"cpu", "🖥 CPU", "%", 50, 99, func(t *config.Thresholds) *float64 { return &t.CPUPercent }},
	{"mem", "🧠 Memory", "%", 50, 99, func(t *config.Thresholds) *float64 { return &t.MemPercent }},
	{"disk", "💾 Disk", "%", 50, 99, func(t *config.Thresholds) *float64 { return &t.DiskPercent }},
	{"temp", "🌡 Temp", "°C", 50, 105, func(t *config.Thresholds) *float64 { return &t.TempCelsius }},
	{"batt", "🔋 Battery", "%", 5, 50, func(t *config.Thresholds) *float64 { return &t.BatteryPercent }},
}

// thresholdStep is what one −/+ press moves a threshold by.
const thresholdStep = 5

// thresholdSpecFor returns the spec named key.
func thresholdSpecFor(key string) (thresholdSpec, bool) {
	for _, sp := range thresholdSpecs {
		if sp.key == key {
			return sp, true
		}
	}
	return thresholdSpec{}, false
}

// thresholds returns a copy of the current thresholds under the lock.
func (a *Agent) thresholds() config.Thresholds {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg.Thresholds
}

// settingsView renders the Settings screen as a message.
func (a *Agent) settingsView() (string, telegram.Keyboard) {
	return a.screen(context.Background(), tgui.Open(scrSettings))
}

// onOff is a digest state as the settings screen shows it.
func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// settingsScreen is the Settings section (§3.10): thresholds and the
// digest, tuned in place, and the way to Watching, Update, Clear chat and
// Help. Each −/+ button carries the value it sets; the value in the
// middle explains the row when pressed.
func (a *Agent) settingsScreen(_ context.Context, _ tgui.Call) tgui.View {
	t := a.thresholds()
	var rows []string
	var kb [][]tgui.Button
	for _, sp := range thresholdSpecs {
		v := *sp.get(&t)
		val := fmt.Sprintf("%.0f%s", v, sp.unit)
		rows = append(rows, padRight(stripEmoji(sp.label)+" alert", 15)+val)
		// Targets are whole numbers: a value from the config file such as
		// 87.5 steps to 83 and 93.
		to := func(delta float64) tgui.Call {
			target := clamp(math.Round(v)+delta, sp.min, sp.max)
			return tgui.Call{Act: cfgThreshold, Args: []string{sp.key, strconv.FormatFloat(target, 'f', 0, 64)}}
		}
		kb = append(kb, []tgui.Button{
			{Label: sp.label + " −5", Call: to(-thresholdStep)},
			{Label: sp.label + " " + val, Call: tgui.Call{Act: cfgThreshold, Args: []string{sp.key}}},
			{Label: sp.label + " +5", Call: to(thresholdStep)},
		})
	}
	enabled, hour := a.digestCfg()
	rows = append(rows, padRight("Daily digest", 15)+fmt.Sprintf("%s · %02d:00", onOff(enabled), hour))
	at := func(h int) tgui.Call {
		return tgui.Call{Act: cfgDigestAt, Args: []string{strconv.Itoa((h + 24) % 24)}}
	}
	kb = append(kb,
		[]tgui.Button{
			{Label: "📰 Digest: " + onOff(enabled), Call: tgui.Call{Act: cfgDigest, Args: []string{onOff(!enabled)}}},
			{Label: "−1h", Call: at(hour - 1)},
			{Label: fmt.Sprintf("%02d:00", hour), Call: tgui.Call{Act: cfgDigestAt}},
			{Label: "+1h", Call: at(hour + 1)},
		},
		[]tgui.Button{
			{Label: "👁 Watching", Call: tgui.Open(scrWatching)},
			{Label: "⬇️ Update", Call: tgui.Open(scrUpdate)},
			{Label: "🧹 Clear chat", Call: tgui.Call{Act: askClear}},
		},
		[]tgui.Button{{Label: "❓ Help", Call: tgui.Open(scrHelp)}},
	)
	return tgui.View{
		Text: "⚙️ <b>Settings</b>\nAlert thresholds and the daily digest:\n" + pre(rows) +
			"\nAlerts fire when a value crosses its threshold (battery: when below). Steps of 5.",
		Rows: kb,
	}
}

// thresholdPress handles "~1th|<key>|<target>": it sets the threshold to
// target and shows Settings again. Without a target it is the value
// label in the middle of the row, which only explains itself.
func (a *Agent) thresholdPress(ctx context.Context, cb *telegram.Callback, c tgui.Call) {
	if len(c.Args) == 0 || len(c.Args) > 2 {
		a.refuseCallback(ctx, cb, false)
		return
	}
	sp, ok := thresholdSpecFor(c.Args[0])
	if !ok {
		a.refuseCallback(ctx, cb, false)
		return
	}
	name := stripEmoji(sp.label) + " alert"
	if len(c.Args) == 1 {
		a.answer(ctx, cb, "Tap −5 or +5 to change the "+name+".")
		return
	}
	// A whole number in range, in canonical form: anything else, such as
	// NaN, Inf or a forged extreme, is not a button the screen emits.
	n, err := strconv.Atoi(c.Args[1])
	target := float64(n)
	if err != nil || strconv.Itoa(n) != c.Args[1] || target < sp.min || target > sp.max {
		a.refuseCallback(ctx, cb, false)
		return
	}
	a.mu.Lock()
	v := sp.get(&a.cfg.Thresholds)
	changed := *v != target
	*v = target
	cfg := a.cfg
	a.mu.Unlock()
	toast := fmt.Sprintf("%s is already %d%s", name, n, sp.unit)
	if changed {
		toast = fmt.Sprintf("%s → %d%s%s", name, n, sp.unit, a.persist(cfg))
	}
	text, kb := a.settingsView()
	a.finishCallback(ctx, cb, false, text, kb, toast)
}

// digestPress handles "~1dg|on" and "~1dg|off": the state the digest is
// switched to.
func (a *Agent) digestPress(ctx context.Context, cb *telegram.Callback, c tgui.Call) {
	if len(c.Args) != 1 || (c.Args[0] != "on" && c.Args[0] != "off") {
		a.refuseCallback(ctx, cb, false)
		return
	}
	on := c.Args[0] == "on"
	a.mu.Lock()
	changed := a.cfg.Digest.Enabled != on
	a.cfg.Digest.Enabled = on
	cfg := a.cfg
	a.mu.Unlock()
	toast := "Digest is already " + c.Args[0]
	if changed {
		toast = "Digest " + c.Args[0] + a.persist(cfg)
	}
	text, kb := a.settingsView()
	a.finishCallback(ctx, cb, false, text, kb, toast)
}

// digestAtPress handles "~1dh|<hour>", the hour the digest moves to; bare
// "~1dh" is the hour label, which only explains itself.
func (a *Agent) digestAtPress(ctx context.Context, cb *telegram.Callback, c tgui.Call) {
	if len(c.Args) == 0 {
		a.answer(ctx, cb, "Tap −1h or +1h to move the daily digest.")
		return
	}
	hour, err := strconv.Atoi(c.Args[0])
	if len(c.Args) != 1 || err != nil || strconv.Itoa(hour) != c.Args[0] || hour < 0 || hour > 23 {
		a.refuseCallback(ctx, cb, false)
		return
	}
	a.mu.Lock()
	changed := a.cfg.Digest.Hour != hour
	a.cfg.Digest.Hour = hour
	cfg := a.cfg
	a.mu.Unlock()
	toast := fmt.Sprintf("Digest is already at %02d:00", hour)
	if changed {
		toast = fmt.Sprintf("Digest at %02d:00%s", hour, a.persist(cfg))
	}
	text, kb := a.settingsView()
	a.finishCallback(ctx, cb, false, text, kb, toast)
}

// handleSettingsCallback processes the ⚙️ buttons of older versions,
// which carry a step rather than a value: each press applies its step
// once. Same contract as handleWatchCallback.
func (a *Agent) handleSettingsCallback(_ context.Context, data string) (string, telegram.Keyboard, string, bool) {
	switch {
	case data == "settings":
		text, kb := a.settingsView()
		return text, kb, "", true

	case data == "noop":
		return "", nil, "", true

	case data == "dg:toggle":
		a.mu.Lock()
		a.cfg.Digest.Enabled = !a.cfg.Digest.Enabled
		enabled := a.cfg.Digest.Enabled
		cfg := a.cfg
		a.mu.Unlock()
		text, kb := a.settingsView()
		return text, kb, "Digest " + onOff(enabled) + a.persist(cfg), true

	case strings.HasPrefix(data, "dg:hour:"):
		// Only the two steps the keyboard emitted are accepted.
		delta, err := strconv.Atoi(strings.TrimPrefix(data, "dg:hour:"))
		if err != nil || (delta != -1 && delta != 1) {
			return "", nil, "bad action", true
		}
		a.mu.Lock()
		hour := ((a.cfg.Digest.Hour+delta)%24 + 24) % 24
		a.cfg.Digest.Hour = hour
		cfg := a.cfg
		a.mu.Unlock()
		text, kb := a.settingsView()
		return text, kb, fmt.Sprintf("Digest at %02d:00%s", hour, a.persist(cfg)), true

	case strings.HasPrefix(data, "th:"):
		parts := strings.Split(data, ":")
		if len(parts) != 3 {
			return "", nil, "bad action", true
		}
		// Only the two steps the keyboard emits are accepted: forged data
		// such as NaN or Inf would otherwise be saved and silence the alert.
		delta, err := strconv.ParseFloat(parts[2], 64)
		if err != nil || (delta != -thresholdStep && delta != thresholdStep) {
			return "", nil, "bad action", true
		}
		sp, ok := thresholdSpecFor(parts[1])
		if !ok {
			return "", nil, "unknown threshold", true
		}
		a.mu.Lock()
		v := sp.get(&a.cfg.Thresholds)
		next := clamp(*v+delta, sp.min, sp.max)
		*v = next
		cfg := a.cfg
		a.mu.Unlock()
		toast := fmt.Sprintf("%s → %.0f%s%s", stripEmoji(sp.label), next, sp.unit, a.persist(cfg))
		text, kb := a.settingsView()
		return text, kb, toast, true
	}
	return "", nil, "", false
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

// stripEmoji drops the leading emoji+space from a settings label for use
// in monospace text and toasts.
func stripEmoji(label string) string {
	if i := strings.IndexByte(label, ' '); i > 0 {
		return label[i+1:]
	}
	return label
}
