package agent

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/telegram"
)

// Settings view: alert thresholds tuned with ➖/➕ buttons, persisted to the
// config like every other bot-driven change.

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

// thresholds returns a copy of the current thresholds under the lock.
func (a *Agent) thresholds() config.Thresholds {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg.Thresholds
}

// settingsView renders current thresholds with tune buttons.
func (a *Agent) settingsView() (string, telegram.Keyboard) {
	t := a.thresholds()
	var b strings.Builder
	b.WriteString("⚙️ <b>Alert thresholds</b>\nTune with ➖ / ➕ (steps of 5):\n<pre>")
	var kb telegram.Keyboard
	for _, sp := range thresholdSpecs {
		val := *sp.get(&t)
		fmt.Fprintf(&b, " %s %s\n", padRight(stripEmoji(sp.label), 9), fmt.Sprintf("%.0f%s", val, sp.unit))
		kb = append(kb, []telegram.Button{
			{Text: "➖", Data: "th:" + sp.key + ":-5"},
			{Text: fmt.Sprintf("%s %.0f%s", sp.label, val, sp.unit), Data: "noop"},
			{Text: "➕", Data: "th:" + sp.key + ":+5"},
		})
	}
	b.WriteString("</pre>\nAlerts fire when a value crosses its threshold\n(battery: when below).")
	enabled, hour := a.digestCfg()
	state := "off"
	if enabled {
		state = "on"
	}
	fmt.Fprintf(&b, "\n\n📰 Daily digest <b>%s</b> at %02d:00 — tap the middle\nbutton to toggle, ➖/➕ to shift the hour.", state, hour)
	kb = append(kb, []telegram.Button{
		{Text: "➖", Data: "dg:hour:-1"},
		{Text: fmt.Sprintf("📰 %s · %02d:00", state, hour), Data: "dg:toggle"},
		{Text: "➕", Data: "dg:hour:+1"},
	})
	kb = append(kb, []telegram.Button{{Text: "⬅️ Status", Data: "status"}, {Text: "👁 Watching", Data: "watching"}})
	return b.String(), kb
}

// handleSettingsCallback processes ⚙️ buttons. Same contract as
// handleWatchCallback.
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
		state := "off"
		if enabled {
			state = "on"
		}
		text, kb := a.settingsView()
		return text, kb, "Digest " + state + a.persist(cfg), true

	case strings.HasPrefix(data, "dg:hour:"):
		delta, err := strconv.Atoi(strings.TrimPrefix(data, "dg:hour:"))
		if err != nil {
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
		delta, err := strconv.ParseFloat(parts[2], 64)
		if err != nil {
			return "", nil, "bad action", true
		}
		var toast string
		for _, sp := range thresholdSpecs {
			if sp.key != parts[1] {
				continue
			}
			a.mu.Lock()
			v := sp.get(&a.cfg.Thresholds)
			next := clamp(*v+delta, sp.min, sp.max)
			*v = next
			cfg := a.cfg
			a.mu.Unlock()
			toast = fmt.Sprintf("%s → %.0f%s%s", stripEmoji(sp.label), next, sp.unit, a.persist(cfg))
		}
		if toast == "" {
			return "", nil, "unknown threshold", true
		}
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
