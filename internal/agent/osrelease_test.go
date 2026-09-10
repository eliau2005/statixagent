package agent

import (
	"strings"
	"testing"
)

func TestParseOSRelease(t *testing.T) {
	const raw = `# a comment
NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.20.3
PRETTY_NAME='Alpine Linux v3.20'

ID_LIKE="rhel fedora"
malformed line
`
	kv := ParseOSRelease(strings.NewReader(raw))
	for _, tc := range []struct{ key, want string }{
		{"NAME", "Alpine Linux"},
		{"ID", "alpine"},
		{"VERSION_ID", "3.20.3"},
		{"PRETTY_NAME", "Alpine Linux v3.20"},
		{"ID_LIKE", "rhel fedora"},
	} {
		if got := kv[tc.key]; got != tc.want {
			t.Errorf("%s = %q, want %q", tc.key, got, tc.want)
		}
	}
	if _, ok := kv["malformed line"]; ok {
		t.Errorf("a line without = must be skipped: %+v", kv)
	}
	if len(kv) != 5 {
		t.Errorf("parsed %d keys, want 5: %+v", len(kv), kv)
	}
}

func TestUFWInstallHint(t *testing.T) {
	cases := []struct {
		name string
		osr  map[string]string
		want string
	}{
		{"ubuntu", map[string]string{"ID": "ubuntu"}, "apt install ufw"},
		{"alpine", map[string]string{"ID": "alpine"}, "apk add ufw"},
		{"arch", map[string]string{"ID": "arch"}, "pacman -S ufw"},
		{"rocky", map[string]string{"ID": "rocky"}, "dnf install ufw"},
		// An unknown derivative falls back to the family it declares.
		{"via ID_LIKE", map[string]string{"ID": "myrhel", "ID_LIKE": "rhel fedora"}, "dnf install ufw"},
		{"mixed case", map[string]string{"ID": "Debian"}, "apt install ufw"},
	}
	for _, tc := range cases {
		if got := ufwInstallHint(tc.osr); !strings.Contains(got, tc.want) {
			t.Errorf("%s: hint = %q, want it to contain %q", tc.name, got, tc.want)
		}
	}

	// The RHEL family needs EPEL — suggesting a bare dnf install would fail.
	if got := ufwInstallHint(map[string]string{"ID": "rocky"}); !strings.Contains(got, "EPEL") {
		t.Errorf("rhel-family hint must mention EPEL: %q", got)
	}

	// Unknown or unreadable os-release lists the common managers rather
	// than guessing one wrong.
	for _, osr := range []map[string]string{nil, {}, {"ID": "plan9"}} {
		got := ufwInstallHint(osr)
		for _, want := range []string{"apt install ufw", "dnf install ufw", "apk add ufw", "pacman -S ufw"} {
			if !strings.Contains(got, want) {
				t.Errorf("generic hint for %+v = %q, missing %q", osr, got, want)
			}
		}
	}
}

func TestFirewallMissingUFWUsesDistroHint(t *testing.T) {
	a := testAgent(&fakeSender{})
	a.src.Runner = &missingUFW{}
	a.src.OSRelease = func() map[string]string { return map[string]string{"ID": "alpine"} }
	text, _ := a.firewallView(t.Context())
	if !strings.Contains(text, "apk add ufw") {
		t.Errorf("missing-ufw view must suggest this distro's package manager: %q", text)
	}
}
