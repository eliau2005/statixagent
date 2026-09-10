package agent

import (
	"bufio"
	"io"
	"strings"
)

// /etc/os-release is the portable way to name a distribution, and the only
// thing the agent needs it for is suggesting the right package manager when
// /firewall finds no ufw. Reading the file stays behind Sources.OSRelease so
// this package keeps its hands off the filesystem (docs/ARCHITECTURE.md).

// ParseOSRelease reads the KEY=value lines of an os-release file. Values may
// be bare, single- or double-quoted; comments and blank lines are skipped.
func ParseOSRelease(r io.Reader) map[string]string {
	kv := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		kv[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return kv
}

// ufwInstallHints maps a distribution id to the command that installs ufw.
// The values are HTML — they are spliced into the /firewall view. The RHEL
// family carries the EPEL caveat because ufw is not in the base repos there.
var ufwInstallHints = map[string]string{
	"debian":              "<code>apt install ufw</code>",
	"ubuntu":              "<code>apt install ufw</code>",
	"raspbian":            "<code>apt install ufw</code>",
	"linuxmint":           "<code>apt install ufw</code>",
	"pop":                 "<code>apt install ufw</code>",
	"devuan":              "<code>apt install ufw</code>",
	"fedora":              "<code>dnf install ufw</code>",
	"rhel":                "<code>dnf install ufw</code> (needs the EPEL repository)",
	"centos":              "<code>dnf install ufw</code> (needs the EPEL repository)",
	"rocky":               "<code>dnf install ufw</code> (needs the EPEL repository)",
	"almalinux":           "<code>dnf install ufw</code> (needs the EPEL repository)",
	"alpine":              "<code>apk add ufw</code>",
	"arch":                "<code>pacman -S ufw</code>",
	"manjaro":             "<code>pacman -S ufw</code>",
	"endeavouros":         "<code>pacman -S ufw</code>",
	"opensuse":            "<code>zypper install ufw</code>",
	"opensuse-leap":       "<code>zypper install ufw</code>",
	"opensuse-tumbleweed": "<code>zypper install ufw</code>",
	"sles":                "<code>zypper install ufw</code>",
	"suse":                "<code>zypper install ufw</code>",
}

// ufwInstallHint suggests how to install ufw on this distribution. An
// unknown or unreadable os-release lists the common package managers
// instead of guessing one wrong.
func ufwInstallHint(osr map[string]string) string {
	for _, id := range osIDs(osr) {
		if cmd, ok := ufwInstallHints[id]; ok {
			return cmd
		}
	}
	return "<code>apt install ufw</code> · <code>dnf install ufw</code> (EPEL) · " +
		"<code>apk add ufw</code> · <code>pacman -S ufw</code>"
}

// osIDs is ID followed by the ID_LIKE tokens — most specific first, so a
// derivative we know by name beats the family it declares kinship with.
func osIDs(osr map[string]string) []string {
	var ids []string
	if id := strings.ToLower(strings.TrimSpace(osr["ID"])); id != "" {
		ids = append(ids, id)
	}
	return append(ids, strings.Fields(strings.ToLower(osr["ID_LIKE"]))...)
}
