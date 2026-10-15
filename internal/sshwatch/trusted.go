package sshwatch

import (
	"fmt"
	"net/netip"
	"strings"
)

// TrustedIPs matches SSH source addresses against the configured trusted
// ranges, so a login from the owner's own network can skip the alert.
// The zero value trusts nothing.
type TrustedIPs struct {
	prefixes []netip.Prefix
}

// NewTrustedIPs returns a matcher for the given ranges. Callers parse and
// validate entries up front (config.ParseTrustedIP).
func NewTrustedIPs(prefixes []netip.Prefix) *TrustedIPs {
	return &TrustedIPs{prefixes: append([]netip.Prefix(nil), prefixes...)}
}

// Empty reports whether no ranges are trusted.
func (t *TrustedIPs) Empty() bool {
	return t == nil || len(t.prefixes) == 0
}

// Match reports whether ip, as logged by sshd, falls inside a trusted range.
// IPv4-mapped IPv6 addresses match their IPv4 range. A source that is not
// a literal address (e.g. a hostname under UseDNS) is never trusted; Match
// returns an error for it so the caller can say why a listed range did not
// apply.
func (t *TrustedIPs) Match(ip string) (bool, error) {
	if t.Empty() {
		return false, nil
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false, fmt.Errorf("source %q is not an IP literal", ip)
	}
	addr = addr.WithZone("").Unmap()
	for _, p := range t.prefixes {
		if p.Contains(addr) {
			return true, nil
		}
	}
	return false, nil
}

// Contains is Match without the reason: unparseable sources are untrusted.
func (t *TrustedIPs) Contains(ip string) bool {
	ok, _ := t.Match(ip)
	return ok
}
