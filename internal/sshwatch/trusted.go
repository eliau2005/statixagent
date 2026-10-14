package sshwatch

import (
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

// Contains reports whether ip, as logged by sshd, falls inside a trusted
// range. IPv4-mapped IPv6 addresses match their IPv4 range; anything that
// is not a literal address (e.g. a hostname under UseDNS) is never trusted.
func (t *TrustedIPs) Contains(ip string) bool {
	if t == nil || len(t.prefixes) == 0 {
		return false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	addr = addr.WithZone("").Unmap()
	for _, p := range t.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
