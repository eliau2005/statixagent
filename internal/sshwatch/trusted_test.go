package sshwatch

import (
	"net/netip"
	"testing"
)

func TestTrustedIPsContains(t *testing.T) {
	trusted := NewTrustedIPs([]netip.Prefix{
		netip.MustParsePrefix("203.0.113.7/32"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("2001:db8:1::/48"),
		netip.MustParsePrefix("2001:db8:ffff::42/128"),
	})
	cases := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.7", true},
		{"203.0.113.8", false},
		{"10.0.0.0", true},        // first address of /8
		{"10.255.255.255", true},  // last address of /8
		{"11.0.0.0", false},       // just past /8
		{"9.255.255.255", false},  // just before /8
		{"192.168.1.255", true},   // last address of /24
		{"192.168.2.0", false},    // just past /24
		{"::ffff:10.1.2.3", true}, // IPv4-mapped matches IPv4 range
		{"2001:db8:1::1", true},   // inside /48
		{"2001:db8:1:ffff:ffff:ffff:ffff:ffff", true},
		{"2001:db8:2::1", false}, // just past /48
		{"2001:db8:ffff::42", true},
		{"2001:db8:ffff::43", false},
		{"fe80::1%eth0", false},     // zone stripped, still not trusted
		{"host.example.com", false}, // UseDNS hostname
		{"", false},
	}
	for _, c := range cases {
		if got := trusted.Contains(c.ip); got != c.want {
			t.Errorf("Contains(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestTrustedIPsEmpty(t *testing.T) {
	for _, set := range []*TrustedIPs{nil, NewTrustedIPs(nil), {}} {
		if set.Contains("203.0.113.7") || set.Contains("::1") {
			t.Errorf("empty set %v must trust nothing", set)
		}
	}
}

func TestTrustedIPsZoneStripped(t *testing.T) {
	trusted := NewTrustedIPs([]netip.Prefix{netip.MustParsePrefix("fe80::/10")})
	if !trusted.Contains("fe80::1%eth0") {
		t.Error("link-local address with zone must match fe80::/10")
	}
}

func TestTrustedIPsMatchReportsUnparseableSource(t *testing.T) {
	trusted := NewTrustedIPs([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	cases := []struct {
		ip      string
		want    bool
		wantErr bool
	}{
		{"10.1.2.3", true, false},
		{"192.0.2.1", false, false}, // parseable, just not trusted
		{"host.example.com", false, true},
		{"", false, true},
	}
	for _, c := range cases {
		got, err := trusted.Match(c.ip)
		if got != c.want || (err != nil) != c.wantErr {
			t.Errorf("Match(%q) = %v, %v; want %v, err=%v", c.ip, got, err, c.want, c.wantErr)
		}
	}
	// An empty set has nothing to explain, so it never reports an error.
	if ok, err := NewTrustedIPs(nil).Match("host.example.com"); ok || err != nil {
		t.Errorf("empty set Match = %v, %v", ok, err)
	}
}
