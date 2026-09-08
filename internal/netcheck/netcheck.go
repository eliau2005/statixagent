// Package netcheck verifies the reachability concerns of MVP §3: expiring
// SSL certificates on configured endpoints.
package netcheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"strings"
	"time"
)

// CertStatus is the result of one certificate check.
type CertStatus struct {
	Host     string
	NotAfter time.Time
	// DaysLeft is whole days until expiry, rounded down, so a certificate
	// that expired at any point in the past is always negative: -1 covers
	// the first 24 hours after NotAfter. Negative means expired.
	DaysLeft int
	Subject  string
	Err      string // non-empty when the handshake failed
}

// CheckCert connects to host (host or host:port, default 443) and reports
// the leaf certificate's expiry. The chain is read without trust validation:
// the agent reports expiry even for self-signed or private-CA certs.
func CheckCert(ctx context.Context, host string, now time.Time) CertStatus {
	addr := host
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}
	serverName, _, _ := strings.Cut(addr, ":")
	st := CertStatus{Host: host}

	d := tls.Dialer{Config: &tls.Config{
		InsecureSkipVerify: true, // expiry check only; trust is not the question here
		ServerName:         serverName,
	}}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := d.DialContext(dctx, "tcp", addr)
	if err != nil {
		st.Err = err.Error()
		return st
	}
	defer conn.Close()

	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		st.Err = "no peer certificate"
		return st
	}
	leaf := certs[0]
	st.NotAfter = leaf.NotAfter
	st.Subject = leaf.Subject.CommonName
	st.DaysLeft = int(math.Floor(leaf.NotAfter.Sub(now).Hours() / 24))
	return st
}

// CheckCerts checks every host with a shared deadline.
func CheckCerts(ctx context.Context, hosts []string, now time.Time) []CertStatus {
	out := make([]CertStatus, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, CheckCert(ctx, h, now))
	}
	return out
}

// Heartbeat-style latency check: time to open a TCP connection.
func Latency(ctx context.Context, addr string) (time.Duration, error) {
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}
	var d net.Dialer
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := d.DialContext(dctx, "tcp", addr)
	if err != nil {
		return 0, fmt.Errorf("netcheck: %w", err)
	}
	conn.Close()
	return time.Since(start), nil
}
