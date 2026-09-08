package netcheck

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// startTLSServer runs a TLS listener with a cert expiring at notAfter and
// returns its host:port.
func startTLSServer(t *testing.T, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.local"},
		NotBefore:    notAfter.Add(-24 * 365 * time.Hour),
		NotAfter:     notAfter,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				c.(*tls.Conn).Handshake()
				c.Close()
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// A cert that died a few hours ago must read as expired (-1), not as 0 days
// left, which the alert path treats as "expires today".
func TestCheckCertJustExpired(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	addr := startTLSServer(t, now.Add(-3*time.Hour))

	st := CheckCert(context.Background(), addr, now)
	if st.Err != "" {
		t.Fatalf("err = %s", st.Err)
	}
	if st.DaysLeft != -1 {
		t.Errorf("days left = %d, want -1", st.DaysLeft)
	}
}

func TestCheckCert(t *testing.T) {
	now := time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)
	expiry := now.Add(30*24*time.Hour + time.Hour)
	addr := startTLSServer(t, expiry)

	st := CheckCert(context.Background(), addr, now)
	if st.Err != "" {
		t.Fatalf("err = %s", st.Err)
	}
	if st.DaysLeft != 30 {
		t.Errorf("days left = %d, want 30", st.DaysLeft)
	}
	if st.Subject != "test.local" {
		t.Errorf("subject = %q", st.Subject)
	}
}

func TestCheckCertExpired(t *testing.T) {
	now := time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)
	addr := startTLSServer(t, now.Add(-48*time.Hour))
	st := CheckCert(context.Background(), addr, now)
	if st.Err != "" {
		t.Fatalf("expired cert must still be readable (no trust validation), got err %s", st.Err)
	}
	if st.DaysLeft >= 0 {
		t.Errorf("days left = %d, want negative", st.DaysLeft)
	}
}

func TestCheckCertUnreachable(t *testing.T) {
	st := CheckCert(context.Background(), "127.0.0.1:1", time.Now())
	if st.Err == "" {
		t.Error("unreachable host must set Err")
	}
}

func TestLatency(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	d, err := Latency(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if d <= 0 || d > 5*time.Second {
		t.Errorf("latency = %s", d)
	}
	if _, err := Latency(context.Background(), "127.0.0.1:1"); err == nil {
		t.Error("closed port must error")
	}
}
