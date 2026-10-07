package sshwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// GeoInfo is the location summary attached to login alerts.
type GeoInfo struct {
	Country string
	City    string
	ISP     string
}

// String renders "City, Country (ISP)" with empty parts omitted.
func (g GeoInfo) String() string {
	s := g.City
	if g.Country != "" {
		if s != "" {
			s += ", "
		}
		s += g.Country
	}
	if g.ISP != "" {
		s += " (" + g.ISP + ")"
	}
	return s
}

// geoCacheMax bounds the lookup cache. Lookups happen for successful logins
// and live sessions, so this is many times what a real host needs, while
// keeping a long-running agent's memory flat.
const geoCacheMax = 1024

// GeoResolver looks up IPs against ip-api.com with an in-memory cache.
// Lookups are best-effort: on any failure it returns a zero GeoInfo, never
// an error — alerts must not depend on a third-party service being up.
type GeoResolver struct {
	Client  *http.Client
	BaseURL string // default http://ip-api.com

	mu    sync.Mutex
	cache map[string]GeoInfo
}

// NewGeoResolver returns a resolver with a 5s-timeout client.
func NewGeoResolver() *GeoResolver {
	return &GeoResolver{
		Client:  &http.Client{Timeout: 5 * time.Second},
		BaseURL: "http://ip-api.com",
		cache:   map[string]GeoInfo{},
	}
}

// Lookup resolves one IP. Private/loopback addresses skip the network and
// report as local traffic.
func (g *GeoResolver) Lookup(ctx context.Context, ip string) GeoInfo {
	parsed := net.ParseIP(ip)
	if parsed != nil && (parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast()) {
		return GeoInfo{Country: "local network"}
	}
	g.mu.Lock()
	if g.cache == nil {
		g.cache = map[string]GeoInfo{}
	}
	if info, ok := g.cache[ip]; ok {
		g.mu.Unlock()
		return info
	}
	g.mu.Unlock()

	var info GeoInfo
	url := fmt.Sprintf("%s/json/%s?fields=status,country,city,isp", g.BaseURL, ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return info
	}
	resp, err := g.Client.Do(req)
	if err != nil {
		return info
	}
	defer resp.Body.Close()
	var body struct {
		Status  string `json:"status"`
		Country string `json:"country"`
		City    string `json:"city"`
		ISP     string `json:"isp"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&body) != nil || body.Status != "success" {
		return info
	}
	info = GeoInfo{Country: body.Country, City: body.City, ISP: body.ISP}
	g.mu.Lock()
	if len(g.cache) >= geoCacheMax {
		// Start over rather than track recency: a miss costs one lookup.
		clear(g.cache)
	}
	g.cache[ip] = info
	g.mu.Unlock()
	return info
}
