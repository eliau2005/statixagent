// Package dockermon reads container state from the Docker Engine API using a
// plain HTTP client — no Docker SDK, keeping the binary small. On Linux the
// client dials the unix socket; tests use httptest over TCP.
package dockermon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Container is the agent's view of one container.
type Container struct {
	ID           string
	Name         string
	Image        string
	State        string // running, exited, restarting, ...
	Status       string // human text: "Up 3 hours", "Exited (1) 2 minutes ago"
	RestartCount int

	CPUPercent float64 // filled by Stats
	MemUsage   uint64
	MemLimit   uint64
}

// Client talks to one Docker daemon.
type Client struct {
	http *http.Client
	base string // "http://docker" for unix socket, real URL in tests

	mu           sync.Mutex
	restartsSeen map[string]int // container ID → last seen restart count
}

// New returns a Client that connects via the given dialer (unix socket on
// Linux). baseURL is the URL prefix for requests.
func New(httpClient *http.Client, baseURL string) *Client {
	return &Client{http: httpClient, base: strings.TrimRight(baseURL, "/"), restartsSeen: map[string]int{}}
}

// NewUnixSocket returns a Client for /var/run/docker.sock.
func NewUnixSocket(socketPath string) *Client {
	c := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
	return New(c, "http://docker")
}

// ListContainers returns all containers (running and stopped) with restart
// counts from per-container inspect.
func (c *Client) ListContainers(ctx context.Context) ([]Container, error) {
	var raw []struct {
		ID     string   `json:"Id"`
		Names  []string `json:"Names"`
		Image  string   `json:"Image"`
		State  string   `json:"State"`
		Status string   `json:"Status"`
	}
	if err := c.get(ctx, "/containers/json?all=true", &raw); err != nil {
		return nil, err
	}
	out := make([]Container, 0, len(raw))
	for _, r := range raw {
		ct := Container{ID: r.ID, Image: r.Image, State: r.State, Status: r.Status}
		if len(r.Names) > 0 {
			ct.Name = strings.TrimPrefix(r.Names[0], "/")
		}
		var insp struct {
			RestartCount int `json:"RestartCount"`
		}
		if err := c.get(ctx, "/containers/"+r.ID+"/json", &insp); err == nil {
			ct.RestartCount = insp.RestartCount
		}
		out = append(out, ct)
	}
	return out, nil
}

// PublishedPort is a host port a running container publishes.
type PublishedPort struct {
	Port      int
	Proto     string // tcp, udp
	Container string
}

// PublishedPorts lists the host ports published by running containers on a
// non-loopback address. Docker forwards these before the host's INPUT
// rules, so a firewall view needs them to avoid calling a port closed.
// One list request, no per-container inspect.
func (c *Client) PublishedPorts(ctx context.Context) ([]PublishedPort, error) {
	var raw []struct {
		Names []string `json:"Names"`
		Ports []struct {
			IP         string `json:"IP"`
			PublicPort int    `json:"PublicPort"`
			Type       string `json:"Type"`
		} `json:"Ports"`
	}
	if err := c.get(ctx, "/containers/json", &raw); err != nil {
		return nil, err
	}
	var out []PublishedPort
	seen := map[string]bool{}
	for _, r := range raw {
		name := ""
		if len(r.Names) > 0 {
			name = strings.TrimPrefix(r.Names[0], "/")
		}
		for _, p := range r.Ports {
			if p.PublicPort == 0 {
				continue // exposed but not published
			}
			if ip, err := netip.ParseAddr(p.IP); err == nil && ip.IsLoopback() {
				continue // reachable from this host only
			}
			key := fmt.Sprintf("%d/%s", p.PublicPort, p.Type)
			if seen[key] {
				continue // the IPv4 and IPv6 bindings of one mapping
			}
			seen[key] = true
			out = append(out, PublishedPort{Port: p.PublicPort, Proto: p.Type, Container: name})
		}
	}
	return out, nil
}

// Stats fills CPU and memory usage for one running container using a single
// non-streaming stats read.
func (c *Client) Stats(ctx context.Context, ct *Container) error {
	var s struct {
		CPUStats struct {
			CPUUsage struct {
				Total uint64 `json:"total_usage"`
			} `json:"cpu_usage"`
			SystemUsage uint64 `json:"system_cpu_usage"`
			OnlineCPUs  int    `json:"online_cpus"`
		} `json:"cpu_stats"`
		PreCPUStats struct {
			CPUUsage struct {
				Total uint64 `json:"total_usage"`
			} `json:"cpu_usage"`
			SystemUsage uint64 `json:"system_cpu_usage"`
		} `json:"precpu_stats"`
		MemoryStats struct {
			Usage uint64 `json:"usage"`
			Limit uint64 `json:"limit"`
			Stats struct {
				InactiveFile uint64 `json:"inactive_file"`
			} `json:"stats"`
		} `json:"memory_stats"`
	}
	if err := c.get(ctx, "/containers/"+ct.ID+"/stats?stream=false", &s); err != nil {
		return err
	}
	cpuDelta := int64(s.CPUStats.CPUUsage.Total) - int64(s.PreCPUStats.CPUUsage.Total)
	sysDelta := int64(s.CPUStats.SystemUsage) - int64(s.PreCPUStats.SystemUsage)
	if cpuDelta > 0 && sysDelta > 0 {
		cpus := s.CPUStats.OnlineCPUs
		if cpus == 0 {
			cpus = 1
		}
		ct.CPUPercent = float64(cpuDelta) / float64(sysDelta) * float64(cpus) * 100
	}
	// Docker subtracts inactive page cache from "used", same as `docker stats`.
	ct.MemUsage = s.MemoryStats.Usage - s.MemoryStats.Stats.InactiveFile
	ct.MemLimit = s.MemoryStats.Limit
	return nil
}

// RestartLoops compares restart counts against the previous call and returns
// the containers whose count grew — i.e. they restarted since last sample.
// The first call only seeds the baseline and reports nothing.
func (c *Client) RestartLoops(containers []Container) []Container {
	c.mu.Lock()
	defer c.mu.Unlock()
	first := len(c.restartsSeen) == 0
	var looping []Container
	for _, ct := range containers {
		prev, seen := c.restartsSeen[ct.ID]
		if !first && seen && ct.RestartCount > prev {
			looping = append(looping, ct)
		}
		c.restartsSeen[ct.ID] = ct.RestartCount
	}
	return looping
}

func (c *Client) get(ctx context.Context, path string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("docker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker: %s returned %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}
