// Package procfs parses the text formats of Linux /proc files. Every parser
// is a pure function over an io.Reader so the package builds and tests on any
// OS; only the agent's linux collector opens the real /proc paths.
package procfs

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// CPUStat holds one cpu line of /proc/stat in USER_HZ ticks.
type CPUStat struct {
	Name    string // "cpu" for the aggregate, "cpu0", "cpu1", ... per core
	User    uint64
	Nice    uint64
	System  uint64
	Idle    uint64
	IOWait  uint64
	IRQ     uint64
	SoftIRQ uint64
	Steal   uint64
}

// Total returns all ticks including idle.
func (c CPUStat) Total() uint64 {
	return c.User + c.Nice + c.System + c.Idle + c.IOWait + c.IRQ + c.SoftIRQ + c.Steal
}

// Busy returns non-idle ticks (idle + iowait count as idle).
func (c CPUStat) Busy() uint64 {
	return c.Total() - c.Idle - c.IOWait
}

// Stat is the parsed subset of /proc/stat the agent uses.
type Stat struct {
	Aggregate CPUStat
	PerCore   []CPUStat
	BootTime  time.Time
}

// ParseStat parses /proc/stat.
func ParseStat(r io.Reader) (Stat, error) {
	var st Stat
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		switch {
		case f[0] == "cpu":
			c, err := parseCPULine(f)
			if err != nil {
				return Stat{}, err
			}
			st.Aggregate = c
		case strings.HasPrefix(f[0], "cpu"):
			c, err := parseCPULine(f)
			if err != nil {
				return Stat{}, err
			}
			st.PerCore = append(st.PerCore, c)
		case f[0] == "btime" && len(f) >= 2:
			sec, err := strconv.ParseInt(f[1], 10, 64)
			if err != nil {
				return Stat{}, fmt.Errorf("procfs: btime: %w", err)
			}
			st.BootTime = time.Unix(sec, 0)
		}
	}
	if err := sc.Err(); err != nil {
		return Stat{}, err
	}
	if st.Aggregate.Name == "" {
		return Stat{}, fmt.Errorf("procfs: no cpu line in stat")
	}
	return st, nil
}

func parseCPULine(f []string) (CPUStat, error) {
	if len(f) < 5 {
		return CPUStat{}, fmt.Errorf("procfs: short cpu line: %v", f)
	}
	c := CPUStat{Name: f[0]}
	dst := []*uint64{&c.User, &c.Nice, &c.System, &c.Idle, &c.IOWait, &c.IRQ, &c.SoftIRQ, &c.Steal}
	for i, p := range dst {
		if 1+i >= len(f) {
			break // older kernels omit trailing fields
		}
		v, err := strconv.ParseUint(f[1+i], 10, 64)
		if err != nil {
			return CPUStat{}, fmt.Errorf("procfs: cpu line field %d: %w", i, err)
		}
		*p = v
	}
	return c, nil
}

// MemInfo holds the fields of /proc/meminfo the agent uses, in bytes.
type MemInfo struct {
	Total     uint64
	Free      uint64
	Available uint64
	Buffers   uint64
	Cached    uint64
	SwapTotal uint64
	SwapFree  uint64
}

// UsedPercent returns used memory as a percentage of total, using
// MemAvailable (the kernel's own estimate of reclaimable memory).
func (m MemInfo) UsedPercent() float64 {
	if m.Total == 0 {
		return 0
	}
	return 100 * float64(m.Total-m.Available) / float64(m.Total)
}

// ParseMemInfo parses /proc/meminfo. Values are converted from kB to bytes.
func ParseMemInfo(r io.Reader) (MemInfo, error) {
	var m MemInfo
	fields := map[string]*uint64{
		"MemTotal":     &m.Total,
		"MemFree":      &m.Free,
		"MemAvailable": &m.Available,
		"Buffers":      &m.Buffers,
		"Cached":       &m.Cached,
		"SwapTotal":    &m.SwapTotal,
		"SwapFree":     &m.SwapFree,
	}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		key, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		dst, want := fields[key]
		if !want {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		v, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			return MemInfo{}, fmt.Errorf("procfs: meminfo %s: %w", key, err)
		}
		*dst = v * 1024
	}
	if err := sc.Err(); err != nil {
		return MemInfo{}, err
	}
	if m.Total == 0 {
		return MemInfo{}, fmt.Errorf("procfs: meminfo missing MemTotal")
	}
	return m, nil
}

// LoadAvg is /proc/loadavg.
type LoadAvg struct {
	Load1, Load5, Load15 float64
	RunningProcs         int
	TotalProcs           int
}

// ParseLoadAvg parses /proc/loadavg.
func ParseLoadAvg(r io.Reader) (LoadAvg, error) {
	var l LoadAvg
	var ratio string
	data, err := io.ReadAll(r)
	if err != nil {
		return LoadAvg{}, err
	}
	if _, err := fmt.Sscanf(string(data), "%f %f %f %s", &l.Load1, &l.Load5, &l.Load15, &ratio); err != nil {
		return LoadAvg{}, fmt.Errorf("procfs: loadavg: %w", err)
	}
	run, total, ok := strings.Cut(ratio, "/")
	if ok {
		l.RunningProcs, _ = strconv.Atoi(run)
		l.TotalProcs, _ = strconv.Atoi(total)
	}
	return l, nil
}

// ParseUptime parses /proc/uptime and returns the system uptime.
func ParseUptime(r io.Reader) (time.Duration, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return 0, err
	}
	var up, idle float64
	if _, err := fmt.Sscanf(string(data), "%f %f", &up, &idle); err != nil {
		return 0, fmt.Errorf("procfs: uptime: %w", err)
	}
	return time.Duration(up * float64(time.Second)), nil
}

// NetDev is one interface line of /proc/net/dev (cumulative counters).
type NetDev struct {
	Name      string
	RxBytes   uint64
	RxPackets uint64
	RxErrors  uint64
	TxBytes   uint64
	TxPackets uint64
	TxErrors  uint64
}

// ParseNetDev parses /proc/net/dev, skipping the loopback interface.
func ParseNetDev(r io.Reader) ([]NetDev, error) {
	var out []NetDev
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue // the two header lines
		}
		name = strings.TrimSpace(name)
		if name == "lo" {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 11 {
			return nil, fmt.Errorf("procfs: net/dev: short line for %s", name)
		}
		var vals [11]uint64
		for i := range vals {
			v, err := strconv.ParseUint(f[i], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("procfs: net/dev %s: %w", name, err)
			}
			vals[i] = v
		}
		out = append(out, NetDev{
			Name:    name,
			RxBytes: vals[0], RxPackets: vals[1], RxErrors: vals[2],
			TxBytes: vals[8], TxPackets: vals[9], TxErrors: vals[10],
		})
	}
	return out, sc.Err()
}

// DiskStat is one device line of /proc/diskstats (cumulative counters).
type DiskStat struct {
	Name           string
	ReadsCompleted uint64
	SectorsRead    uint64
	WritesComplete uint64
	SectorsWritten uint64
	IOTimeMillis   uint64
}

// ParseDiskStats parses /proc/diskstats, keeping only whole devices the
// caller cares about; partition filtering is left to the caller since
// naming conventions vary (sda1, nvme0n1p1, mmcblk0p1).
func ParseDiskStats(r io.Reader) ([]DiskStat, error) {
	var out []DiskStat
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 14 {
			continue
		}
		idx := func(i int) uint64 {
			v, _ := strconv.ParseUint(f[i], 10, 64)
			return v
		}
		out = append(out, DiskStat{
			Name:           f[2],
			ReadsCompleted: idx(3),
			SectorsRead:    idx(5),
			WritesComplete: idx(7),
			SectorsWritten: idx(9),
			IOTimeMillis:   idx(12),
		})
	}
	return out, sc.Err()
}

// ParseTCPListeners parses /proc/net/tcp (or tcp6) and returns the local
// ports in LISTEN state. The caller merges v4+v6 results and dedupes.
func ParseTCPListeners(r io.Reader) ([]int, error) {
	const listenState = "0A"
	var out []int
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		// sl local_address rem_address st ...
		if len(f) < 4 || !strings.HasSuffix(f[0], ":") {
			continue // header or malformed line
		}
		if f[3] != listenState {
			continue
		}
		_, portHex, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseInt(portHex, 16, 32)
		if err != nil {
			return nil, fmt.Errorf("procfs: net/tcp port %q: %w", portHex, err)
		}
		out = append(out, int(port))
	}
	return out, sc.Err()
}

// FileNR is /proc/sys/fs/file-nr: allocated and maximum file handles.
type FileNR struct {
	Allocated uint64
	Max       uint64
}

// ParseFileNR parses /proc/sys/fs/file-nr.
func ParseFileNR(r io.Reader) (FileNR, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return FileNR{}, err
	}
	f := strings.Fields(string(data))
	if len(f) != 3 {
		return FileNR{}, fmt.Errorf("procfs: file-nr: want 3 fields, got %d", len(f))
	}
	alloc, err1 := strconv.ParseUint(f[0], 10, 64)
	max, err2 := strconv.ParseUint(f[2], 10, 64)
	if err1 != nil || err2 != nil {
		return FileNR{}, fmt.Errorf("procfs: file-nr: bad numbers in %q", string(data))
	}
	return FileNR{Allocated: alloc, Max: max}, nil
}
