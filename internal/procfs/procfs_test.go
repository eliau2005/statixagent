package procfs

import (
	"strings"
	"testing"
	"time"
)

const statFixture = `cpu  168487 1107 47702 3517073 11796 0 3013 250 0 0
cpu0 42295 281 12110 878533 3052 0 1532 60 0 0
cpu1 42064 273 11865 879605 2912 0 632 64 0 0
cpu2 42105 277 11888 879464 2933 0 441 63 0 0
cpu3 42021 274 11838 879470 2898 0 407 61 0 0
intr 22084970 9 0 0 0
ctxt 41918096
btime 1717000000
processes 31415
procs_running 2
procs_blocked 0
`

func TestParseStat(t *testing.T) {
	st, err := ParseStat(strings.NewReader(statFixture))
	if err != nil {
		t.Fatal(err)
	}
	if st.Aggregate.User != 168487 || st.Aggregate.Idle != 3517073 || st.Aggregate.Steal != 250 {
		t.Errorf("aggregate = %+v", st.Aggregate)
	}
	if len(st.PerCore) != 4 || st.PerCore[3].Name != "cpu3" {
		t.Errorf("per-core = %d cores", len(st.PerCore))
	}
	if got := st.BootTime.Unix(); got != 1717000000 {
		t.Errorf("boot time = %d", got)
	}
	if st.Aggregate.Total() == 0 || st.Aggregate.Busy() >= st.Aggregate.Total() {
		t.Errorf("total=%d busy=%d", st.Aggregate.Total(), st.Aggregate.Busy())
	}
}

func TestParseStatRejectsEmpty(t *testing.T) {
	if _, err := ParseStat(strings.NewReader("intr 1 2 3\n")); err == nil {
		t.Error("want error for stat without cpu line")
	}
}

const memFixture = `MemTotal:        8024904 kB
MemFree:          421312 kB
MemAvailable:    4517168 kB
Buffers:          330064 kB
Cached:          3771692 kB
SwapCached:            0 kB
SwapTotal:       2097148 kB
SwapFree:        2097148 kB
Dirty:               212 kB
`

func TestParseMemInfo(t *testing.T) {
	m, err := ParseMemInfo(strings.NewReader(memFixture))
	if err != nil {
		t.Fatal(err)
	}
	if m.Total != 8024904*1024 {
		t.Errorf("total = %d", m.Total)
	}
	if m.Available != 4517168*1024 {
		t.Errorf("available = %d", m.Available)
	}
	if m.SwapTotal != 2097148*1024 || m.SwapFree != m.SwapTotal {
		t.Errorf("swap = %d/%d", m.SwapFree, m.SwapTotal)
	}
	want := 100 * float64(8024904-4517168) / 8024904
	if got := m.UsedPercent(); got < want-0.01 || got > want+0.01 {
		t.Errorf("used%% = %.2f, want %.2f", got, want)
	}
}

func TestParseLoadAvg(t *testing.T) {
	l, err := ParseLoadAvg(strings.NewReader("0.52 0.58 0.59 3/1234 56789\n"))
	if err != nil {
		t.Fatal(err)
	}
	if l.Load1 != 0.52 || l.Load15 != 0.59 {
		t.Errorf("loads = %+v", l)
	}
	if l.RunningProcs != 3 || l.TotalProcs != 1234 {
		t.Errorf("procs = %d/%d", l.RunningProcs, l.TotalProcs)
	}
}

func TestParseUptime(t *testing.T) {
	up, err := ParseUptime(strings.NewReader("351735.21 1401762.97\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := time.Duration(351735.21 * float64(time.Second))
	if up != want {
		t.Errorf("uptime = %s, want %s", up, want)
	}
}

const netDevFixture = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1318408    9756    0    0    0     0          0         0  1318408    9756    0    0    0     0       0          0
  eth0: 5917218163 4396406    7    0    0     0          0         0 218529099 1571513    2    0    0     0       0          0
wlan0:  331894     2345    0    0    0     0          0         0   129834    1009    0    0    0     0       0          0
`

func TestParseNetDev(t *testing.T) {
	devs, err := ParseNetDev(strings.NewReader(netDevFixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 2 {
		t.Fatalf("devices = %d (loopback must be skipped)", len(devs))
	}
	eth := devs[0]
	if eth.Name != "eth0" || eth.RxBytes != 5917218163 || eth.TxBytes != 218529099 {
		t.Errorf("eth0 = %+v", eth)
	}
	if eth.RxErrors != 7 || eth.TxErrors != 2 {
		t.Errorf("eth0 errors = rx %d tx %d", eth.RxErrors, eth.TxErrors)
	}
}

const diskStatsFixture = `   8       0 sda 124511 4533 6342830 49572 376103 197986 12476290 351468 0 142336 401040 0 0 0 0
   8       1 sda1 124301 4533 6334106 49520 375941 197986 12476290 351401 0 142280 400921 0 0 0 0
 259       0 nvme0n1 98472 120 8374561 12849 220431 88123 18374829 98231 0 84720 111080 0 0 0 0
`

func TestParseDiskStats(t *testing.T) {
	ds, err := ParseDiskStats(strings.NewReader(diskStatsFixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 3 {
		t.Fatalf("disks = %d", len(ds))
	}
	sda := ds[0]
	if sda.Name != "sda" || sda.ReadsCompleted != 124511 || sda.SectorsWritten != 12476290 {
		t.Errorf("sda = %+v", sda)
	}
	if ds[2].Name != "nvme0n1" || ds[2].IOTimeMillis != 84720 {
		t.Errorf("nvme = %+v", ds[2])
	}
}

const tcpFixture = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 24452 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   112        0 25011 1 0000000000000000 100 0 0 10 0
   2: AC120001:9C40 AC120002:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 31337 1 0000000000000000 20 4 30 10 -1
`

func TestParseTCPListeners(t *testing.T) {
	ports, err := ParseTCPListeners(strings.NewReader(tcpFixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 2 || ports[0] != 22 || ports[1] != 3306 {
		t.Errorf("ports = %v, want [22 3306] (established conns excluded)", ports)
	}
}

func TestParseFileNR(t *testing.T) {
	fn, err := ParseFileNR(strings.NewReader("9472\t0\t9223372036854775807\n"))
	if err != nil {
		t.Fatal(err)
	}
	if fn.Allocated != 9472 || fn.Max != 9223372036854775807 {
		t.Errorf("file-nr = %+v", fn)
	}
	if _, err := ParseFileNR(strings.NewReader("bogus\n")); err == nil {
		t.Error("want error for malformed file-nr")
	}
}
