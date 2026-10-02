package prober

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ubombar/garagat"
	"github.com/ubombar/garagat/link"
	"github.com/ubombar/garagat/pcapfile"
)

const hops = 5

// network simulates a path of hops-1 routers in front of every destination.
func network(delay time.Duration, corrupt bool) link.Responder {
	return func(pkt []byte) ([][]byte, time.Duration) {
		var ttl uint8
		var dst netip.Addr
		var router netip.Addr
		if pkt[0]>>4 == 4 {
			ttl = pkt[8]
			dst = netip.AddrFrom4([4]byte(pkt[16:20]))
			router = netip.AddrFrom4([4]byte{10, 0, 0, ttl})
		} else {
			ttl = pkt[7]
			dst = netip.AddrFrom16([16]byte(pkt[24:40]))
			router = netip.MustParseAddr("2001:db8:ffff::" + strconv.FormatUint(uint64(ttl), 16))
		}
		if corrupt && pkt[0]>>4 == 4 {
			pkt = append([]byte(nil), pkt...)
			binary.BigEndian.PutUint16(pkt[4:], binary.BigEndian.Uint16(pkt[4:])+1)
		}
		if ttl < hops {
			return [][]byte{garagat.TimeExceeded(router, pkt, 255-ttl)}, delay
		}
		if echo := garagat.EchoReply(pkt, 64); echo != nil {
			return [][]byte{echo}, delay
		}
		return [][]byte{garagat.DestinationUnreachable(dst, pkt, 64)}, delay
	}
}

func testConfig(sim *link.Simulated, out io.Writer, logs io.Writer) Config {
	cfg := DefaultConfig()
	cfg.Interface = "sim0"
	cfg.Opener = sim.Open
	cfg.ProbingRate = 100_000
	cfg.SnifferWaitTime = 300 * time.Millisecond
	cfg.StatsInterval = 0
	cfg.Output = out
	cfg.Logger = NewLogger(logs, LevelTrace)
	cfg.SourceIPv4 = netip.MustParseAddr("192.0.2.1")
	cfg.SourceIPv6 = netip.MustParseAddr("2001:db8::1")
	cfg.CaracalID = 4242
	return cfg
}

func probes(dsts ...string) string {
	var sb strings.Builder
	for _, d := range dsts {
		parts := strings.Split(d, "/")
		for ttl := 1; ttl <= hops+1; ttl++ {
			sb.WriteString(parts[0] + ",24000,33434," + strconv.Itoa(ttl) + "," + parts[1] + "\n")
		}
	}
	return sb.String()
}

func readCSV(t *testing.T, out string) []map[string]string {
	t.Helper()
	rows, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatalf("invalid CSV: %v\n%s", err, out)
	}
	if strings.Join(rows[0], ",") != garagat.CSVHeader {
		t.Fatalf("bad header %v", rows[0])
	}
	var res []map[string]string
	for _, r := range rows[1:] {
		m := map[string]string{}
		for i, k := range rows[0] {
			m[k] = r[i]
		}
		res = append(res, m)
	}
	return res
}

func TestProbeSimulated(t *testing.T) {
	sim := link.NewSimulated(network(5*time.Millisecond, false))
	var out, logs bytes.Buffer
	cfg := testConfig(sim, &out, &logs)
	cfg.MetaRound = "r42"
	input := probes("8.8.8.8/udp", "1.1.1.1/icmp", "2001:4860:4860::8888/icmp6", "2001:4860:4860::8844/udp") + "not,a,probe\n"
	stats, err := ProbeReader(context.Background(), cfg, strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Prober.Read != 24 || stats.Prober.Sent != 24 || stats.Prober.Failed != 0 {
		t.Errorf("prober stats %s", stats.Prober)
	}
	rows := readCSV(t, out.String())
	if len(rows) != 24 {
		t.Fatalf("got %d replies, want 24\n%s\n%s", len(rows), out.String(), logs.String())
	}
	if stats.Sniffer.ReceivedCount != 24 || stats.Sniffer.ReceivedInvalidCount != 0 {
		t.Errorf("sniffer stats %s", stats.Sniffer)
	}
	// 4 routers per family (shared by the destinations) + 4 destinations.
	if stats.Sniffer.ICMPDistinctInclDest != 12 || stats.Sniffer.ICMPDistinctExclDest != 8 {
		t.Errorf("sniffer stats %s", stats.Sniffer)
	}
	for _, r := range rows {
		ttl, _ := strconv.Atoi(r["probe_ttl"])
		if r["round"] != "r42" {
			t.Errorf("round = %s", r["round"])
		}
		rtt, _ := strconv.Atoi(r["rtt"])
		if rtt < 40 || rtt > 2000 {
			t.Errorf("rtt = %d", rtt)
		}
		if ttl < hops {
			if r["reply_icmp_type"] != "11" && r["reply_icmp_type"] != "3" {
				t.Errorf("ttl %d: type %s", ttl, r["reply_icmp_type"])
			}
			if r["reply_src_addr"] == r["probe_dst_addr"] {
				t.Errorf("ttl %d: reply from destination", ttl)
			}
		} else if r["reply_src_addr"] != r["probe_dst_addr"] {
			t.Errorf("ttl %d: reply from %s", ttl, r["reply_src_addr"])
		}
		switch r["probe_protocol"] {
		case "17":
			if r["probe_dst_port"] != "33434" || r["probe_src_port"] != "24000" {
				t.Errorf("udp ports %v", r)
			}
		case "1", "58":
			if r["probe_src_port"] != "24000" {
				t.Errorf("icmp id %v", r)
			}
		}
		if strings.Contains(r["probe_dst_addr"], ".") && !strings.HasPrefix(r["probe_src_addr"], "::ffff:192.0.2.1") {
			t.Errorf("probe_src_addr = %s", r["probe_src_addr"])
		}
	}
	if !strings.Contains(logs.String(), "line=not,a,probe") {
		t.Error("invalid line not logged")
	}
	if !strings.Contains(logs.String(), "packets_sent=24") {
		t.Error("final statistics not logged")
	}
}

func TestProbeIntegrityCheck(t *testing.T) {
	for _, check := range []bool{true, false} {
		sim := link.NewSimulated(network(0, true))
		var out, logs bytes.Buffer
		cfg := testConfig(sim, &out, &logs)
		cfg.IntegrityCheck = check
		cfg.SnifferWaitTime = 100 * time.Millisecond
		stats, err := ProbeReader(context.Background(), cfg, strings.NewReader(probes("8.8.8.8/icmp")))
		if err != nil {
			t.Fatal(err)
		}
		rows := readCSV(t, out.String())
		// The echo reply from the destination cannot be validated.
		want := 2
		if !check {
			want = hops + 1
		}
		if len(rows) != want {
			t.Errorf("check=%v: got %d rows, want %d", check, len(rows), want)
		}
		if check && stats.Sniffer.ReceivedInvalidCount != hops-1 {
			t.Errorf("invalid count %d", stats.Sniffer.ReceivedInvalidCount)
		}
	}
}

func TestProbeFilters(t *testing.T) {
	dir := t.TempDir()
	excl := filepath.Join(dir, "excl.txt")
	incl := filepath.Join(dir, "incl.txt")
	os.WriteFile(excl, []byte("# deny\n8.8.4.0/24\n"), 0o644)
	os.WriteFile(incl, []byte("8.8.0.0/16\n2001:4860::/32\n"), 0o644)
	sim := link.NewSimulated(network(0, false))
	var out, logs bytes.Buffer
	cfg := testConfig(sim, &out, &logs)
	cfg.PrefixExclFile = excl
	cfg.PrefixInclFile = incl
	cfg.FilterMinTTL = 2
	cfg.FilterMaxTTL = 5
	cfg.NPackets = 2
	cfg.SnifferWaitTime = 100 * time.Millisecond
	pcapPath := filepath.Join(dir, "out.pcap")
	cfg.OutputFilePcap = pcapPath
	input := probes("8.8.8.8/udp", "8.8.4.4/udp", "1.1.1.1/icmp", "2001:4860:4860::8888/icmp6")
	stats, err := ProbeReader(context.Background(), cfg, strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	want := ProberStatistics{Read: 24, Sent: 16, FilteredLowTTL: 4, FilteredHighTTL: 4, FilteredPrefixExcl: 4, FilteredPrefixNotIncl: 4}
	if stats.Prober != want {
		t.Errorf("stats = %s\nwant    %s", stats.Prober, want)
	}
	if len(sim.Sent()) != 16 {
		t.Errorf("sent %d packets", len(sim.Sent()))
	}
	f, err := os.Open(pcapPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := pcapfile.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for {
		if _, err := r.Next(); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != 16 {
		t.Errorf("pcap has %d packets, want 16", n)
	}
}

func TestProbeMaxProbesAndCancel(t *testing.T) {
	sim := link.NewSimulated(nil)
	var out, logs bytes.Buffer
	cfg := testConfig(sim, &out, &logs)
	cfg.MaxProbes = 5
	cfg.SnifferWaitTime = 0
	if _, err := ProbeReader(context.Background(), cfg, strings.NewReader(probes("8.8.8.8/udp", "1.1.1.1/udp"))); err != nil {
		t.Fatal(err)
	}
	if len(sim.Sent()) != 5 {
		t.Errorf("sent %d, want 5", len(sim.Sent()))
	}

	sim = link.NewSimulated(nil)
	cfg = testConfig(sim, &out, &logs)
	cfg.SnifferWaitTime = 0
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ProbeReader(ctx, cfg, strings.NewReader(probes("8.8.8.8/udp"))); err != nil {
		t.Fatal(err)
	}
	if len(sim.Sent()) != 0 {
		t.Errorf("sent %d after cancel", len(sim.Sent()))
	}
}

func TestProbeRate(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	sim := link.NewSimulated(nil)
	var out, logs bytes.Buffer
	cfg := testConfig(sim, &out, &logs)
	cfg.ProbingRate = 200
	cfg.BatchSize = 1
	cfg.SnifferWaitTime = 0
	var sb strings.Builder
	for i := 0; i < 100; i++ {
		sb.WriteString("8.8.8.8,24000,33434,1,udp\n")
	}
	start := time.Now()
	if _, err := ProbeReader(context.Background(), cfg, strings.NewReader(sb.String())); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 400*time.Millisecond || d > 2*time.Second {
		t.Errorf("100 probes at 200 pps took %v", d)
	}
}

func TestConfigValidate(t *testing.T) {
	bad := []func(*Config){
		func(c *Config) { c.NPackets = 0 },
		func(c *Config) { c.BatchSize = 0 },
		func(c *Config) { c.ProbingRate = 0 },
		func(c *Config) { c.Interface = "" },
		func(c *Config) { c.PrefixExclFile = "/nonexistent" },
		func(c *Config) { c.SourceIPv4 = netip.MustParseAddr("::1") },
		func(c *Config) { c.SourceIPv6 = netip.MustParseAddr("1.2.3.4") },
		func(c *Config) { c.FilterMaxTTL = 256 },
	}
	for i, f := range bad {
		c := DefaultConfig()
		c.Interface = "x"
		f(&c)
		if c.Validate() == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
	c := DefaultConfig()
	c.Interface = "eth0"
	c.MetaRound = "3"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if s := c.String(); !strings.Contains(s, "interface=eth0") || !strings.Contains(s, "round=3") {
		t.Errorf("String() = %s", s)
	}
}

func TestLogger(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, LevelWarning)
	l.Infof("hidden")
	l.Warnf("shown %d", 1)
	if strings.Contains(buf.String(), "hidden") || !strings.Contains(buf.String(), "[warning] shown 1") {
		t.Errorf("logs: %s", buf.String())
	}
	var nilLogger *Logger
	nilLogger.Infof("no panic")
	for _, s := range []string{"trace", "debug", "info", "warning", "error", "fatal", "off"} {
		if _, err := ParseLevel(s); err != nil {
			t.Error(err)
		}
	}
	if _, err := ParseLevel("loud"); err == nil {
		t.Error("expected error")
	}
}
