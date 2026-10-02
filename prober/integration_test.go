//go:build integration

package prober

// These tests send real packets and need root (or CAP_NET_RAW on Linux, BPF
// access on macOS). Run them with:
//
//	sudo go test -tags integration ./prober/
//
// Set GARAGAT_INTERNET=1 to also probe 8.8.8.8 through the default interface.

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ubombar/garagat/neighbors"
)

func loopback() string {
	if runtime.GOOS == "linux" {
		return "lo"
	}
	return "lo0"
}

// Neither Linux nor macOS answer packets injected on the loopback interface
// (AF_PACKET on lo, BPF on lo0), so this test only runs when
// GARAGAT_LOOPBACK is set, for systems that do.
func TestIntegrationLoopback(t *testing.T) {
	if os.Getenv("GARAGAT_LOOPBACK") == "" {
		t.Skip("set GARAGAT_LOOPBACK=1 to probe the loopback interface")
	}
	var out, logs bytes.Buffer
	cfg := DefaultConfig()
	cfg.Interface = loopback()
	cfg.Output = &out
	cfg.Logger = NewLogger(&logs, LevelDebug)
	cfg.StatsInterval = 0
	input := "127.0.0.1,24000,0,10,icmp\n127.0.0.1,24000,33434,11,udp\n::1,24000,0,12,icmp6\n::1,24001,33434,13,udp\n"
	stats, err := ProbeReader(context.Background(), cfg, strings.NewReader(input))
	t.Log(logs.String())
	t.Log(out.String())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Prober.Sent != 4 {
		t.Fatalf("sent %d probes", stats.Prober.Sent)
	}
	rows := readCSV(t, out.String())
	seen := map[string]bool{}
	for _, r := range rows {
		seen[r["probe_protocol"]+"/"+r["probe_ttl"]+"/"+r["reply_icmp_type"]] = true
		if r["reply_src_addr"] != r["probe_dst_addr"] {
			t.Errorf("reply from %s for %s", r["reply_src_addr"], r["probe_dst_addr"])
		}
		rtt, _ := strconv.Atoi(r["rtt"])
		if rtt > 1000 {
			t.Errorf("rtt %d too large", rtt)
		}
	}
	// Echo replies and port unreachable messages from the local stack.
	for _, k := range []string{"1/10/0", "17/11/3", "58/12/129", "17/13/1"} {
		if !seen[k] {
			t.Errorf("missing reply %s", k)
		}
	}
}

// TestIntegrationGateway pings the default IPv4 gateway, which resolves its
// MAC address with ARP and exercises the real send and capture paths.
func TestIntegrationGateway(t *testing.T) {
	v4, _, err := neighbors.DefaultRoutes()
	if err != nil || !v4.Gateway.IsValid() {
		t.Skip("no IPv4 default gateway")
	}
	if out, err := exec.Command("ping", "-c", "2", v4.Gateway.String()).CombinedOutput(); err != nil {
		t.Skipf("the gateway does not answer ping: %v\n%s", err, out)
	}
	var out, logs bytes.Buffer
	cfg := DefaultConfig()
	cfg.Interface = v4.Interface
	cfg.Output = &out
	cfg.Logger = NewLogger(&logs, LevelDebug)
	cfg.StatsInterval = 0
	cfg.MetaRound = "gw"
	gw := v4.Gateway.String()
	input := gw + ",24000,0,64,icmp\n" + gw + ",24001,0,63,icmp\n"
	stats, err := ProbeReader(context.Background(), cfg, strings.NewReader(input))
	t.Log(logs.String())
	t.Log(out.String())
	if err != nil {
		t.Fatal(err)
	}
	// Echo replies cannot be validated, so late replies to the system ping
	// above may be captured too: keep the replies to our probes.
	var rows []map[string]string
	for _, r := range readCSV(t, out.String()) {
		if r["probe_src_port"] == "24000" || r["probe_src_port"] == "24001" {
			rows = append(rows, r)
		}
	}
	if len(rows) != 2 {
		t.Fatalf("got %d replies, want 2", len(rows))
	}
	for _, r := range rows {
		if r["reply_icmp_type"] != "0" || r["reply_src_addr"] != "::ffff:"+gw || r["round"] != "gw" {
			t.Errorf("unexpected reply %v", r)
		}
		if r["probe_ttl"] != "64" && r["probe_ttl"] != "63" {
			t.Errorf("probe_ttl %s", r["probe_ttl"])
		}
	}
	if stats.Link.Received < 2 {
		t.Errorf("link stats %s", stats.Link)
	}
}

func TestIntegrationInternet(t *testing.T) {
	if os.Getenv("GARAGAT_INTERNET") == "" {
		t.Skip("set GARAGAT_INTERNET=1 to probe 8.8.8.8")
	}
	var out, logs bytes.Buffer
	cfg := DefaultConfig()
	cfg.Interface = neighbors.DefaultInterface()
	cfg.Output = &out
	cfg.Logger = NewLogger(&logs, LevelDebug)
	cfg.SnifferWaitTime = 2 * time.Second
	cfg.StatsInterval = 0
	var sb strings.Builder
	for ttl := 1; ttl <= 32; ttl++ {
		sb.WriteString("8.8.8.8,24000,33434," + strconv.Itoa(ttl) + ",icmp\n")
	}
	stats, err := ProbeReader(context.Background(), cfg, strings.NewReader(sb.String()))
	t.Log(logs.String())
	t.Log(out.String())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Sniffer.ReceivedCount == 0 {
		t.Fatal("no replies")
	}
	rows := readCSV(t, out.String())
	echo := false
	for _, r := range rows {
		if r["reply_src_addr"] == "::ffff:8.8.8.8" && r["reply_icmp_type"] == "0" {
			echo = true
		}
	}
	if !echo {
		t.Error("no echo reply from 8.8.8.8")
	}
}
