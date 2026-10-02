package main

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ubombar/garagat"
	"github.com/ubombar/garagat/link"
)

func TestHelp(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--help"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	for _, flag := range []string{"--probing-rate", "--interface", "--batch-size", "--log-level", "--n-packets", "--max-probes",
		"--source-address-v4", "--source-address-v6", "--sniffer-wait-time", "--rate-limiting-method",
		"--filter-from-prefix-file-excl", "--filter-from-prefix-file-incl", "--filter-min-ttl", "--filter-max-ttl",
		"--caracal-id", "--meta-round", "--no-integrity-check", "--output-file-pcap"} {
		if !strings.Contains(out.String(), flag) {
			t.Errorf("help is missing %s", flag)
		}
	}
	if !strings.Contains(errb.String(), "garagat v") {
		t.Error("missing banner")
	}
}

func TestInvalidFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--probing-rate", "0"},
		{"--n-packets", "0"},
		{"--batch-size", "-1"},
		{"--max-probes", "0"},
		{"--rate-limiting-method", "fast"},
		{"--caracal-id", "70000"},
		{"--source-address-v4", "::1"},
		{"--source-address-v6", "1.2.3.4"},
		{"--log-level", "loud"},
		{"--gateway-mac-v4", "zz"},
		{"--filter-from-prefix-file-excl", "/nonexistent"},
		{"--unknown"},
	} {
		var out, errb bytes.Buffer
		if code := run(append(args, "-z", "lo"), strings.NewReader(""), &out, &errb); code == 0 {
			t.Errorf("%v: expected failure", args)
		}
	}
}

func TestRunSimulated(t *testing.T) {
	sim := link.NewSimulated(func(pkt []byte) ([][]byte, time.Duration) {
		return [][]byte{garagat.TimeExceeded(netip.MustParseAddr("10.0.0.1"), pkt, 250)}, 0
	})
	opener = sim.Open
	defer func() { opener = nil }()
	var out, errb bytes.Buffer
	input := "8.8.8.8,24000,33434,3,udp\n8.8.4.4,24000,0,4,icmp\n"
	code := run([]string{"-z", "sim0", "-W", "1", "--caracal-id", "7", "--meta-round", "9", "--source-address-v4", "192.0.2.1", "-L", "error"},
		strings.NewReader(input), &out, &errb)
	if code != 0 {
		t.Fatalf("exit code %d: %s", code, errb.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if lines[0] != garagat.CSVHeader || len(lines) != 3 {
		t.Fatalf("output:\n%s", out.String())
	}
	for _, l := range lines[1:] {
		if !strings.HasSuffix(l, ",9") || !strings.Contains(l, "::ffff:192.0.2.1,") || !strings.Contains(l, "::ffff:10.0.0.1,1,11,0,250") {
			t.Errorf("unexpected line %s", l)
		}
	}
}
