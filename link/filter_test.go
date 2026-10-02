package link

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"testing"

	"github.com/ubombar/garagat"
	"github.com/ubombar/garagat/pcapfile"
	"golang.org/x/net/bpf"
)

func vm(t *testing.T, f FilterFunc, lt garagat.LinkType) *bpf.VM {
	t.Helper()
	raw, err := f(lt)
	if err != nil {
		t.Fatal(err)
	}
	insns, ok := bpf.Disassemble(raw)
	if !ok {
		t.Fatal("cannot disassemble")
	}
	v, err := bpf.NewVM(insns)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func packets(t *testing.T, name string) [][]byte {
	t.Helper()
	f, err := os.Open("../testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := pcapfile.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for {
		p, err := r.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, append([]byte(nil), p.Data...))
	}
}

// The first packet of each fixture is the probe (rejected), the second one is
// the reply (accepted).
func TestReplyFilterEthernet(t *testing.T) {
	v := vm(t, ReplyFilter, garagat.LinkTypeEthernet)
	for _, name := range []string{
		"icmp-icmp-ttl-exceeded.pcap", "icmp-icmp-ttl-exceeded-mpls.pcap", "icmp-icmp-echo-reply.pcap",
		"icmp6-icmp6-ttl-exceeded.pcap", "icmp6-icmp6-echo-reply.pcap",
		"udp-icmp-ttl-exceeded.pcap", "udp-icmp6-ttl-exceeded.pcap",
	} {
		pkts := packets(t, name)
		for i, p := range pkts {
			n, err := v.Run(p)
			if err != nil {
				t.Fatal(err)
			}
			_, parsed := garagat.Parse(p, garagat.LinkTypeEthernet, 0)
			if (n > 0) != parsed {
				t.Errorf("%s #%d: filter=%d parser=%v", name, i, n, parsed)
			}
			if i > 0 && n == 0 {
				t.Errorf("%s #%d: reply rejected", name, i)
			}
		}
	}
	for _, p := range packets(t, "arp.pcap") {
		if n, _ := v.Run(p); n != 0 {
			t.Error("ARP accepted")
		}
	}
}

func TestReplyFilterRawAndNull(t *testing.T) {
	probe := garagat.MapAddr(netip.MustParseAddr("8.8.8.8"))
	b := &garagat.ProbeBuilder{L2: garagat.L2None, SrcIPv4: netip.MustParseAddr("192.0.2.1"), SrcIPv6: netip.MustParseAddr("2001:db8::1")}
	pkt, _ := b.Build(garagat.Probe{DstAddr: probe, SrcPort: 1, TTL: 3, Protocol: garagat.ICMP}, 1)
	te := garagat.TimeExceeded(netip.MustParseAddr("10.0.0.1"), pkt, 64)
	echo := garagat.EchoReply(pkt, 64)
	pkt6, _ := b.Build(garagat.Probe{DstAddr: netip.MustParseAddr("2001:db8::2"), SrcPort: 1, TTL: 3, Protocol: garagat.ICMPv6}, 1)
	te6 := garagat.DestinationUnreachable(netip.MustParseAddr("2001:db8::3"), pkt6, 64)
	echo6 := garagat.EchoReply(pkt6, 64)

	for _, lt := range []garagat.LinkType{garagat.LinkTypeRaw, garagat.LinkTypeNull} {
		v := vm(t, ReplyFilter, lt)
		prefix := []byte{}
		if lt == garagat.LinkTypeNull {
			prefix = []byte{2, 0, 0, 0}
		}
		for name, c := range map[string]struct {
			data []byte
			want bool
		}{"probe": {pkt, false}, "te": {te, true}, "echo": {echo, true}, "probe6": {pkt6, false}, "unreach6": {te6, true}, "echo6": {echo6, true}} {
			n, err := v.Run(append(append([]byte{}, prefix...), c.data...))
			if err != nil {
				t.Fatal(err)
			}
			if (n > 0) != c.want {
				t.Errorf("lt=%d %s: accepted=%v", lt, name, n > 0)
			}
		}
	}
	if _, err := ReplyFilter(9999); err == nil {
		t.Error("expected unsupported link type")
	}
}

func TestNeighborFilter(t *testing.T) {
	v := vm(t, NeighborFilter, garagat.LinkTypeEthernet)
	accepted := 0
	for _, p := range packets(t, "arp.pcap") {
		n, _ := v.Run(p)
		isReply := len(p) >= 22 && p[20] == 0 && p[21] == 2
		if (n > 0) != isReply {
			t.Errorf("arp op %d: accepted=%v", p[21], n > 0)
		}
		if n > 0 {
			accepted++
		}
	}
	for _, p := range packets(t, "icmp6-icmp6-echo-reply.pcap") {
		if n, _ := v.Run(p); n != 0 {
			t.Error("ICMPv6 echo accepted")
		}
	}
	if _, err := NeighborFilter(garagat.LinkTypeRaw); err == nil {
		t.Error("expected error for raw link")
	}
}
