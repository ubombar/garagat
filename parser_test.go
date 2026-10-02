package garagat

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"testing"

	"github.com/ubombar/garagat/pcapfile"
)

func readPcap(t *testing.T, path string) ([]pcapfile.Packet, LinkType) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := pcapfile.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var pkts []pcapfile.Packet
	for {
		p, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		p.Data = append([]byte(nil), p.Data...)
		pkts = append(pkts, p)
	}
	return pkts, LinkType(r.LinkType())
}

func parseFile(t *testing.T, path string) []*Reply {
	t.Helper()
	pkts, lt := readPcap(t, path)
	var replies []*Reply
	for _, p := range pkts {
		if r, ok := Parse(p.Data, lt, p.Timestamp.UnixMicro()); ok {
			replies = append(replies, r)
		}
	}
	return replies
}

func addr(s string) netip.Addr { return MapAddr(netip.MustParseAddr(s)) }

type expected struct {
	ts                              int64
	replySrc, replyDst              string
	replySize                       uint16
	replyTTL, replyProto, typ, code uint8
	labels                          []MPLSLabel
	probeDst                        string
	probeSize                       uint16
	probeTTL, probeProto            uint8
	srcPort, dstPort                uint16
	quotedTTL                       uint8
	rtt                             int // -1 to skip
	unreach, echo, exceeded         bool
}

func check(t *testing.T, r *Reply, e expected) {
	t.Helper()
	eq := func(name string, got, want any) {
		t.Helper()
		if got != want {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	eq("capture_timestamp", r.CaptureTimestamp, e.ts)
	eq("reply_src_addr", r.ReplySrcAddr, addr(e.replySrc))
	eq("reply_dst_addr", r.ReplyDstAddr, addr(e.replyDst))
	eq("reply_size", r.ReplySize, e.replySize)
	eq("reply_ttl", r.ReplyTTL, e.replyTTL)
	eq("reply_protocol", r.ReplyProtocol, e.replyProto)
	eq("reply_icmp_type", r.ReplyICMPType, e.typ)
	eq("reply_icmp_code", r.ReplyICMPCode, e.code)
	eq("len(reply_mpls_labels)", len(r.ReplyMPLSLabels), len(e.labels))
	for i := range min(len(r.ReplyMPLSLabels), len(e.labels)) {
		eq("mpls label", r.ReplyMPLSLabels[i], e.labels[i])
	}
	eq("probe_dst_addr", r.ProbeDstAddr, addr(e.probeDst))
	eq("probe_size", r.ProbeSize, e.probeSize)
	eq("probe_ttl", r.ProbeTTL, e.probeTTL)
	eq("probe_protocol", r.ProbeProtocol, e.probeProto)
	eq("probe_src_port", r.ProbeSrcPort, e.srcPort)
	eq("probe_dst_port", r.ProbeDstPort, e.dstPort)
	eq("quoted_ttl", r.QuotedTTL, e.quotedTTL)
	if e.rtt >= 0 {
		eq("rtt", r.RTT, uint16(e.rtt))
	}
	eq("is_destination_unreachable", r.IsDestinationUnreachable(), e.unreach)
	eq("is_echo_reply", r.IsEchoReply(), e.echo)
	eq("is_time_exceeded", r.IsTimeExceeded(), e.exceeded)
}

// The expected values are the ones of caracal's tests/parser_test.cpp.
func TestParseFixtures(t *testing.T) {
	cases := map[string]expected{
		"icmp-icmp-ttl-exceeded.pcap": {
			ts: 1613155623845580, replySrc: "72.14.204.68", replyDst: "192.168.1.5",
			replySize: 56, replyTTL: 250, replyProto: ProtoICMP, typ: 11, code: 0,
			probeDst: "8.8.8.8", probeSize: 36, probeTTL: 6, probeProto: ProtoICMP,
			srcPort: 24000, dstPort: 0, quotedTTL: 1, rtt: 66, exceeded: true,
		},
		"icmp-icmp-ttl-exceeded-mpls.pcap": {
			ts: 1638522471773669, replySrc: "12.122.28.42", replyDst: "132.227.123.8",
			replySize: 172, replyTTL: 239, replyProto: ProtoICMP, typ: 11, code: 0,
			labels:   []MPLSLabel{{29657, 0, 0, 1}, {25437, 0, 1, 1}},
			probeDst: "65.83.239.127", probeSize: 42, probeTTL: 12, probeProto: ProtoICMP,
			srcPort: 24000, dstPort: 0, quotedTTL: 2, rtt: -1, exceeded: true,
		},
		"icmp-icmp-echo-reply.pcap": {
			ts: 1613155697130290, replySrc: "8.8.8.8", replyDst: "192.168.1.5",
			replySize: 40, replyTTL: 117, replyProto: ProtoICMP, typ: 0, code: 0,
			probeDst: "8.8.8.8", probeSize: 0, probeTTL: 10, probeProto: ProtoICMP,
			srcPort: 24000, dstPort: 0, quotedTTL: 0, rtt: 69, echo: true,
		},
		"icmp6-icmp6-ttl-exceeded.pcap": {
			ts: 1615987564867543, replySrc: "2a04:8ec0:0:a::1:119", replyDst: "2a04:8ec0:0:164:620c:e59a:daf8:21e9",
			replySize: 60, replyTTL: 63, replyProto: ProtoICMPv6, typ: 3, code: 0,
			probeDst: "2001:4860:4860::8888", probeSize: 12, probeTTL: 2, probeProto: ProtoICMPv6,
			srcPort: 24000, dstPort: 0, quotedTTL: 1, rtt: 6, exceeded: true,
		},
		"icmp6-icmp6-echo-reply.pcap": {
			ts: 1615987338565191, replySrc: "2001:4860:4860::8888", replyDst: "2a04:8ec0:0:164:620c:e59a:daf8:21e9",
			replySize: 18, replyTTL: 118, replyProto: ProtoICMPv6, typ: 129, code: 0,
			probeDst: "2001:4860:4860::8888", probeSize: 0, probeTTL: 8, probeProto: ProtoICMPv6,
			srcPort: 24000, dstPort: 0, quotedTTL: 0, rtt: 13, echo: true,
		},
		"udp-icmp-ttl-exceeded.pcap": {
			ts: 1613155487934429, replySrc: "72.14.204.68", replyDst: "192.168.1.5",
			replySize: 56, replyTTL: 250, replyProto: ProtoICMP, typ: 11, code: 0,
			probeDst: "8.8.8.8", probeSize: 36, probeTTL: 6, probeProto: ProtoUDP,
			srcPort: 24000, dstPort: 33434, quotedTTL: 1, rtt: 83, exceeded: true,
		},
		"udp-icmp6-ttl-exceeded.pcap": {
			ts: 1615987632702320, replySrc: "2a04:8ec0:0:a::1:119", replyDst: "2a04:8ec0:0:164:620c:e59a:daf8:21e9",
			replySize: 60, replyTTL: 63, replyProto: ProtoICMPv6, typ: 3, code: 0,
			probeDst: "2001:4860:4860::8888", probeSize: 12, probeTTL: 2, probeProto: ProtoUDP,
			srcPort: 24000, dstPort: 33434, quotedTTL: 1, rtt: 6, exceeded: true,
		},
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			replies := parseFile(t, "testdata/"+name)
			if len(replies) != 1 {
				t.Fatalf("got %d replies, want 1", len(replies))
			}
			check(t, replies[0], e)
		})
	}
}

func TestParseNonIP(t *testing.T) {
	if replies := parseFile(t, "testdata/arp.pcap"); len(replies) != 0 {
		t.Fatalf("got %d replies, want 0", len(replies))
	}
}

func TestParseGarbage(t *testing.T) {
	inputs := [][]byte{nil, {0}, make([]byte, 14), make([]byte, 60), {0x45, 0, 0, 0}}
	for _, lt := range []LinkType{LinkTypeEthernet, LinkTypeNull, LinkTypeRaw, LinkTypeLinuxSLL, 9999} {
		for _, in := range inputs {
			if _, ok := Parse(in, lt, 0); ok {
				t.Errorf("Parse(%x, %d) succeeded", in, lt)
			}
		}
	}
	// Truncate every fixture at every length: the parser must never panic.
	for _, name := range []string{"icmp-icmp-ttl-exceeded-mpls.pcap", "udp-icmp6-ttl-exceeded.pcap", "icmp6-icmp6-echo-reply.pcap"} {
		pkts, lt := readPcap(t, "testdata/"+name)
		for _, p := range pkts {
			for i := range p.Data {
				Parse(p.Data[:i], lt, 0)
			}
		}
	}
}

func TestReplyCSV(t *testing.T) {
	replies := parseFile(t, "testdata/icmp-icmp-ttl-exceeded-mpls.pcap")
	got := replies[0].CSV("1")
	want := `1638522471773669,1,::ffff:132.227.123.8,::ffff:65.83.239.127,24000,0,12,2,::ffff:12.122.28.42,1,11,0,239,172,"[(29657,0,0,1),(25437,0,1,1)]",` +
		itoa(int(replies[0].RTT)) + ",1"
	if got != want {
		t.Errorf("CSV =\n%s\nwant\n%s", got, want)
	}
	replies = parseFile(t, "testdata/udp-icmp6-ttl-exceeded.pcap")
	got = replies[0].CSV("round-7")
	want = `1615987632702320,17,2a04:8ec0:0:164:620c:e59a:daf8:21e9,2001:4860:4860::8888,24000,33434,2,1,2a04:8ec0:0:a::1:119,58,3,0,63,60,"[]",6,round-7`
	if got != want {
		t.Errorf("CSV =\n%s\nwant\n%s", got, want)
	}
}

func itoa(i int) string {
	return string(appendInt(nil, i))
}

func appendInt(b []byte, i int) []byte {
	if i >= 10 {
		b = appendInt(b, i/10)
	}
	return append(b, byte('0'+i%10))
}

func TestReplyIsValid(t *testing.T) {
	// The fixtures were captured with an unknown caracal ID, so we recompute
	// the probe ID instead.
	r := parseFile(t, "testdata/icmp-icmp-ttl-exceeded.pcap")[0]
	var id uint16
	found := false
	for i := 0; i < 65536; i++ {
		if r.IsValid(uint16(i)) {
			id, found = uint16(i), true
			break
		}
	}
	if !found {
		t.Fatal("no caracal ID validates the reply")
	}
	if r.Checksum(id) != r.ProbeID {
		t.Fatal("checksum mismatch")
	}
	if r.IsValid(id + 1) {
		t.Error("reply is valid with the wrong ID")
	}
	echo := parseFile(t, "testdata/icmp-icmp-echo-reply.pcap")[0]
	if !echo.IsValid(1234) {
		t.Error("echo replies must always be valid")
	}
}

func FuzzParse(f *testing.F) {
	for _, name := range []string{"icmp-icmp-ttl-exceeded-mpls.pcap", "udp-icmp6-ttl-exceeded.pcap", "icmp-icmp-echo-reply.pcap"} {
		f.Add(mustRead(name))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		Parse(data, LinkTypeEthernet, 1)
		Parse(data, LinkTypeRaw, 1)
	})
}

func mustRead(name string) []byte {
	f, err := os.Open("testdata/" + name)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	r, err := pcapfile.NewReader(f)
	if err != nil {
		panic(err)
	}
	var last []byte
	for {
		p, err := r.Next()
		if err != nil {
			return last
		}
		last = append([]byte(nil), p.Data...)
	}
}
