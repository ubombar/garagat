package garagat

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// TestBuildMatchesCaracal rebuilds the probes captured in the caracal
// fixtures (the first frame of each file was sent by caracal) and checks that
// garagat produces the same bytes.
func TestBuildMatchesCaracal(t *testing.T) {
	for _, name := range []string{
		"icmp-icmp-ttl-exceeded.pcap",
		"icmp-icmp-ttl-exceeded-mpls.pcap",
		"icmp-icmp-echo-reply.pcap",
		"icmp6-icmp6-ttl-exceeded.pcap",
		"icmp6-icmp6-echo-reply.pcap",
		"udp-icmp-ttl-exceeded.pcap",
		"udp-icmp6-ttl-exceeded.pcap",
	} {
		t.Run(name, func(t *testing.T) {
			pkts, _ := readPcap(t, "testdata/"+name)
			want := pkts[0].Data
			var dst, src [6]byte
			copy(dst[:], want[0:6])
			copy(src[:], want[6:12])
			l3 := want[14:]
			var (
				l3p          L3
				l4p          L4
				srcIP, dstIP netip.Addr
				ttl          uint8
				l4           []byte
			)
			if binary.BigEndian.Uint16(want[12:]) == 0x0800 {
				l3p = IPv4
				srcIP = netip.AddrFrom4([4]byte(l3[12:16]))
				dstIP = netip.AddrFrom4([4]byte(l3[16:20]))
				ttl = l3[8]
				l4 = l3[20:]
				if l3[9] == ProtoUDP {
					l4p = UDP
				} else {
					l4p = ICMP
				}
			} else {
				l3p = IPv6
				srcIP = netip.AddrFrom16([16]byte(l3[8:24]))
				dstIP = netip.AddrFrom16([16]byte(l3[24:40]))
				ttl = l3[7]
				l4 = l3[40:]
				if l3[6] == ProtoUDP {
					l4p = UDP
				} else {
					l4p = ICMPv6
				}
			}
			// The fixtures were captured with older caracal versions that
			// encoded the TTL in the payload length; derive it from the
			// packet so the test checks the encoding, not the version.
			payloadSize := len(l4) - l4p.HeaderSize()
			if l3p == IPv4 {
				payloadSize = int(binary.BigEndian.Uint16(l3[2:])) - IPv4HeaderSize - l4p.HeaderSize()
			} else {
				payloadSize = int(binary.BigEndian.Uint16(l3[4:])) - l4p.HeaderSize()
			}
			buf := make([]byte, 65536)
			p, err := NewPacket(buf, L2Ethernet, l3p, l4p, payloadSize)
			if err != nil {
				t.Fatal(err)
			}
			BuildEthernet(p, src, dst)
			if l3p == IPv4 {
				BuildIPv4(p, srcIP, dstIP, ttl, binary.BigEndian.Uint16(l3[4:]))
			} else {
				BuildIPv6(p, srcIP, dstIP, ttl, binary.BigEndian.Uint32(l3)&0xFFFFF)
			}
			switch l4p {
			case ICMP:
				BuildICMP(p, binary.BigEndian.Uint16(l4[4:]), binary.BigEndian.Uint16(l4[6:]))
			case ICMPv6:
				BuildICMPv6(p, binary.BigEndian.Uint16(l4[4:]), binary.BigEndian.Uint16(l4[6:]))
			case UDP:
				BuildUDP(p, binary.BigEndian.Uint16(l4[6:]), binary.BigEndian.Uint16(l4[0:]), binary.BigEndian.Uint16(l4[2:]))
			}
			got := p.Bytes()
			if !bytes.Equal(got, want[:len(got)]) {
				t.Errorf("built packet differs from caracal\n got %x\nwant %x", got, want[:len(got)])
			}
		})
	}
}

func verifyTransport(t *testing.T, p *Packet) {
	t.Helper()
	if p.L3Proto == IPv4 {
		if ChecksumFold(ChecksumAdd(0, p.L3()[:IPv4HeaderSize])) != 0 {
			t.Error("invalid IPv4 header checksum")
		}
	}
	var sum uint64
	if p.L4Proto == ICMP {
		sum = ChecksumAdd(0, p.L4())
	} else {
		l3 := p.L3()
		sum = ChecksumAdd(0, p.L4())
		if p.L3Proto == IPv4 {
			sum += IPv4PseudoHeaderSum([4]byte(l3[12:16]), [4]byte(l3[16:20]), p.L4Proto.Number(), uint16(len(p.L4())))
		} else {
			sum += IPv6PseudoHeaderSum([16]byte(l3[8:24]), [16]byte(l3[24:40]), p.L4Proto.Number(), uint32(len(p.L4())))
		}
	}
	if ChecksumFold(sum) != 0 {
		t.Errorf("invalid transport checksum for %v/%v", p.L3Proto, p.L4Proto)
	}
}

func TestBuildChecksums(t *testing.T) {
	src4, dst4 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("1.1.1.1")
	src6, dst6 := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:4860:4860::8888")
	buf := make([]byte, 65536)
	for _, target := range []uint16{0, 1, 24000, 0x7FFF, 0xFFFE, 0xFFFF} {
		for ttl := 0; ttl < 256; ttl += 17 {
			for _, c := range []struct {
				l3 L3
				l4 L4
			}{{IPv4, ICMP}, {IPv4, UDP}, {IPv6, ICMPv6}, {IPv6, UDP}} {
				p, err := NewPacket(buf, L2Ethernet, c.l3, c.l4, ttl+PayloadTweakBytes)
				if err != nil {
					t.Fatal(err)
				}
				BuildEthernet(p, [6]byte{1}, [6]byte{2})
				if c.l3 == IPv4 {
					BuildIPv4(p, src4, dst4, uint8(ttl), 1234)
				} else {
					BuildIPv6(p, src6, dst6, uint8(ttl), 5)
				}
				switch c.l4 {
				case ICMP:
					BuildICMP(p, target, 42)
				case ICMPv6:
					BuildICMPv6(p, target, 42)
				case UDP:
					BuildUDP(p, target, 24000, 33434)
				}
				if target != 0 && target != 0xFFFF {
					verifyTransport(t, p)
				}
				cks := binary.BigEndian.Uint16(p.L4()[2:])
				if c.l4 == UDP {
					cks = binary.BigEndian.Uint16(p.L4()[6:])
				}
				if cks != target {
					t.Errorf("checksum field = %d, want %d", cks, target)
				}
			}
		}
	}
}

func TestProbeBuilderRoundTrip(t *testing.T) {
	// Build probes, wrap them in synthetic ICMP replies, parse the replies and
	// check that the probe fields are recovered.
	b := &ProbeBuilder{
		L2:        L2Ethernet,
		SrcIPv4:   netip.MustParseAddr("192.0.2.1"),
		SrcIPv6:   netip.MustParseAddr("2001:db8::1"),
		CaracalID: 4242,
	}
	probes := []string{
		"8.8.8.8,24000,33434,7,udp",
		"8.8.8.8,24000,0,1,icmp",
		"2001:4860:4860::8888,24001,33434,12,udp",
		"2001:4860:4860::8888,65535,0,255,icmp6,77",
	}
	const sendTenthMs = 16131556238455
	for _, line := range probes {
		probe, err := ParseProbe(line)
		if err != nil {
			t.Fatal(err)
		}
		pkt, err := b.Build(probe, EncodeTimestamp(sendTenthMs))
		if err != nil {
			t.Fatal(err)
		}
		router := netip.MustParseAddr("203.0.113.9")
		if probe.L3() == IPv6 {
			router = netip.MustParseAddr("2001:db8:ffff::9")
		}
		reply := TimeExceeded(router, pkt[EthernetHeaderSize:], 64)
		captureUs := int64(sendTenthMs*100 + 12345)
		r, ok := Parse(reply, LinkTypeRaw, captureUs)
		if !ok {
			t.Fatalf("%s: reply not parsed", line)
		}
		if r.ProbeDstAddr != MapAddr(probe.DstAddr) || r.ProbeSrcPort != probe.SrcPort ||
			r.ProbeTTL != probe.TTL || r.ProbeProtocol != probe.Protocol.Number() || !r.IsTimeExceeded() {
			t.Errorf("%s: got %s", line, r)
		}
		if probe.Protocol == UDP && r.ProbeDstPort != probe.DstPort {
			t.Errorf("%s: dst port %d", line, r.ProbeDstPort)
		}
		if r.RTT != 123 {
			t.Errorf("%s: rtt = %d, want 123", line, r.RTT)
		}
		if !r.IsValid(b.CaracalID) {
			t.Errorf("%s: reply is not valid", line)
		}
		if probe.L3() == IPv6 && r.ProbeFlowLabel != probe.FlowLabel {
			t.Errorf("%s: flow label %d", line, r.ProbeFlowLabel)
		}
	}
}

func TestPacketErrors(t *testing.T) {
	if _, err := NewPacket(make([]byte, 10), L2Ethernet, IPv4, ICMP, 2); err == nil {
		t.Error("expected buffer too small")
	}
	if _, err := NewPacket(make([]byte, 70000), L2None, IPv6, UDP, 66000); err == nil {
		t.Error("expected packet too large")
	}
	defer func() {
		if recover() == nil {
			t.Error("expected panic for short payload")
		}
	}()
	p, _ := NewPacket(make([]byte, 100), L2None, IPv4, ICMP, 1)
	BuildICMP(p, 1, 1)
}

func TestBuildLoopback(t *testing.T) {
	buf := make([]byte, 128)
	p, _ := NewPacket(buf, L2BSDLoopback, IPv4, ICMP, 2)
	BuildLoopback(p)
	BuildIPv4(p, netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.1"), 1, 1)
	if binary.NativeEndian.Uint32(p.L2()) != 2 {
		t.Error("wrong IPv4 family")
	}
	if v, _ := networkLayer(p.L2(), LinkTypeNull); v != 4 {
		t.Error("loopback packet not recognized as IPv4")
	}
}

func TestTweakPayload(t *testing.T) {
	for _, o := range []uint16{0, 1, 0x1234, 0xFFFE, 0xFFFF} {
		for _, tg := range []uint16{1, 0x8000, 0xFFFE} {
			tw := TweakPayload(o, tg)
			if got := ChecksumFinish(uint64(^o) + uint64(tw)); got != tg && o != 0 {
				t.Errorf("TweakPayload(%x, %x) = %x gives %x", o, tg, tw, got)
			}
		}
	}
}
