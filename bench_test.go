package garagat

import (
	"net/netip"
	"testing"
)

func BenchmarkParseProbe(b *testing.B) {
	for b.Loop() {
		ParseProbe("2001:4860:4860::8888,24000,33434,12,icmp6,1")
	}
}

func BenchmarkBuild(b *testing.B) {
	pb := &ProbeBuilder{L2: L2Ethernet, SrcIPv4: netip.MustParseAddr("192.0.2.1"), CaracalID: 1}
	p, _ := ParseProbe("8.8.8.8,24000,33434,12,udp")
	for b.Loop() {
		pb.Build(p, 1234)
	}
}

func BenchmarkParseReply(b *testing.B) {
	data := mustRead("icmp-icmp-ttl-exceeded-mpls.pcap")
	for b.Loop() {
		Parse(data, LinkTypeEthernet, 1638522471773669)
	}
}

func BenchmarkReplyCSV(b *testing.B) {
	r, _ := Parse(mustRead("icmp-icmp-ttl-exceeded-mpls.pcap"), LinkTypeEthernet, 1638522471773669)
	var buf []byte
	for b.Loop() {
		buf = r.AppendCSV(buf[:0], "1")
	}
}

func BenchmarkIPChecksum(b *testing.B) {
	data := []byte{0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7}
	for b.Loop() {
		IPChecksum(data)
	}
}
