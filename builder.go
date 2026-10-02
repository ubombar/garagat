package garagat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
)

// Packet is a packet buffer with the offsets of its layers.
type Packet struct {
	buf                      []byte
	l2, l3, l4, payload, end int
	L2Proto                  L2
	L3Proto                  L3
	L4Proto                  L4
}

// NewPacket lays out a packet with the given protocols and payload size in
// buf. The packet bytes are zeroed.
func NewPacket(buf []byte, l2 L2, l3 L3, l4 L4, payloadSize int) (*Packet, error) {
	p := &Packet{L2Proto: l2, L3Proto: l3, L4Proto: l4}
	p.l2 = 0
	p.l3 = p.l2 + l2.HeaderSize()
	p.l4 = p.l3 + l3.HeaderSize()
	p.payload = p.l4 + l4.HeaderSize()
	p.end = p.payload + payloadSize
	if p.end > len(buf) {
		return nil, errors.New("packet buffer is too small")
	}
	if p.end > 65535 {
		return nil, errors.New("packet is too large")
	}
	p.buf = buf[:p.end]
	clear(p.buf)
	return p, nil
}

// Bytes returns the packet starting from the link-layer header.
func (p *Packet) Bytes() []byte { return p.buf[p.l2:p.end] }

// L2 returns the packet starting from the link-layer header.
func (p *Packet) L2() []byte { return p.buf[p.l2:p.end] }

// L3 returns the packet starting from the network-layer header.
func (p *Packet) L3() []byte { return p.buf[p.l3:p.end] }

// L4 returns the packet starting from the transport-layer header.
func (p *Packet) L4() []byte { return p.buf[p.l4:p.end] }

// Payload returns the packet payload.
func (p *Packet) Payload() []byte { return p.buf[p.payload:p.end] }

// TransportChecksum computes the transport checksum, including the IPv4 or
// IPv6 pseudo-header. The IP header must already be built.
func (p *Packet) TransportChecksum() uint16 {
	l3, l4 := p.L3(), p.L4()
	sum := ChecksumAdd(0, l4)
	if p.L3Proto == IPv4 {
		sum += IPv4PseudoHeaderSum([4]byte(l3[12:16]), [4]byte(l3[16:20]), p.L4Proto.Number(), uint16(len(l4)))
	} else {
		sum += IPv6PseudoHeaderSum([16]byte(l3[8:24]), [16]byte(l3[24:40]), p.L4Proto.Number(), uint32(len(l4)))
	}
	return ChecksumFinish(sum)
}

// TweakPayload returns the two payload bytes (as a big-endian word) that turn
// a packet whose checksum is original into a packet whose checksum is target.
func TweakPayload(original, target uint16) uint16 {
	o := uint32(^original)
	t := uint32(^target)
	if t < o {
		t += 0xFFFF
	}
	return uint16(t - o)
}

func (p *Packet) checkPayload() {
	if len(p.Payload()) < PayloadTweakBytes {
		panic(fmt.Sprintf("the payload must be at-least %d bytes long to allow for a custom checksum", PayloadTweakBytes))
	}
}

// loopbackAF6 is the value of AF_INET6 in the BSD loopback header.
var loopbackAF6 = map[string]uint32{"darwin": 30, "ios": 30, "freebsd": 28, "dragonfly": 28, "openbsd": 24, "netbsd": 24}[runtime.GOOS]

// BuildLoopback builds the BSD loopback header (DLT_NULL): the address family
// in host byte order.
func BuildLoopback(p *Packet) {
	af := uint32(2)
	if p.L3Proto == IPv6 {
		af = loopbackAF6
		if af == 0 {
			af = 30
		}
	}
	binary.NativeEndian.PutUint32(p.L2(), af)
}

// BuildEthernet builds the Ethernet header.
func BuildEthernet(p *Packet, src, dst [6]byte) {
	b := p.L2()
	copy(b[0:6], dst[:])
	copy(b[6:12], src[:])
	if p.L3Proto == IPv4 {
		binary.BigEndian.PutUint16(b[12:], 0x0800)
	} else {
		binary.BigEndian.PutUint16(b[12:], 0x86DD)
	}
}

// BuildIPv4 builds the IPv4 header. The probe checksum is stored in the ID
// field, since the TTL field is modified at each hop.
func BuildIPv4(p *Packet, src, dst netip.Addr, ttl uint8, id uint16) {
	b := p.L3()
	b[0] = 0x45
	b[1] = 0
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	binary.BigEndian.PutUint16(b[4:], id)
	binary.BigEndian.PutUint16(b[6:], 0)
	b[8] = ttl
	b[9] = p.L4Proto.Number()
	binary.BigEndian.PutUint16(b[10:], 0)
	s, d := src.Unmap().As4(), dst.Unmap().As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[10:], IPChecksum(b[:IPv4HeaderSize]))
}

// BuildIPv6 builds the IPv6 header. The TTL cannot be stored in the flow
// label since it is used for load-balancing, it is encoded in the payload
// length instead (see https://homepages.dcc.ufmg.br/~cunha/papers/almeida17pam-mda6.pdf).
func BuildIPv6(p *Packet, src, dst netip.Addr, ttl uint8, flowLabel uint32) {
	b := p.L3()
	binary.BigEndian.PutUint32(b[0:], 0x60000000+flowLabel)
	binary.BigEndian.PutUint16(b[4:], uint16(len(p.L4())))
	b[6] = p.L4Proto.Number()
	b[7] = ttl
	s, d := src.As16(), dst.As16()
	copy(b[8:24], s[:])
	copy(b[24:40], d[:])
}

// BuildICMP builds an ICMP echo request. The flow ID is encoded in the
// checksum (and in the identifier), and the timestamp in the sequence number.
func BuildICMP(p *Packet, targetChecksum, sequence uint16) {
	p.checkPayload()
	b := p.L4()
	b[0] = 8 // Echo Request
	b[1] = 0
	binary.BigEndian.PutUint16(b[2:], 0)
	binary.BigEndian.PutUint16(b[4:], targetChecksum)
	binary.BigEndian.PutUint16(b[6:], sequence)
	original := IPChecksum(b[:ICMPHeaderSize])
	binary.BigEndian.PutUint16(p.Payload(), TweakPayload(original, targetChecksum))
	binary.BigEndian.PutUint16(b[2:], targetChecksum)
}

// BuildICMPv6 builds an ICMPv6 echo request. Unlike ICMPv4, the checksum
// includes the IPv6 pseudo-header, so the IP header must be built first.
func BuildICMPv6(p *Packet, targetChecksum, sequence uint16) {
	p.checkPayload()
	b := p.L4()
	b[0] = 128 // Echo Request
	b[1] = 0
	binary.BigEndian.PutUint16(b[2:], 0)
	binary.BigEndian.PutUint16(b[4:], targetChecksum)
	binary.BigEndian.PutUint16(b[6:], sequence)
	original := p.TransportChecksum()
	binary.BigEndian.PutUint16(p.Payload(), TweakPayload(original, targetChecksum))
	binary.BigEndian.PutUint16(b[2:], targetChecksum)
}

// BuildUDP builds a UDP probe. The flow ID is encoded in the ports and the
// timestamp in the checksum. The TTL is encoded in the payload length.
func BuildUDP(p *Packet, targetChecksum, srcPort, dstPort uint16) {
	p.checkPayload()
	b := p.L4()
	binary.BigEndian.PutUint16(b[0:], srcPort)
	binary.BigEndian.PutUint16(b[2:], dstPort)
	binary.BigEndian.PutUint16(b[4:], uint16(len(b)))
	binary.BigEndian.PutUint16(b[6:], 0)
	original := p.TransportChecksum()
	binary.BigEndian.PutUint16(p.Payload(), TweakPayload(original, targetChecksum))
	binary.BigEndian.PutUint16(b[6:], targetChecksum)
}

// ProbeBuilder builds complete probe packets for a given link.
type ProbeBuilder struct {
	L2        L2
	SrcMAC    [6]byte
	DstMACv4  [6]byte
	DstMACv6  [6]byte
	SrcIPv4   netip.Addr
	SrcIPv6   netip.Addr
	CaracalID uint16
	buf       [65536]byte
}

// Build builds the probe packet with the given encoded timestamp. The returned
// slice is only valid until the next call.
func (b *ProbeBuilder) Build(probe Probe, timestampEnc uint16) ([]byte, error) {
	l3 := probe.L3()
	p, err := NewPacket(b.buf[:], b.L2, l3, probe.Protocol, int(probe.TTL)+PayloadTweakBytes)
	if err != nil {
		return nil, err
	}
	switch b.L2 {
	case L2BSDLoopback:
		BuildLoopback(p)
	case L2Ethernet:
		if l3 == IPv4 {
			BuildEthernet(p, b.SrcMAC, b.DstMACv4)
		} else {
			BuildEthernet(p, b.SrcMAC, b.DstMACv6)
		}
	}
	if l3 == IPv4 {
		src := b.SrcIPv4
		if !src.IsValid() {
			src = netip.IPv4Unspecified()
		}
		BuildIPv4(p, src, probe.DstAddr, probe.TTL, probe.Checksum(b.CaracalID))
	} else {
		src := b.SrcIPv6
		if !src.IsValid() {
			src = netip.IPv6Unspecified()
		}
		BuildIPv6(p, src, probe.DstAddr, probe.TTL, probe.FlowLabel)
	}
	switch probe.Protocol {
	case ICMP:
		BuildICMP(p, probe.SrcPort, timestampEnc)
	case ICMPv6:
		BuildICMPv6(p, probe.SrcPort, timestampEnc)
	case UDP:
		BuildUDP(p, timestampEnc, probe.SrcPort, probe.DstPort)
	}
	return p.Bytes(), nil
}
