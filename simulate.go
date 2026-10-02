package garagat

import (
	"encoding/binary"
	"net/netip"
)

// This file builds the replies a router or a host would send to a probe. It
// is used by the tests and by the simulated link of the prober, and can be
// used to test tools built on garagat without network access.

// TimeExceeded returns the raw IP packet (no link-layer header) of an ICMP or
// ICMPv6 time exceeded message sent by `from` in response to `probe`, a raw
// IP packet. The whole probe is quoted.
func TimeExceeded(from netip.Addr, probe []byte, ttl uint8) []byte {
	return icmpError(from, probe, ttl, 11, 3, 0)
}

// DestinationUnreachable returns an ICMP or ICMPv6 destination unreachable
// message (port unreachable) sent by `from` in response to `probe`.
func DestinationUnreachable(from netip.Addr, probe []byte, ttl uint8) []byte {
	return icmpError(from, probe, ttl, 3, 1, 4)
}

func icmpError(from netip.Addr, probe []byte, ttl uint8, type4, type6, code6 uint8) []byte {
	if len(probe) == 0 {
		return nil
	}
	if probe[0]>>4 == 4 {
		code := uint8(0)
		if type4 == 3 {
			code = 3 // Port unreachable
		}
		icmp := make([]byte, 8+len(probe))
		icmp[0], icmp[1] = type4, code
		copy(icmp[8:], probe)
		binary.BigEndian.PutUint16(icmp[2:], IPChecksum(icmp))
		return ipv4Packet(from, netip.AddrFrom4([4]byte(probe[12:16])), ttl, ProtoICMP, icmp)
	}
	icmp := make([]byte, 8+len(probe))
	icmp[0], icmp[1] = type6, code6
	copy(icmp[8:], probe)
	src := from.As16()
	dst := [16]byte(probe[8:24])
	sum := ChecksumAdd(0, icmp) + IPv6PseudoHeaderSum(src, dst, ProtoICMPv6, uint32(len(icmp)))
	binary.BigEndian.PutUint16(icmp[2:], ChecksumFinish(sum))
	return ipv6Packet(from, netip.AddrFrom16(dst), ttl, ProtoICMPv6, icmp)
}

// EchoReply returns the ICMP or ICMPv6 echo reply to an echo request probe,
// as a raw IP packet, or nil if the probe is not an echo request.
func EchoReply(probe []byte, ttl uint8) []byte {
	if len(probe) == 0 {
		return nil
	}
	if probe[0]>>4 == 4 {
		ihl := int(probe[0]&0xF) * 4
		if len(probe) < ihl+8 || probe[9] != ProtoICMP || probe[ihl] != 8 {
			return nil
		}
		icmp := append([]byte(nil), probe[ihl:]...)
		icmp[0] = 0
		binary.BigEndian.PutUint16(icmp[2:], 0)
		binary.BigEndian.PutUint16(icmp[2:], IPChecksum(icmp))
		return ipv4Packet(netip.AddrFrom4([4]byte(probe[16:20])), netip.AddrFrom4([4]byte(probe[12:16])), ttl, ProtoICMP, icmp)
	}
	if len(probe) < IPv6HeaderSize+8 || probe[6] != ProtoICMPv6 || probe[IPv6HeaderSize] != 128 {
		return nil
	}
	icmp := append([]byte(nil), probe[IPv6HeaderSize:]...)
	icmp[0] = 129
	src, dst := [16]byte(probe[24:40]), [16]byte(probe[8:24])
	binary.BigEndian.PutUint16(icmp[2:], 0)
	sum := ChecksumAdd(0, icmp) + IPv6PseudoHeaderSum(src, dst, ProtoICMPv6, uint32(len(icmp)))
	binary.BigEndian.PutUint16(icmp[2:], ChecksumFinish(sum))
	return ipv6Packet(netip.AddrFrom16(src), netip.AddrFrom16(dst), ttl, ProtoICMPv6, icmp)
}

func ipv4Packet(src, dst netip.Addr, ttl, proto uint8, payload []byte) []byte {
	b := make([]byte, IPv4HeaderSize+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8], b[9] = ttl, proto
	s, d := src.Unmap().As4(), dst.Unmap().As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	binary.BigEndian.PutUint16(b[10:], IPChecksum(b[:IPv4HeaderSize]))
	copy(b[IPv4HeaderSize:], payload)
	return b
}

func ipv6Packet(src, dst netip.Addr, hops, next uint8, payload []byte) []byte {
	b := make([]byte, IPv6HeaderSize+len(payload))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], uint16(len(payload)))
	b[6], b[7] = next, hops
	s, d := src.As16(), dst.As16()
	copy(b[8:], s[:])
	copy(b[24:], d[:])
	copy(b[IPv6HeaderSize:], payload)
	return b
}
