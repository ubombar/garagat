package garagat

import (
	"encoding/binary"
	"net/netip"
)

// LinkType is a pcap link-layer header type (LINKTYPE_* / DLT_*).
type LinkType uint32

const (
	LinkTypeNull     LinkType = 0   // BSD loopback, host-order address family
	LinkTypeEthernet LinkType = 1   // Ethernet II
	LinkTypeRawBSD   LinkType = 12  // DLT_RAW on most BSDs and Linux
	LinkTypeRawOBSD  LinkType = 14  // DLT_RAW on OpenBSD
	LinkTypeRaw      LinkType = 101 // LINKTYPE_RAW
	LinkTypeLoop     LinkType = 108 // OpenBSD loopback, network-order family
	LinkTypeLinuxSLL LinkType = 113 // Linux cooked capture
	LinkTypeIPv4     LinkType = 228
	LinkTypeIPv6     LinkType = 229
)

// L2 returns the link-layer protocol used to build probes for this link type.
func (t LinkType) L2() (L2, bool) {
	switch t {
	case LinkTypeEthernet:
		return L2Ethernet, true
	case LinkTypeNull:
		return L2BSDLoopback, true
	case LinkTypeRawBSD, LinkTypeRawOBSD, LinkTypeRaw:
		return L2None, true
	}
	return 0, false
}

// networkLayer strips the link-layer header. It returns the IP version found
// (4 or 6) and the network-layer bytes, or 0 if the packet is not IP.
func networkLayer(data []byte, lt LinkType) (int, []byte) {
	var ethertype uint16
	switch lt {
	case LinkTypeEthernet:
		if len(data) < EthernetHeaderSize {
			return 0, nil
		}
		ethertype = binary.BigEndian.Uint16(data[12:])
		data = data[EthernetHeaderSize:]
		// 802.1Q and 802.1ad VLAN tags.
		for (ethertype == 0x8100 || ethertype == 0x88A8) && len(data) >= 4 {
			ethertype = binary.BigEndian.Uint16(data[2:])
			data = data[4:]
		}
	case LinkTypeLinuxSLL:
		if len(data) < 16 {
			return 0, nil
		}
		ethertype = binary.BigEndian.Uint16(data[14:])
		data = data[16:]
	case LinkTypeNull, LinkTypeLoop:
		if len(data) < 4 {
			return 0, nil
		}
		data = data[4:]
		return ipVersion(data)
	case LinkTypeRawBSD, LinkTypeRawOBSD, LinkTypeRaw, LinkTypeIPv4, LinkTypeIPv6:
		return ipVersion(data)
	default:
		return 0, nil
	}
	switch ethertype {
	case 0x0800:
		return 4, data
	case 0x86DD:
		return 6, data
	}
	return 0, nil
}

func ipVersion(data []byte) (int, []byte) {
	if len(data) == 0 {
		return 0, nil
	}
	switch data[0] >> 4 {
	case 4:
		return 4, data
	case 6:
		return 6, data
	}
	return 0, nil
}

// ipv4Header is a parsed IPv4 header.
type ipv4Header struct {
	src, dst netip.Addr
	id       uint16
	totLen   uint16
	ttl      uint8
	protocol uint8
	fragOff  uint16
	payload  []byte
}

func parseIPv4(b []byte) (ipv4Header, bool) {
	var h ipv4Header
	if len(b) < IPv4HeaderSize {
		return h, false
	}
	ihl := int(b[0]&0x0F) * 4
	if ihl < IPv4HeaderSize || ihl > len(b) {
		return h, false
	}
	h.totLen = binary.BigEndian.Uint16(b[2:])
	h.id = binary.BigEndian.Uint16(b[4:])
	h.fragOff = binary.BigEndian.Uint16(b[6:]) & 0x1FFF
	h.ttl = b[8]
	h.protocol = b[9]
	h.src = MapAddr(netip.AddrFrom4([4]byte(b[12:16])))
	h.dst = MapAddr(netip.AddrFrom4([4]byte(b[16:20])))
	end := int(h.totLen)
	if end < ihl || end > len(b) {
		end = len(b)
	}
	h.payload = b[ihl:end]
	return h, true
}

// ipv6Header is a parsed IPv6 header.
type ipv6Header struct {
	src, dst   netip.Addr
	payloadLen uint16
	hopLimit   uint8
	flowLabel  uint32
	nextHeader uint8
	payload    []byte
}

func parseIPv6(b []byte) (ipv6Header, bool) {
	var h ipv6Header
	if len(b) < IPv6HeaderSize {
		return h, false
	}
	h.flowLabel = binary.BigEndian.Uint32(b) & 0xFFFFF
	h.payloadLen = binary.BigEndian.Uint16(b[4:])
	h.nextHeader = b[6]
	h.hopLimit = b[7]
	h.src = netip.AddrFrom16([16]byte(b[8:24]))
	h.dst = netip.AddrFrom16([16]byte(b[24:40]))
	payload := b[IPv6HeaderSize:]
	if int(h.payloadLen) < len(payload) {
		payload = payload[:h.payloadLen]
	}
	// Skip the hop-by-hop, routing and destination options headers.
	for (h.nextHeader == 0 || h.nextHeader == 43 || h.nextHeader == 60) && len(payload) >= 8 {
		n := (int(payload[1]) + 1) * 8
		if n > len(payload) {
			break
		}
		h.nextHeader = payload[0]
		payload = payload[n:]
	}
	h.payload = payload
	return h, true
}

// icmpExtensionsMinPayload is the minimum length of the original datagram
// when ICMP extensions are present (RFC 4884).
const icmpExtensionsMinPayload = 128

// parseMPLSLabels parses the MPLS label stacks in the ICMP extension structure
// that follows the original datagram (RFC 4884, RFC 4950). payload is the ICMP
// payload after the 8-byte header and lengthBytes the original datagram length
// announced in the ICMP header.
func parseMPLSLabels(payload []byte, lengthBytes int) []MPLSLabel {
	offset := max(lengthBytes, icmpExtensionsMinPayload)
	if len(payload) <= offset {
		return nil
	}
	ext := payload[offset:]
	if len(ext) < 4 || ext[0]>>4 != 2 {
		return nil
	}
	if cksum := binary.BigEndian.Uint16(ext[2:]); cksum != 0 && ChecksumFold(ChecksumAdd(0, ext)) != 0 {
		return nil
	}
	var labels []MPLSLabel
	objects := ext[4:]
	for len(objects) >= 4 {
		length := int(binary.BigEndian.Uint16(objects))
		if length < 4 || length > len(objects) {
			break
		}
		class, ctype := objects[2], objects[3]
		if class == 1 && ctype == 1 {
			body := objects[4:length]
			for i := 0; i+4 <= len(body); i += 4 {
				v := binary.BigEndian.Uint32(body[i:])
				labels = append(labels, MPLSLabel{
					Label:         v >> 12,
					Experimental:  uint8(v>>9) & 0x7,
					BottomOfStack: uint8(v>>8) & 0x1,
					TTL:           uint8(v),
				})
			}
		}
		objects = objects[length:]
	}
	return labels
}

// Parse parses a captured packet into a reply. captureUs is the capture time
// in microseconds since the epoch. It returns false for packets that are not
// ICMP/ICMPv6 echo replies, time exceeded or destination unreachable messages.
func Parse(data []byte, lt LinkType, captureUs int64) (*Reply, bool) {
	version, l3 := networkLayer(data, lt)
	reply := &Reply{CaptureTimestamp: captureUs}
	captureTenthMs := uint64(captureUs) / 100

	switch version {
	case 4:
		ip, ok := parseIPv4(l3)
		if !ok {
			return nil, false
		}
		reply.ReplySrcAddr = ip.src
		reply.ReplyDstAddr = ip.dst
		reply.ReplyID = ip.id
		reply.ReplySize = ip.totLen
		reply.ReplyTTL = ip.ttl
		if ip.protocol != ProtoICMP || ip.fragOff != 0 || len(ip.payload) < 8 {
			return nil, false
		}
		icmp := ip.payload
		typ, code := icmp[0], icmp[1]
		switch typ {
		case 3, 11: // Destination Unreachable, Time Exceeded
			reply.ReplyProtocol = ProtoICMP
			reply.ReplyICMPType = typ
			reply.ReplyICMPCode = code
			reply.ReplyMPLSLabels = parseMPLSLabels(icmp[8:], int(icmp[5])*4)
			inner, ok := parseIPv4(icmp[8:])
			if !ok {
				// Discard the packet if it doesn't contain an inner IP packet.
				return nil, false
			}
			reply.ProbeDstAddr = inner.dst
			reply.ProbeID = inner.id
			reply.ProbeSize = inner.totLen
			reply.QuotedTTL = inner.ttl
			if inner.fragOff == 0 && len(inner.payload) >= 8 {
				switch inner.protocol {
				case ProtoICMP:
					parseInnerICMP(reply, ProtoICMP, inner.payload, captureTenthMs)
					reply.ProbeTTL = uint8(int(inner.totLen) - IPv4HeaderSize - ICMPHeaderSize - PayloadTweakBytes)
				case ProtoUDP:
					parseInnerUDP(reply, inner.payload, captureTenthMs)
				}
			}
			return reply, true
		case 0: // Echo Reply
			reply.ReplyProtocol = ProtoICMP
			reply.ReplyICMPType = typ
			reply.ReplyICMPCode = code
			parseInnerICMP(reply, ProtoICMP, icmp, captureTenthMs)
			reply.ProbeTTL = uint8(int(ip.totLen) - IPv4HeaderSize - ICMPHeaderSize - PayloadTweakBytes)
			// Echo replies do not quote the probe, so we assume that the reply
			// comes from the probe destination.
			reply.ProbeDstAddr = reply.ReplySrcAddr
			return reply, true
		}
		return nil, false

	case 6:
		ip, ok := parseIPv6(l3)
		if !ok {
			return nil, false
		}
		reply.ReplySrcAddr = ip.src
		reply.ReplyDstAddr = ip.dst
		reply.ReplySize = ip.payloadLen
		reply.ReplyTTL = ip.hopLimit
		if ip.nextHeader != ProtoICMPv6 || len(ip.payload) < 8 {
			return nil, false
		}
		icmp := ip.payload
		typ, code := icmp[0], icmp[1]
		switch typ {
		case 1, 3: // Destination Unreachable, Time Exceeded
			reply.ReplyProtocol = ProtoICMPv6
			reply.ReplyICMPType = typ
			reply.ReplyICMPCode = code
			reply.ReplyMPLSLabels = parseMPLSLabels(icmp[8:], int(icmp[4])*8)
			if inner, ok := parseIPv6(icmp[8:]); ok {
				reply.ProbeDstAddr = inner.dst
				reply.ProbeSize = inner.payloadLen
				reply.QuotedTTL = inner.hopLimit
				reply.ProbeFlowLabel = inner.flowLabel
				if len(inner.payload) >= 8 {
					switch inner.nextHeader {
					case ProtoICMPv6:
						parseInnerICMP(reply, ProtoICMPv6, inner.payload, captureTenthMs)
						reply.ProbeTTL = uint8(int(inner.payloadLen) - ICMPv6HeaderSize - PayloadTweakBytes)
					case ProtoUDP:
						parseInnerUDP(reply, inner.payload, captureTenthMs)
					}
				}
			}
			return reply, true
		case 129: // Echo Reply
			reply.ReplyProtocol = ProtoICMPv6
			reply.ReplyICMPType = typ
			reply.ReplyICMPCode = code
			parseInnerICMP(reply, ProtoICMPv6, icmp, captureTenthMs)
			reply.ProbeTTL = uint8(int(ip.payloadLen) - ICMPv6HeaderSize - PayloadTweakBytes)
			reply.ProbeDstAddr = reply.ReplySrcAddr
			return reply, true
		}
		return nil, false
	}
	return nil, false
}

func parseInnerICMP(reply *Reply, protocol uint8, icmp []byte, captureTenthMs uint64) {
	reply.ProbeProtocol = protocol
	reply.ProbeSrcPort = binary.BigEndian.Uint16(icmp[4:])
	reply.ProbeDstPort = 0
	reply.RTT = TimestampDifference(captureTenthMs, binary.BigEndian.Uint16(icmp[6:]))
}

func parseInnerUDP(reply *Reply, udp []byte, captureTenthMs uint64) {
	reply.ProbeProtocol = ProtoUDP
	reply.ProbeSrcPort = binary.BigEndian.Uint16(udp[0:])
	reply.ProbeDstPort = binary.BigEndian.Uint16(udp[2:])
	reply.ProbeTTL = uint8(int(binary.BigEndian.Uint16(udp[4:])) - UDPHeaderSize - PayloadTweakBytes)
	reply.RTT = TimestampDifference(captureTenthMs, binary.BigEndian.Uint16(udp[6:]))
}
