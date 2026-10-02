// Package garagat is a stateless ICMP/UDP IPv4/IPv6 Paris traceroute and ping
// engine written in pure Go. It is a port of caracal (C++) and caracat (Rust)
// and keeps their probe encoding, input format and output format.
package garagat

import "fmt"

// IP protocol numbers used by garagat.
const (
	ProtoICMP   uint8 = 1
	ProtoUDP    uint8 = 17
	ProtoIPv6   uint8 = 41
	ProtoICMPv6 uint8 = 58
)

// Sizes used when building and parsing probes.
const (
	// PayloadTweakBytes is the number of payload bytes used to correct the
	// transport checksum.
	PayloadTweakBytes = 2
	// ICMPHeaderSize is the size of the ICMP echo header.
	ICMPHeaderSize = 8
	// ICMPv6HeaderSize is the size of the ICMPv6 echo header.
	ICMPv6HeaderSize = 8
	// UDPHeaderSize is the size of the UDP header.
	UDPHeaderSize = 8
	// IPv4HeaderSize is the size of an IPv4 header without options.
	IPv4HeaderSize = 20
	// IPv6HeaderSize is the size of the IPv6 fixed header.
	IPv6HeaderSize = 40
	// EthernetHeaderSize is the size of an Ethernet II header.
	EthernetHeaderSize = 14
	// LoopbackHeaderSize is the size of the BSD loopback (DLT_NULL) header.
	LoopbackHeaderSize = 4
)

// L2 is a link-layer protocol.
type L2 int

const (
	// L2None means packets start directly with the IP header (DLT_RAW).
	L2None L2 = iota
	// L2BSDLoopback is the 4-byte BSD loopback header (DLT_NULL).
	L2BSDLoopback
	// L2Ethernet is an Ethernet II header.
	L2Ethernet
)

func (l L2) String() string {
	switch l {
	case L2None:
		return "none"
	case L2BSDLoopback:
		return "bsd-loopback"
	case L2Ethernet:
		return "ethernet"
	}
	return fmt.Sprintf("L2(%d)", int(l))
}

// HeaderSize returns the size of the link-layer header.
func (l L2) HeaderSize() int {
	switch l {
	case L2BSDLoopback:
		return LoopbackHeaderSize
	case L2Ethernet:
		return EthernetHeaderSize
	}
	return 0
}

// L3 is a network-layer protocol.
type L3 int

const (
	IPv4 L3 = iota
	IPv6
)

func (l L3) String() string {
	if l == IPv4 {
		return "ipv4"
	}
	return "ipv6"
}

// HeaderSize returns the size of the network-layer header built by garagat.
func (l L3) HeaderSize() int {
	if l == IPv4 {
		return IPv4HeaderSize
	}
	return IPv6HeaderSize
}

// L4 is a transport-layer protocol.
type L4 int

const (
	ICMP L4 = iota
	ICMPv6
	UDP
)

// ParseL4 parses "icmp", "icmp6" or "udp".
func ParseL4(s string) (L4, error) {
	switch s {
	case "icmp":
		return ICMP, nil
	case "icmp6":
		return ICMPv6, nil
	case "udp":
		return UDP, nil
	}
	return 0, fmt.Errorf("invalid protocol: %s", s)
}

func (l L4) String() string {
	switch l {
	case ICMP:
		return "icmp"
	case ICMPv6:
		return "icmp6"
	case UDP:
		return "udp"
	}
	return fmt.Sprintf("L4(%d)", int(l))
}

// Number returns the IP protocol number (e.g. 1 for ICMP).
func (l L4) Number() uint8 {
	switch l {
	case ICMP:
		return ProtoICMP
	case ICMPv6:
		return ProtoICMPv6
	}
	return ProtoUDP
}

// HeaderSize returns the size of the transport header built by garagat.
func (l L4) HeaderSize() int {
	switch l {
	case ICMP:
		return ICMPHeaderSize
	case ICMPv6:
		return ICMPv6HeaderSize
	}
	return UDPHeaderSize
}
