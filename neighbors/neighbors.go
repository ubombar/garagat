// Package neighbors finds the default gateways and resolves link-layer
// addresses with ARP and NDP, in pure Go.
package neighbors

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/ubombar/garagat"
	"github.com/ubombar/garagat/link"
)

// Route is a default route.
type Route struct {
	Interface string
	Gateway   netip.Addr
}

// DefaultRoutes returns the IPv4 and IPv6 default routes. A missing route is
// returned as a zero Route.
func DefaultRoutes() (v4, v6 Route, err error) {
	return defaultRoutes()
}

// DefaultInterface returns the interface of the default IPv4 route, or of
// the default IPv6 route, or the first interface that is up and not a
// loopback.
func DefaultInterface() string {
	v4, v6, _ := DefaultRoutes()
	if v4.Interface != "" {
		return v4.Interface
	}
	if v6.Interface != "" {
		return v6.Interface
	}
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		if i.Flags&net.FlagUp != 0 && i.Flags&net.FlagLoopback == 0 {
			if addrs, _ := i.Addrs(); len(addrs) > 0 {
				return i.Name
			}
		}
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 {
			return i.Name
		}
	}
	return ""
}

func addrs(name string) ([]netip.Addr, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	as, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range as {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out, nil
}

// SourceIPv4 returns the first IPv4 address of the interface.
func SourceIPv4(name string) (netip.Addr, error) {
	as, err := addrs(name)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range as {
		if a.Is4() {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%s has no IPv4 address", name)
}

// SourceIPv6 returns the first IPv6 address of the interface that is not
// link-local, loopback or multicast.
func SourceIPv6(name string) (netip.Addr, error) {
	as, err := addrs(name)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range as {
		if a.Is6() && !a.IsLinkLocalUnicast() && !a.IsLoopback() && !a.IsMulticast() {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%s has no global IPv6 address", name)
}

// LinkLocalIPv6 returns the link-local IPv6 address of the interface.
func LinkLocalIPv6(name string) (netip.Addr, error) {
	as, err := addrs(name)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range as {
		if a.Is6() && a.IsLinkLocalUnicast() {
			return a.WithZone(""), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%s has no link-local IPv6 address", name)
}

// MAC returns the hardware address of the interface.
func MAC(name string) ([6]byte, error) {
	var mac [6]byte
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return mac, err
	}
	if len(iface.HardwareAddr) != 6 {
		return mac, fmt.Errorf("%s has no Ethernet address", name)
	}
	copy(mac[:], iface.HardwareAddr)
	return mac, nil
}

// BuildARPRequest builds an Ethernet ARP request for target.
func BuildARPRequest(srcMAC [6]byte, srcIP, target netip.Addr) []byte {
	b := make([]byte, 42)
	copy(b[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(b[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(b[12:], 0x0806)
	binary.BigEndian.PutUint16(b[14:], 1)      // Ethernet
	binary.BigEndian.PutUint16(b[16:], 0x0800) // IPv4
	b[18], b[19] = 6, 4
	binary.BigEndian.PutUint16(b[20:], 1) // Request
	copy(b[22:28], srcMAC[:])
	s, t := srcIP.Unmap().As4(), target.Unmap().As4()
	copy(b[28:32], s[:])
	copy(b[38:42], t[:])
	return b
}

// ParseARPReply returns the sender MAC address if frame is an ARP reply from
// target.
func ParseARPReply(frame []byte, target netip.Addr) ([6]byte, bool) {
	var mac [6]byte
	if len(frame) < 42 || binary.BigEndian.Uint16(frame[12:]) != 0x0806 || binary.BigEndian.Uint16(frame[20:]) != 2 {
		return mac, false
	}
	if netip.AddrFrom4([4]byte(frame[28:32])) != target.Unmap() {
		return mac, false
	}
	copy(mac[:], frame[22:28])
	return mac, true
}

// solicitedNode returns the solicited-node multicast address of a.
func solicitedNode(a netip.Addr) netip.Addr {
	b := a.As16()
	return netip.AddrFrom16([16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, b[13], b[14], b[15]})
}

// BuildNeighborSolicitation builds an Ethernet ICMPv6 neighbor solicitation
// for target, sent to its solicited-node multicast address.
func BuildNeighborSolicitation(srcMAC [6]byte, srcIP, target netip.Addr) []byte {
	dst := solicitedNode(target)
	d := dst.As16()
	b := make([]byte, garagat.EthernetHeaderSize+garagat.IPv6HeaderSize+32)
	copy(b[0:6], []byte{0x33, 0x33, d[12], d[13], d[14], d[15]})
	copy(b[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(b[12:], 0x86DD)
	ip := b[garagat.EthernetHeaderSize:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], 32)
	ip[6], ip[7] = garagat.ProtoICMPv6, 255
	s := srcIP.As16()
	copy(ip[8:24], s[:])
	copy(ip[24:40], d[:])
	icmp := ip[garagat.IPv6HeaderSize:]
	icmp[0] = 135 // Neighbor Solicitation
	t := target.As16()
	copy(icmp[8:24], t[:])
	icmp[24], icmp[25] = 1, 1 // Source link-layer address option
	copy(icmp[26:32], srcMAC[:])
	sum := garagat.ChecksumAdd(0, icmp) + garagat.IPv6PseudoHeaderSum(s, d, garagat.ProtoICMPv6, uint32(len(icmp)))
	binary.BigEndian.PutUint16(icmp[2:], garagat.ChecksumFinish(sum))
	return b
}

// ParseNeighborAdvertisement returns the MAC address of target if frame is
// an ICMPv6 neighbor advertisement for target.
func ParseNeighborAdvertisement(frame []byte, target netip.Addr) ([6]byte, bool) {
	var mac [6]byte
	const off = garagat.EthernetHeaderSize + garagat.IPv6HeaderSize
	if len(frame) < off+24 || binary.BigEndian.Uint16(frame[12:]) != 0x86DD ||
		frame[garagat.EthernetHeaderSize+6] != garagat.ProtoICMPv6 || frame[off] != 136 {
		return mac, false
	}
	if netip.AddrFrom16([16]byte(frame[off+8:off+24])) != target.WithZone("") {
		return mac, false
	}
	// Prefer the target link-layer address option, else the Ethernet source.
	copy(mac[:], frame[6:12])
	opts := frame[off+24:]
	for len(opts) >= 8 {
		n := int(opts[1]) * 8
		if n == 0 || n > len(opts) {
			break
		}
		if opts[0] == 2 && n >= 8 {
			copy(mac[:], opts[2:8])
			break
		}
		opts = opts[n:]
	}
	return mac, true
}

// Resolve resolves the MAC address of target on the interface with ARP
// (IPv4) or NDP (IPv6). It needs the same privileges as probing.
func Resolve(opener link.Opener, iface string, target netip.Addr, timeout time.Duration, retries int) ([6]byte, error) {
	var zero [6]byte
	if opener == nil {
		opener = link.Open
	}
	srcMAC, err := MAC(iface)
	if err != nil {
		return zero, err
	}
	var request []byte
	var parse func([]byte) ([6]byte, bool)
	if garagat.IsIPv4(target) {
		src, err := SourceIPv4(iface)
		if err != nil {
			return zero, err
		}
		request = BuildARPRequest(srcMAC, src, target)
		parse = func(f []byte) ([6]byte, bool) { return ParseARPReply(f, target) }
	} else {
		src, err := LinkLocalIPv6(iface)
		if err != nil {
			if src, err = SourceIPv6(iface); err != nil {
				return zero, err
			}
		}
		target = target.WithZone("")
		request = BuildNeighborSolicitation(srcMAC, src, target)
		parse = func(f []byte) ([6]byte, bool) { return ParseNeighborAdvertisement(f, target) }
	}
	h, err := opener(iface, link.Options{Timeout: 100 * time.Millisecond, Immediate: true, Inbound: true, BufferSize: 1 << 20}, link.NeighborFilter)
	if err != nil {
		return zero, err
	}
	defer h.Close()
	for attempt := 0; attempt <= retries; attempt++ {
		if err := h.WritePacket(request); err != nil {
			return zero, err
		}
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			data, _, err := h.ReadPacket()
			if errors.Is(err, link.ErrTimeout) {
				continue
			}
			if err != nil {
				return zero, err
			}
			if mac, ok := parse(data); ok {
				return mac, nil
			}
		}
	}
	return zero, fmt.Errorf("no reply from %s on %s", target, iface)
}
