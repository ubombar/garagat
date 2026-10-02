package garagat

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ParseAddr parses an IPv4 address in dotted notation ("8.8.8.8"), an IPv4
// address as a decimal uint32 ("134743044"), an IPv4-mapped IPv6 address
// ("::ffff:8.8.8.8") or an IPv6 address. IPv4 addresses are returned in their
// IPv4-mapped IPv6 form, like caracal stores them.
func ParseAddr(s string) (netip.Addr, error) {
	i := strings.IndexAny(s, ".:")
	if i < 0 {
		v, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("invalid IPv4 address: %s", s)
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(v))
		return MapAddr(netip.AddrFrom4(b)), nil
	}
	if s[i] == ':' {
		a, err := netip.ParseAddr(s)
		if err != nil || !a.Is6() || a.Zone() != "" {
			return netip.Addr{}, fmt.Errorf("invalid IPv6 or IPv4-mapped address: %s", s)
		}
		return a, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return netip.Addr{}, fmt.Errorf("invalid IPv4 address: %s", s)
	}
	return MapAddr(a), nil
}

// MapAddr returns the IPv4-mapped IPv6 form of IPv4 addresses and returns IPv6
// addresses unchanged.
func MapAddr(a netip.Addr) netip.Addr {
	if a.Is4() {
		return netip.AddrFrom16(a.As16())
	}
	return a
}

// IsIPv4 reports whether a is an IPv4 or IPv4-mapped IPv6 address.
func IsIPv4(a netip.Addr) bool {
	return a.Is4() || a.Is4In6()
}

// FormatAddr formats IPv4 and IPv4-mapped addresses in dotted notation and
// IPv6 addresses in the usual compressed notation.
func FormatAddr(a netip.Addr) string {
	if !a.IsValid() {
		return "::"
	}
	return a.Unmap().String()
}

// formatAddr6 formats an address the way inet_ntop(AF_INET6) does, which is
// what caracal uses in its CSV output (IPv4 appears as ::ffff:a.b.c.d).
func formatAddr6(a netip.Addr) string {
	if !a.IsValid() {
		return "::"
	}
	return MapAddr(a).String()
}

// lastWordLE returns the last 32 bits of the address read as a little-endian
// integer. caracal reads s6_addr32[3] on little-endian hosts, so this keeps
// the probe IDs compatible with caracal.
func lastWordLE(a netip.Addr) uint32 {
	b := a.As16()
	return binary.LittleEndian.Uint32(b[12:])
}
