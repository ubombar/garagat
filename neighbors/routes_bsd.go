//go:build darwin || freebsd

package neighbors

import (
	"net"
	"net/netip"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func defaultRoutes() (v4, v6 Route, err error) {
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return v4, v6, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return v4, v6, err
	}
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&unix.RTF_GATEWAY == 0 || rm.Flags&unix.RTF_UP == 0 || len(rm.Addrs) <= unix.RTAX_GATEWAY {
			continue
		}
		if r, ok := defaultRoute(rm); ok {
			if r.Gateway.Is4() && !v4.Gateway.IsValid() {
				v4 = r
			} else if r.Gateway.Is6() && !v6.Gateway.IsValid() {
				v6 = r
			}
		}
	}
	return v4, v6, nil
}

func isZeroMask(a route.Addr) bool {
	switch m := a.(type) {
	case nil:
		return true
	case *route.Inet4Addr:
		return m.IP == [4]byte{}
	case *route.Inet6Addr:
		return m.IP == [16]byte{}
	}
	return false
}

func defaultRoute(rm *route.RouteMessage) (Route, bool) {
	var mask route.Addr
	if len(rm.Addrs) > unix.RTAX_NETMASK {
		mask = rm.Addrs[unix.RTAX_NETMASK]
	}
	if !isZeroMask(mask) {
		return Route{}, false
	}
	iface, err := net.InterfaceByIndex(rm.Index)
	if err != nil {
		return Route{}, false
	}
	switch dst := rm.Addrs[unix.RTAX_DST].(type) {
	case *route.Inet4Addr:
		gw, ok := rm.Addrs[unix.RTAX_GATEWAY].(*route.Inet4Addr)
		if !ok || dst.IP != [4]byte{} {
			return Route{}, false
		}
		return Route{Interface: iface.Name, Gateway: netip.AddrFrom4(gw.IP)}, true
	case *route.Inet6Addr:
		gw, ok := rm.Addrs[unix.RTAX_GATEWAY].(*route.Inet6Addr)
		if !ok || dst.IP != [16]byte{} {
			return Route{}, false
		}
		ip := gw.IP
		// KAME embeds the scope ID in bytes 2-3 of link-local addresses.
		if ip[0] == 0xfe && ip[1]&0xc0 == 0x80 {
			ip[2], ip[3] = 0, 0
		}
		return Route{Interface: iface.Name, Gateway: netip.AddrFrom16(ip)}, true
	}
	return Route{}, false
}
