//go:build linux

package neighbors

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseProcRoute(t *testing.T) {
	in := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0101A8C0	0003	0	0	600	00000000	0	0	0
wlan0	00000000	FE01A8C0	0003	0	0	100	00000000	0	0	0
eth0	0001A8C0	00000000	0001	0	0	600	00FFFFFF	0	0	0
`
	r := parseProcRoute(strings.NewReader(in))
	if r.Interface != "wlan0" || r.Gateway != netip.MustParseAddr("192.168.1.254") {
		t.Errorf("got %+v", r)
	}
}

func TestParseProcIPv6Route(t *testing.T) {
	in := `00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000007ed4a8fffea0c7d4 00000400 00000001 00000000 00450003     eth0
20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
`
	r := parseProcIPv6Route(strings.NewReader(in))
	if r.Interface != "eth0" || r.Gateway != netip.MustParseAddr("fe80::7ed4:a8ff:fea0:c7d4") {
		t.Errorf("got %+v", r)
	}
}
