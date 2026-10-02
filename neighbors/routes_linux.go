//go:build linux

package neighbors

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

func defaultRoutes() (v4, v6 Route, err error) {
	if f, err := os.Open("/proc/net/route"); err == nil {
		v4 = parseProcRoute(f)
		f.Close()
	}
	if f, err := os.Open("/proc/net/ipv6_route"); err == nil {
		v6 = parseProcIPv6Route(f)
		f.Close()
	}
	return v4, v6, nil
}

const rtfGateway = 0x2

// parseProcRoute parses /proc/net/route and returns the default route with
// the lowest metric.
func parseProcRoute(r io.Reader) Route {
	var best Route
	bestMetric := -1
	sc := bufio.NewScanner(r)
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, _ := strconv.ParseUint(f[3], 16, 32)
		gw, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil || flags&rtfGateway == 0 {
			continue
		}
		metric, _ := strconv.Atoi(f[6])
		if bestMetric >= 0 && metric >= bestMetric {
			continue
		}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(gw))
		best, bestMetric = Route{Interface: f[0], Gateway: netip.AddrFrom4(b)}, metric
	}
	return best
}

// parseProcIPv6Route parses /proc/net/ipv6_route and returns the default
// route with the lowest metric.
func parseProcIPv6Route(r io.Reader) Route {
	var best Route
	var bestMetric uint64
	found := false
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[0] != strings.Repeat("0", 32) || f[1] != "00" {
			continue
		}
		nh, err := hex.DecodeString(f[4])
		if err != nil || len(nh) != 16 {
			continue
		}
		gw := netip.AddrFrom16([16]byte(nh))
		if gw.IsUnspecified() || f[9] == "lo" {
			continue
		}
		metric, _ := strconv.ParseUint(f[5], 16, 32)
		if found && metric >= bestMetric {
			continue
		}
		best, bestMetric, found = Route{Interface: f[9], Gateway: gw}, metric, true
	}
	return best
}
