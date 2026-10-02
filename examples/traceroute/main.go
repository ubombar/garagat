// Command traceroute is a traceroute implementation on top of garagat,
// inspired by Dmitry Butskoy's traceroute for Linux. It is the port of
// caracat's traceroute example.
//
//	sudo go run ./examples/traceroute -A google.com
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/ubombar/garagat"
	"github.com/ubombar/garagat/link"
	"github.com/ubombar/garagat/neighbors"
	"github.com/ubombar/garagat/prober"
)

// lookupAS returns the origin AS of addr from Team Cymru's whois service.
func lookupAS(addr netip.Addr) string {
	conn, err := net.DialTimeout("tcp", "whois.cymru.com:43", 3*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, " -f %s\r\n", addr)
	line, _ := bufio.NewReader(conn).ReadString('\n')
	asn := strings.TrimSpace(strings.Split(line, "|")[0])
	if asn == "" || asn == "NA" {
		return ""
	}
	return "AS" + asn
}

func main() {
	fs := pflag.NewFlagSet("traceroute", pflag.ExitOnError)
	ipv4 := fs.BoolP("ipv4", "4", false, "Use IPv4")
	ipv6 := fs.BoolP("ipv6", "6", false, "Use IPv6")
	first := fs.IntP("first", "f", 1, "Start from the first_ttl hop")
	icmp := fs.BoolP("icmp", "I", false, "Use ICMP ECHO for tracerouting")
	device := fs.StringP("interface", "i", neighbors.DefaultInterface(), "Specify a network interface to operate with")
	maxHops := fs.IntP("max-hops", "m", 30, "Set the max number of hops (max TTL to be reached)")
	noResolve := fs.BoolP("numeric", "n", false, "Do not resolve IP addresses to their domain names")
	port := fs.Uint16P("port", "p", 33434, "Set the destination port to use")
	wait := fs.Float64P("wait", "w", 5, "Wait for a probe no more than N seconds")
	extensions := fs.BoolP("extensions", "e", false, "Show ICMP extensions (if present), including MPLS")
	asLookups := fs.BoolP("as-path-lookups", "A", false, "Perform AS path lookups and print results directly after the corresponding addresses")
	sport := fs.Uint16("sport", 24000, "Use source port num for outgoing packets")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: traceroute [options] host\n%s", fs.FlagUsages())
	}
	fs.Parse(os.Args[1:])
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	if err := run(fs.Arg(0), *ipv4, *ipv6, *first, *icmp, *device, *maxHops, *noResolve, *port, *wait, *extensions, *asLookups, *sport); err != nil {
		fmt.Fprintln(os.Stderr, "traceroute:", err)
		os.Exit(1)
	}
}

func run(host string, ipv4, ipv6 bool, first int, icmp bool, device string, maxHops int,
	noResolve bool, port uint16, wait float64, extensions, asLookups bool, sport uint16) error {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
		if err != nil {
			return err
		}
		for _, ip := range ips {
			if (ip.Unmap().Is4() && ipv6) || (ip.Is6() && !ip.Is4In6() && ipv4) {
				continue
			}
			addr = ip.Unmap()
			break
		}
		if !addr.IsValid() {
			return fmt.Errorf("no address found for %s", host)
		}
	}
	addr = addr.Unmap()

	protocol := garagat.UDP
	if icmp {
		protocol = garagat.ICMP
		if addr.Is6() {
			protocol = garagat.ICMPv6
		}
	}

	cfg := prober.DefaultConfig()
	cfg.Interface = device
	cfg.Logger = prober.NewLogger(os.Stderr, prober.LevelWarning)
	sender, err := prober.NewSender(&cfg)
	if err != nil {
		return err
	}
	defer sender.Close()
	receiver, err := link.Open(device, link.Options{
		BufferSize: 1 << 20,
		Timeout:    50 * time.Millisecond,
		Immediate:  true,
		Inbound:    true,
	}, link.ReplyFilter)
	if err != nil {
		return err
	}
	defer receiver.Close()

	size := (map[bool]int{true: garagat.IPv4HeaderSize, false: garagat.IPv6HeaderSize})[addr.Is4()] + protocol.HeaderSize() + garagat.PayloadTweakBytes
	fmt.Printf("traceroute to %s (%s), %d hops max, %d+ttl byte packets\n", addr, host, maxHops, size)

	for ttl := first; ttl <= maxHops; ttl++ {
		probe := garagat.Probe{DstAddr: garagat.MapAddr(addr), SrcPort: sport, DstPort: port, TTL: uint8(ttl), Protocol: protocol}
		if err := sender.Send(probe); err != nil {
			return err
		}
		reply := waitReply(receiver, cfg.CaracalID, probe, time.Duration(wait*float64(time.Second)))
		if reply == nil {
			fmt.Printf("%2d  *\n", ttl)
			continue
		}
		src := reply.ReplySrcAddr.Unmap()
		name := src.String()
		if !noResolve {
			if names, err := net.LookupAddr(src.String()); err == nil && len(names) > 0 {
				name = strings.TrimSuffix(names[0], ".")
			}
		}
		line := fmt.Sprintf("%2d  %s (%s)", ttl, name, src)
		if asLookups {
			asn := lookupAS(src)
			if asn == "" {
				asn = "*"
			}
			line += " [" + asn + "]"
		}
		if extensions && len(reply.ReplyMPLSLabels) > 0 {
			var labels []string
			for _, l := range reply.ReplyMPLSLabels {
				labels = append(labels, fmt.Sprintf("MPLS:L=%d,E=%d,S=%d,T=%d", l.Label, l.Experimental, l.BottomOfStack, l.TTL))
			}
			line += " <" + strings.Join(labels, "/") + ">"
		}
		fmt.Printf("%s  %.1fms\n", line, float64(reply.RTT)/10)
		if src == addr {
			break
		}
	}
	return nil
}

// waitReply waits for a valid reply to the probe.
func waitReply(h link.Handle, caracalID uint16, probe garagat.Probe, timeout time.Duration) *garagat.Reply {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, ts, err := h.ReadPacket()
		if errors.Is(err, link.ErrTimeout) {
			continue
		}
		if err != nil {
			return nil
		}
		reply, ok := garagat.Parse(data, h.LinkType(), ts.UnixMicro())
		if !ok || !reply.IsValid(caracalID) || reply.ProbeDstAddr != probe.DstAddr || reply.ProbeSrcPort != probe.SrcPort {
			continue
		}
		if reply.ProbeTTL != probe.TTL && !reply.IsEchoReply() {
			continue
		}
		return reply
	}
	return nil
}
