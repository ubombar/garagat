// Command yarrp is a partial implementation of Yarrp on top of garagat, the
// port of caracat's yarrp example. The CLI should be identical to Yarrp's,
// but not every flag is implemented. See https://github.com/cmand/yarrp.
//
//	sudo go run ./examples/yarrp -i targets.txt -r 1000 -o output.yrp
package main

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/pflag"
	"github.com/ubombar/garagat"
	"github.com/ubombar/garagat/link"
	"github.com/ubombar/garagat/neighbors"
	"github.com/ubombar/garagat/prober"
)

// poissonPMF is the probability mass function of the Poisson distribution.
func poissonPMF(k, lambda float64) float64 {
	lg, _ := math.Lgamma(k + 1)
	return math.Exp(k*math.Log(lambda) - lg - lambda)
}

// permutation iterates over [0, n) in a pseudo-random order without storing
// the permutation: it walks the cycle of a random affine map modulo the next
// power of two and skips values >= n.
type permutation struct {
	n, size, a, c, x, count uint64
}

func newPermutation(n uint64, rng *rand.Rand) *permutation {
	size := uint64(1)
	for size < n {
		size <<= 1
	}
	// x -> a*x + c mod 2^k is a full cycle when c is odd and a = 1 mod 4.
	return &permutation{n: n, size: size, a: rng.Uint64()&^3 | 1, c: rng.Uint64() | 1, x: rng.Uint64() & (size - 1)}
}

func (p *permutation) next() (uint64, bool) {
	for p.count < p.size {
		p.x = (p.a*p.x + p.c) & (p.size - 1)
		p.count++
		if p.x < p.n {
			return p.x, true
		}
	}
	return 0, false
}

func main() {
	fs := pflag.NewFlagSet("yarrp", pflag.ExitOnError)
	output := fs.StringP("output", "o", "output.yrp", "Output file")
	probeType := fs.StringP("type", "t", "icmp", "Probe type (icmp, udp, icmp6, udp6)")
	rate := fs.Uint64P("rate", "r", 10, "Scan rate in pps")
	count := fs.Uint64P("count", "c", 0, "Number of probes to issue (default: unlimited)")
	verbose := fs.BoolP("verbose", "v", false, "Verbose")
	seed := fs.Uint64P("seed", "S", 0, "Seed (default: random)")
	src4 := fs.StringP("srcaddr", "a", "", "Source address of probes (default: auto)")
	src6 := fs.String("srcaddr6", "", "Source v6 address of probes (default: auto)")
	port := fs.Uint16P("port", "p", 80, "Transport dst port")
	test := fs.BoolP("test", "T", false, "Don't send probes")
	instance := fs.Uint16P("instance", "E", 0, "Prober instance")
	input := fs.StringP("input", "i", "", "Input target file")
	minTTL := fs.Uint8P("minttl", "l", 1, "Minimum TTL")
	maxTTL := fs.Uint8P("maxttl", "m", 16, "Maximum TTL")
	poisson := fs.Float64P("poisson", "Z", 0, "Poisson TTLs (default: uniform)")
	iface := fs.StringP("interface", "I", neighbors.DefaultInterface(), "Network interface")
	dstmac := fs.StringP("dstmac", "G", "", "MAC of gateway router (default: auto)")
	for _, name := range []string{"bgp", "blocklist", "fillmode", "granularity", "neighborhood", "v6eh", "srcmac"} {
		fs.String(name, "", "Not implemented")
	}
	fs.BoolP("entire", "Q", false, "Not implemented")
	fs.BoolP("sequential", "s", false, "Not implemented")
	fs.Parse(os.Args[1:])

	for _, name := range []string{"bgp", "blocklist", "fillmode", "granularity", "neighborhood", "v6eh", "srcmac", "entire", "sequential"} {
		if fs.Changed(name) {
			fatal(fmt.Errorf("--%s is not implemented", name))
		}
	}
	if *input == "" {
		fatal(errors.New("--input is required"))
	}

	var protocol garagat.L4
	switch *probeType {
	case "icmp":
		protocol = garagat.ICMP
	case "icmp6":
		protocol = garagat.ICMPv6
	case "udp", "udp6":
		protocol = garagat.UDP
	default:
		fatal(fmt.Errorf("probe type %s is not implemented", *probeType))
	}

	level := prober.LevelInfo
	if *verbose {
		level = prober.LevelTrace
	}
	logger := prober.NewLogger(os.Stderr, level)

	s := *seed
	if !fs.Changed("seed") {
		s = rand.Uint64()
	}
	rng := rand.New(rand.NewPCG(s, s^0x9e3779b97f4a7c15))

	prefixes, err := readPrefixes(*input)
	if err != nil {
		fatal(err)
	}
	var ttls []uint8
	for t := int(*minTTL); t < int(*maxTTL); t++ {
		ttls = append(ttls, uint8(t))
	}
	if len(prefixes) == 0 || len(ttls) == 0 {
		fatal(errors.New("nothing to probe"))
	}

	cfg := prober.DefaultConfig()
	cfg.Interface = *iface
	cfg.CaracalID = *instance
	cfg.Logger = logger
	cfg.DryRun = *test
	if *src4 != "" {
		cfg.SourceIPv4 = netip.MustParseAddr(*src4)
	}
	if *src6 != "" {
		cfg.SourceIPv6 = netip.MustParseAddr(*src6)
	}
	if *dstmac != "" {
		mac, err := parseMAC(*dstmac)
		if err != nil {
			fatal(err)
		}
		cfg.GatewayMACv4, cfg.GatewayMACv6 = &mac, &mac
	}
	sender, err := prober.NewSender(&cfg)
	if err != nil {
		fatal(err)
	}
	defer sender.Close()
	receiver, err := link.Open(*iface, link.Options{BufferSize: 64 << 20, Timeout: 100 * time.Millisecond, Inbound: true}, link.ReplyFilter)
	if err != nil {
		fatal(err)
	}
	f, err := os.Create(*output)
	if err != nil {
		fatal(err)
	}
	out := bufio.NewWriter(f)

	var stopped atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stopped.Load() {
			data, ts, err := receiver.ReadPacket()
			if errors.Is(err, link.ErrTimeout) {
				continue
			}
			if err != nil {
				logger.Errorf("%v", err)
				return
			}
			r, ok := garagat.Parse(data, receiver.LinkType(), ts.UnixMicro())
			if !ok || !r.IsValid(cfg.CaracalID) {
				continue
			}
			// trgt, sec, usec, type, code, ttl, hop, rtt, ipid, psize, rsize, rttl, rtos, mpls, count
			fmt.Fprintf(out, "%s %d %d %d %d %d %s %d %d %d %d %d %d %d %d\n",
				r.ProbeDstAddr.Unmap(), r.CaptureTimestamp/1_000_000, r.CaptureTimestamp%1_000_000,
				r.ReplyICMPType, r.ReplyICMPCode, r.ProbeTTL, r.ReplySrcAddr.Unmap(), uint64(r.RTT)*100,
				r.ProbeID, r.ProbeSize, r.ReplySize, r.ReplyTTL, 0, 0, 0)
		}
	}()

	rl, err := garagat.NewRateLimiter(*rate, 1, garagat.RateAuto)
	if err != nil {
		fatal(err)
	}
	perm := newPermutation(uint64(len(prefixes)*len(ttls)), rng)
	var sent uint64
	for {
		i, ok := perm.next()
		if !ok || (*count > 0 && sent >= *count) {
			break
		}
		prefix := prefixes[i%uint64(len(prefixes))]
		ttl := ttls[(i/uint64(len(prefixes)))%uint64(len(ttls))]
		if *poisson > 0 && rng.Float64() > poissonPMF(float64(ttl), *poisson) {
			continue
		}
		probe := garagat.Probe{DstAddr: garagat.MapAddr(prefix.Addr()), SrcPort: 24000, DstPort: *port, TTL: ttl, Protocol: protocol}
		if err := sender.Send(probe); err != nil {
			logger.Errorf("%s error=%v", probe, err)
		}
		sent++
		rl.Wait()
	}

	logger.Infof("Waiting for replies...")
	time.Sleep(time.Second)
	stopped.Store(true)
	wg.Wait()
	receiver.Close()
	out.Flush()
	f.Close()
}

func readPrefixes(path string) ([]netip.Prefix, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var prefixes []netip.Prefix
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "/") {
			if a, err := netip.ParseAddr(line); err == nil {
				prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
			}
			continue
		}
		if p, err := netip.ParsePrefix(line); err == nil {
			prefixes = append(prefixes, p.Masked())
		}
	}
	return prefixes, sc.Err()
}

func parseMAC(s string) ([6]byte, error) {
	var m [6]byte
	_, err := fmt.Sscanf(s, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5])
	return m, err
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "yarrp:", err)
	os.Exit(1)
}
