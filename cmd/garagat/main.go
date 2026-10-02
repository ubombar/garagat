// Command garagat reads probe specifications on stdin, sends the probes at the
// requested rate and writes the replies in CSV format on stdout. Its flags,
// input and output formats are the ones of caracal.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/pflag"
	"github.com/ubombar/garagat"
	"github.com/ubombar/garagat/link"
	"github.com/ubombar/garagat/prober"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "0.1.0"

// opener overrides the link opener in tests.
var opener link.Opener

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func parseMAC(s string) (*[6]byte, error) {
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return nil, fmt.Errorf("invalid MAC address: %s", s)
	}
	m := [6]byte(hw)
	return &m, nil
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fmt.Fprintf(stderr, "garagat v%s (release build)\n", version)

	cfg := prober.DefaultConfig()
	fs := pflag.NewFlagSet("garagat", pflag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.SortFlags = false
	help := fs.BoolP("help", "h", false, "Show this message")
	showVersion := fs.Bool("version", false, "Show the version and exit")
	rate := fs.IntP("probing-rate", "r", int(cfg.ProbingRate), "Probing rate in packets per second")
	iface := fs.StringP("interface", "z", cfg.Interface, "Interface from which to send the packets")
	batch := fs.IntP("batch-size", "B", int(cfg.BatchSize), "Number of probes to send before calling the rate limiter")
	logLevel := fs.StringP("log-level", "L", "info", "Minimum log level (trace, debug, info, warning, error, fatal)")
	nPackets := fs.IntP("n-packets", "N", int(cfg.NPackets), "Number of packets to send per probe")
	maxProbes := fs.IntP("max-probes", "P", 0, "Maximum number of probes to send (unlimited by default)")
	src4 := fs.String("source-address-v4", "", "Specify the IPv4 source address to use in the packets (if probing in v4)")
	src6 := fs.String("source-address-v6", "", "Specify the IPv6 source address to use in the packets (if probing in v6)")
	gw4 := fs.String("gateway-mac-v4", "", "MAC address of the IPv4 gateway (resolved with ARP by default)")
	gw6 := fs.String("gateway-mac-v6", "", "MAC address of the IPv6 gateway (resolved with NDP by default)")
	wait := fs.IntP("sniffer-wait-time", "W", int(cfg.SnifferWaitTime/time.Second), "Time in seconds to wait after sending the probes to stop the sniffer")
	method := fs.String("rate-limiting-method", cfg.RateLimitingMethod.String(), "Method to use to limit the packets rate (auto, active, sleep, none)")
	excl := fs.String("filter-from-prefix-file-excl", "", "Do not send probes to prefixes specified in file (deny list)")
	incl := fs.String("filter-from-prefix-file-incl", "", "Do not send probes to prefixes *not* specified in file (allow list)")
	minTTL := fs.Int("filter-min-ttl", -1, "Do not send probes with ttl < min_ttl")
	maxTTL := fs.Int("filter-max-ttl", -1, "Do not send probes with ttl > max_ttl")
	caracalID := fs.Int("caracal-id", -1, "Identifier encoded in the probes (random by default)")
	round := fs.String("meta-round", "", "Value of the round column in the CSV output")
	noCheck := fs.Bool("no-integrity-check", false, "Do not check that replies match valid probes")
	pcapOut := fs.String("output-file-pcap", "", "Write every captured packet (including invalid replies) to this pcap file")
	dryRun := fs.Bool("dry-run", false, "Build the probes but do not send them")
	// Hide the sentinel defaults of optional flags in the help.
	for _, name := range []string{"filter-min-ttl", "filter-max-ttl", "caracal-id", "max-probes"} {
		fs.Lookup(name).DefValue = "0"
	}

	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *help {
		fmt.Fprintf(stdout, "Usage: garagat [OPTION...] < probes.csv > replies.csv\n\n%s", fs.FlagUsages())
		return 0
	}
	if *showVersion {
		return 0
	}

	fail := func(err error) int {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	level, err := prober.ParseLevel(*logLevel)
	if err != nil {
		return fail(err)
	}
	cfg.Logger = prober.NewLogger(stderr, level)
	cfg.Output = stdout

	if *rate <= 0 {
		return fail(fmt.Errorf("rate must be > 0"))
	}
	cfg.ProbingRate = uint64(*rate)
	cfg.Interface = *iface
	if *batch <= 0 {
		return fail(fmt.Errorf("batch_size must be > 0"))
	}
	cfg.BatchSize = uint64(*batch)
	if *nPackets <= 0 {
		return fail(fmt.Errorf("n_packets must be > 0"))
	}
	cfg.NPackets = uint64(*nPackets)
	if fs.Changed("max-probes") {
		if *maxProbes <= 0 {
			return fail(fmt.Errorf("max_probes must be > 0"))
		}
		cfg.MaxProbes = uint64(*maxProbes)
	}
	if *src4 != "" {
		if cfg.SourceIPv4, err = netip.ParseAddr(*src4); err != nil || !cfg.SourceIPv4.Unmap().Is4() {
			return fail(fmt.Errorf("invalid IPv4 source address: %s", *src4))
		}
		cfg.SourceIPv4 = cfg.SourceIPv4.Unmap()
	}
	if *src6 != "" {
		if cfg.SourceIPv6, err = netip.ParseAddr(*src6); err != nil || !cfg.SourceIPv6.Is6() || cfg.SourceIPv6.Is4In6() {
			return fail(fmt.Errorf("invalid IPv6 source address: %s", *src6))
		}
	}
	if *gw4 != "" {
		if cfg.GatewayMACv4, err = parseMAC(*gw4); err != nil {
			return fail(err)
		}
	}
	if *gw6 != "" {
		if cfg.GatewayMACv6, err = parseMAC(*gw6); err != nil {
			return fail(err)
		}
	}
	if *wait < 0 {
		return fail(fmt.Errorf("sniffer_wait_time must be >= 0"))
	}
	cfg.SnifferWaitTime = time.Duration(*wait) * time.Second
	if cfg.RateLimitingMethod, err = garagat.ParseRateLimitingMethod(*method); err != nil {
		return fail(err)
	}
	cfg.PrefixExclFile = *excl
	cfg.PrefixInclFile = *incl
	if fs.Changed("filter-min-ttl") {
		if *minTTL < 0 {
			return fail(fmt.Errorf("min_ttl must be >= 0"))
		}
		cfg.FilterMinTTL = *minTTL
	}
	if fs.Changed("filter-max-ttl") {
		if *maxTTL < 0 {
			return fail(fmt.Errorf("max_ttl must be >= 0"))
		}
		cfg.FilterMaxTTL = *maxTTL
	}
	if fs.Changed("caracal-id") {
		if *caracalID < 0 || *caracalID > 65535 {
			return fail(fmt.Errorf("caracal_id must be between 0 and 65535"))
		}
		cfg.CaracalID = uint16(*caracalID)
	}
	cfg.MetaRound = *round
	cfg.IntegrityCheck = !*noCheck
	cfg.OutputFilePcap = *pcapOut
	cfg.DryRun = *dryRun
	cfg.Opener = opener

	// On SIGINT/SIGTERM, stop sending, wait for the last replies and flush.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg.Logger.Infof("Reading from stdin, press CTRL+D to stop...")
	if _, err := prober.ProbeReader(ctx, cfg, stdin); err != nil {
		return fail(err)
	}
	return 0
}
