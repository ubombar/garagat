// Package prober reads probe specifications, sends the probes at a given rate
// and writes the replies in CSV format. It is the equivalent of caracal's
// Prober namespace.
package prober

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/ubombar/garagat"
	"github.com/ubombar/garagat/link"
	"github.com/ubombar/garagat/neighbors"
)

// Config configures the prober.
type Config struct {
	// CaracalID is encoded in the probes to validate the replies.
	CaracalID uint16
	// NPackets is the number of packets sent per probe.
	NPackets uint64
	// BatchSize is the number of packets sent between rate limiter calls.
	BatchSize uint64
	// ProbingRate is the probing rate in packets per second.
	ProbingRate uint64
	// SnifferWaitTime is the time to wait for replies after the last probe.
	SnifferWaitTime time.Duration
	// IntegrityCheck drops replies that do not match a probe.
	IntegrityCheck bool
	// Interface is the network interface used to send and capture.
	Interface string
	// RateLimitingMethod is the rate limiter method.
	RateLimitingMethod garagat.RateLimitingMethod
	// SourceIPv4 and SourceIPv6 override the source addresses.
	SourceIPv4, SourceIPv6 netip.Addr
	// GatewayMACv4 and GatewayMACv6 override the destination MAC addresses
	// on Ethernet links (nil to resolve them with ARP/NDP).
	GatewayMACv4, GatewayMACv6 *[6]byte
	// MaxProbes stops after this number of packets sent (0 for unlimited).
	MaxProbes uint64
	// PrefixExclFile is a file of prefixes not to probe (deny list).
	PrefixExclFile string
	// PrefixInclFile is a file of the only prefixes to probe (allow list).
	PrefixInclFile string
	// FilterMinTTL and FilterMaxTTL skip probes outside the TTL range
	// (negative to disable).
	FilterMinTTL, FilterMaxTTL int
	// MetaRound is the value of the round column ("1" if empty).
	MetaRound string
	// OutputFilePcap writes every captured packet, including invalid ones.
	OutputFilePcap string
	// StatsInterval is the interval between statistics logs (0 disables).
	StatsInterval time.Duration
	// DryRun builds the probes but does not send them.
	DryRun bool

	// Output receives the CSV replies (stdout if nil).
	Output io.Writer
	// Logger receives the logs (stderr at info level if nil).
	Logger *Logger
	// Opener opens the link (link.Open if nil).
	Opener link.Opener
}

// RandomID returns a random caracal ID.
func RandomID() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.LittleEndian.Uint16(b[:])
}

// DefaultConfig returns the default configuration of caracal.
func DefaultConfig() Config {
	return Config{
		CaracalID:          RandomID(),
		NPackets:           1,
		BatchSize:          128,
		ProbingRate:        100,
		SnifferWaitTime:    time.Second,
		IntegrityCheck:     true,
		Interface:          neighbors.DefaultInterface(),
		RateLimitingMethod: garagat.RateAuto,
		FilterMinTTL:       -1,
		FilterMaxTTL:       -1,
		StatsInterval:      5 * time.Second,
	}
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	switch {
	case c.NPackets == 0:
		return fmt.Errorf("n_packets must be > 0")
	case c.BatchSize == 0:
		return fmt.Errorf("batch_size must be > 0")
	case c.ProbingRate == 0:
		return fmt.Errorf("rate must be > 0")
	case c.SnifferWaitTime < 0:
		return fmt.Errorf("sniffer_wait_time must be >= 0")
	case c.Interface == "":
		return fmt.Errorf("no interface given and no default interface found")
	case c.FilterMinTTL > 255 || c.FilterMaxTTL > 255:
		return fmt.Errorf("ttl filters must be <= 255")
	case c.SourceIPv4.IsValid() && !garagat.IsIPv4(c.SourceIPv4):
		return fmt.Errorf("%s is not an IPv4 address", c.SourceIPv4)
	case c.SourceIPv6.IsValid() && garagat.IsIPv4(c.SourceIPv6):
		return fmt.Errorf("%s is not an IPv6 address", c.SourceIPv6)
	}
	for _, p := range []string{c.PrefixExclFile, c.PrefixInclFile} {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("%s does not exists", p)
		}
	}
	return nil
}

func (c *Config) round() string {
	if c.MetaRound == "" {
		return "1"
	}
	return c.MetaRound
}

func (c Config) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "caracal_id=%d n_packets=%d probing_rate=%d batch_size=%d sniffer_wait_time=%g integrity_check=%t interface=%s rate_limiting_method=%s",
		c.CaracalID, c.NPackets, c.ProbingRate, c.BatchSize, c.SnifferWaitTime.Seconds(), c.IntegrityCheck, c.Interface, c.RateLimitingMethod)
	if c.SourceIPv4.IsValid() {
		fmt.Fprintf(&sb, " source_ipv4=%s", garagat.FormatAddr(c.SourceIPv4))
	}
	if c.SourceIPv6.IsValid() {
		fmt.Fprintf(&sb, " source_ipv6=%s", c.SourceIPv6)
	}
	if c.MaxProbes > 0 {
		fmt.Fprintf(&sb, " max_probes=%d", c.MaxProbes)
	}
	if c.PrefixExclFile != "" {
		fmt.Fprintf(&sb, " prefix_excl_file=%s", c.PrefixExclFile)
	}
	if c.PrefixInclFile != "" {
		fmt.Fprintf(&sb, " prefix_incl_file=%s", c.PrefixInclFile)
	}
	if c.FilterMinTTL >= 0 {
		fmt.Fprintf(&sb, " min_ttl=%d", c.FilterMinTTL)
	}
	if c.FilterMaxTTL >= 0 {
		fmt.Fprintf(&sb, " max_ttl=%d", c.FilterMaxTTL)
	}
	if c.MetaRound != "" {
		fmt.Fprintf(&sb, " round=%s", c.MetaRound)
	}
	if c.OutputFilePcap != "" {
		fmt.Fprintf(&sb, " output_file_pcap=%s", c.OutputFilePcap)
	}
	if c.DryRun {
		sb.WriteString(" dry_run=true")
	}
	return sb.String()
}
