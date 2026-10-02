package garagat

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Probe is a traceroute probe specification.
type Probe struct {
	// DstAddr is the destination address. IPv4 addresses may be given in
	// either their 4-byte or IPv4-mapped IPv6 form.
	DstAddr netip.Addr
	// SrcPort is the UDP source port, or the ICMP checksum and identifier.
	SrcPort uint16
	// DstPort is the UDP destination port (unused for ICMP).
	DstPort uint16
	// TTL is the time-to-live (hop limit).
	TTL uint8
	// Protocol is the transport protocol.
	Protocol L4
	// FlowLabel is the IPv6 flow label (20 bits).
	FlowLabel uint32
	// WaitUs is the number of microseconds to wait after sending the probe.
	WaitUs uint32
}

// ParseProbe parses a probe from a CSV line:
//
//	dst_addr,src_port,dst_port,ttl,protocol[,flow_label[,wait_us]]
func ParseProbe(line string) (Probe, error) {
	var p Probe
	fields := strings.Split(line, ",")
	if len(fields) < 5 || len(fields) > 7 {
		return p, fmt.Errorf("invalid CSV line: %s", line)
	}
	var err error
	if p.DstAddr, err = ParseAddr(strings.TrimSpace(fields[0])); err != nil {
		return p, err
	}
	parse := func(s string, bits int) (uint64, error) {
		v, err := strconv.ParseUint(strings.TrimSpace(s), 10, bits)
		if err != nil {
			return 0, fmt.Errorf("invalid value %q: must be between 0 and %d", s, uint64(1)<<bits-1)
		}
		return v, nil
	}
	v, err := parse(fields[1], 16)
	if err != nil {
		return p, err
	}
	p.SrcPort = uint16(v)
	if v, err = parse(fields[2], 16); err != nil {
		return p, err
	}
	p.DstPort = uint16(v)
	if v, err = parse(fields[3], 8); err != nil {
		return p, err
	}
	p.TTL = uint8(v)
	if p.Protocol, err = ParseL4(strings.TrimSpace(fields[4])); err != nil {
		return p, err
	}
	if len(fields) > 5 {
		if v, err = parse(fields[5], 32); err != nil {
			return p, err
		}
		p.FlowLabel = uint32(v)
	}
	if len(fields) > 6 {
		if v, err = parse(fields[6], 32); err != nil {
			return p, err
		}
		p.WaitUs = uint32(v)
	}
	return p, nil
}

// CSV formats the probe in the input format, including the optional columns.
func (p Probe) CSV() string {
	return fmt.Sprintf("%s,%d,%d,%d,%s,%d,%d", FormatAddr(p.DstAddr), p.SrcPort,
		p.DstPort, p.TTL, p.Protocol, p.FlowLabel, p.WaitUs)
}

func (p Probe) String() string {
	return fmt.Sprintf("dst_addr=%s src_port=%d dst_port=%d ttl=%d protocol=%s flow_label=%d wait_us=%d",
		FormatAddr(p.DstAddr), p.SrcPort, p.DstPort, p.TTL, p.Protocol, p.FlowLabel, p.WaitUs)
}

// Equal compares two probes, ignoring WaitUs.
func (p Probe) Equal(o Probe) bool {
	return MapAddr(p.DstAddr) == MapAddr(o.DstAddr) && p.SrcPort == o.SrcPort &&
		p.DstPort == o.DstPort && p.TTL == o.TTL && p.Protocol == o.Protocol &&
		p.FlowLabel == o.FlowLabel
}

// L3 returns the network protocol of the probe.
func (p Probe) L3() L3 {
	if IsIPv4(p.DstAddr) {
		return IPv4
	}
	return IPv6
}

// Checksum computes the value stored in the IPv4 ID field of the probe, used
// to verify the integrity of the replies.
func (p Probe) Checksum(caracalID uint16) uint16 {
	return CaracalChecksum(uint32(caracalID), lastWordLE(p.DstAddr), p.SrcPort, p.TTL)
}
