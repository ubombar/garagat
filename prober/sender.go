package prober

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/ubombar/garagat"
	"github.com/ubombar/garagat/link"
	"github.com/ubombar/garagat/neighbors"
)

// Sender builds and sends probes on an interface.
type Sender struct {
	handle  link.Handle
	builder garagat.ProbeBuilder
	dryRun  bool
}

func formatMAC(m [6]byte) string { return net.HardwareAddr(m[:]).String() }

// NewSender opens the interface and finds the source addresses and the
// gateway MAC addresses.
func NewSender(cfg *Config) (*Sender, error) {
	logger := cfg.Logger
	opener := cfg.Opener
	if opener == nil {
		opener = link.Open
	}
	h, err := opener(cfg.Interface, link.Options{SendOnly: true}, nil)
	if err != nil {
		return nil, err
	}
	l2, ok := h.LinkType().L2()
	if !ok {
		h.Close()
		return nil, fmt.Errorf("unsupported link type %d", h.LinkType())
	}
	s := &Sender{handle: h, dryRun: cfg.DryRun}
	s.builder.L2 = l2
	s.builder.CaracalID = cfg.CaracalID

	if l2 == garagat.L2Ethernet {
		if mac, err := neighbors.MAC(cfg.Interface); err == nil {
			s.builder.SrcMAC = mac
		}
		iface, _ := net.InterfaceByName(cfg.Interface)
		loopback := iface != nil && iface.Flags&net.FlagLoopback != 0
		v4, v6, err := neighbors.DefaultRoutes()
		if err != nil {
			logger.Warnf("cannot read the routing table: %v", err)
		}
		resolve := func(override *[6]byte, r neighbors.Route, family string) [6]byte {
			if override != nil {
				return *override
			}
			if loopback {
				return [6]byte{}
			}
			if !r.Gateway.IsValid() || (r.Interface != "" && r.Interface != cfg.Interface) {
				logger.Warnf("no %s default gateway on %s, using 00:00:00:00:00:00", family, cfg.Interface)
				return [6]byte{}
			}
			logger.Infof("Resolving the %s gateway MAC address (%s)...", family, r.Gateway)
			mac, err := neighbors.Resolve(opener, cfg.Interface, r.Gateway, time.Second, 2)
			if err != nil {
				logger.Warnf("cannot resolve the %s gateway MAC address: %v", family, err)
			}
			return mac
		}
		s.builder.DstMACv4 = resolve(cfg.GatewayMACv4, v4, "IPv4")
		s.builder.DstMACv6 = resolve(cfg.GatewayMACv6, v6, "IPv6")
	}

	s.builder.SrcIPv4 = cfg.SourceIPv4
	if !s.builder.SrcIPv4.IsValid() {
		s.builder.SrcIPv4, _ = neighbors.SourceIPv4(cfg.Interface)
	}
	if !s.builder.SrcIPv4.IsValid() {
		s.builder.SrcIPv4 = netip.IPv4Unspecified()
	}
	s.builder.SrcIPv6 = cfg.SourceIPv6
	if !s.builder.SrcIPv6.IsValid() {
		s.builder.SrcIPv6, _ = neighbors.SourceIPv6(cfg.Interface)
	}
	if !s.builder.SrcIPv6.IsValid() {
		s.builder.SrcIPv6 = netip.IPv6Unspecified()
	}
	logger.Infof("link_type=%s src_mac=%s dst_mac_v4=%s dst_mac_v6=%s", l2, formatMAC(s.builder.SrcMAC), formatMAC(s.builder.DstMACv4), formatMAC(s.builder.DstMACv6))
	logger.Infof("src_ip_v4=%s src_ip_v6=%s", garagat.FormatAddr(s.builder.SrcIPv4), s.builder.SrcIPv6)
	return s, nil
}

// Send sends a probe, encoding the current time.
func (s *Sender) Send(p garagat.Probe) error {
	pkt, err := s.builder.Build(p, garagat.EncodeTimestamp(garagat.TimestampNow()))
	if err != nil {
		return err
	}
	if s.dryRun {
		return nil
	}
	return s.handle.WritePacket(pkt)
}

// Close closes the link.
func (s *Sender) Close() error { return s.handle.Close() }
