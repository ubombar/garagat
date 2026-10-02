package garagat

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// MPLSLabel is an MPLS label stack entry found in an ICMP extension
// (RFC 4950).
type MPLSLabel struct {
	Label         uint32 // 20 bits
	Experimental  uint8  // 3 bits
	BottomOfStack uint8  // 1 bit
	TTL           uint8
}

// Reply is a reply to a probe. Addresses are IPv6 or IPv4-mapped IPv6.
type Reply struct {
	// CaptureTimestamp is the capture time in microseconds since the epoch.
	CaptureTimestamp int64

	// ReplySrcAddr is the source address of the reply.
	ReplySrcAddr netip.Addr
	// ReplyDstAddr is the destination address of the reply (the probe source).
	ReplyDstAddr netip.Addr
	// ReplyID is the IP ID of the reply (0 for IPv6).
	ReplyID uint16
	// ReplySize is the IPv4 total length, or the IPv6 payload length.
	ReplySize uint16
	// ReplyTTL is the TTL of the reply.
	ReplyTTL uint8
	// ReplyProtocol is the protocol of the reply (ICMP or ICMPv6).
	ReplyProtocol uint8
	// ReplyICMPType is the ICMP type of the reply.
	ReplyICMPType uint8
	// ReplyICMPCode is the ICMP code of the reply.
	ReplyICMPCode uint8
	// ReplyMPLSLabels are the MPLS labels in the ICMP extensions.
	ReplyMPLSLabels []MPLSLabel

	// ProbeDstAddr is the destination of the probe, quoted in the reply.
	// For echo replies, this is the reply source.
	ProbeDstAddr netip.Addr
	// ProbeID is the IP ID of the quoted probe (0 for IPv6).
	ProbeID uint16
	// ProbeFlowLabel is the flow label of the quoted probe (IPv6 only).
	ProbeFlowLabel uint32
	// ProbeSize is the IPv4 total length, or the IPv6 payload length, of the
	// quoted probe.
	ProbeSize uint16
	// ProbeProtocol is the protocol of the probe.
	ProbeProtocol uint8
	// QuotedTTL is the TTL of the probe as seen by the replying host.
	QuotedTTL uint8

	// ProbeSrcPort is the UDP source port, or the ICMP identifier, of the probe.
	ProbeSrcPort uint16
	// ProbeDstPort is the UDP destination port of the probe (0 for ICMP).
	ProbeDstPort uint16
	// ProbeTTL is the TTL of the probe, decoded from the payload length.
	ProbeTTL uint8

	// RTT is the estimated round-trip time in tenths of milliseconds.
	RTT uint16
}

// CSVHeader is the header of the CSV output.
const CSVHeader = "capture_timestamp,probe_protocol,probe_src_addr,probe_dst_addr," +
	"probe_src_port,probe_dst_port,probe_ttl,quoted_ttl,reply_src_addr,reply_protocol," +
	"reply_icmp_type,reply_icmp_code,reply_ttl,reply_size,reply_mpls_labels,rtt,round"

// Checksum computes the probe checksum from the quoted probe fields.
func (r *Reply) Checksum(caracalID uint16) uint16 {
	return CaracalChecksum(uint32(caracalID), lastWordLE(r.ProbeDstAddr), r.ProbeSrcPort, r.ProbeTTL)
}

// IsValid reports whether the reply matches a probe sent with caracalID.
// Only IPv4 ICMP time exceeded and destination unreachable messages can be
// validated; other replies are always valid.
func (r *Reply) IsValid(caracalID uint16) bool {
	if r.ReplyProtocol == ProtoICMP && (r.ReplyICMPType == 3 || r.ReplyICMPType == 11) {
		return r.ProbeID == r.Checksum(caracalID)
	}
	return true
}

// IsDestinationUnreachable reports whether the reply is an ICMP or ICMPv6
// destination unreachable message.
func (r *Reply) IsDestinationUnreachable() bool {
	return (r.ReplyProtocol == ProtoICMP && r.ReplyICMPType == 3) ||
		(r.ReplyProtocol == ProtoICMPv6 && r.ReplyICMPType == 1)
}

// IsEchoReply reports whether the reply is an ICMP or ICMPv6 echo reply.
func (r *Reply) IsEchoReply() bool {
	return (r.ReplyProtocol == ProtoICMP && r.ReplyICMPType == 0) ||
		(r.ReplyProtocol == ProtoICMPv6 && r.ReplyICMPType == 129)
}

// IsTimeExceeded reports whether the reply is an ICMP or ICMPv6 time exceeded
// message.
func (r *Reply) IsTimeExceeded() bool {
	return (r.ReplyProtocol == ProtoICMP && r.ReplyICMPType == 11) ||
		(r.ReplyProtocol == ProtoICMPv6 && r.ReplyICMPType == 3)
}

// AppendCSV appends the reply in the CSV output format, without a newline.
func (r *Reply) AppendCSV(b []byte, round string) []byte {
	b = strconv.AppendInt(b, r.CaptureTimestamp, 10)
	b = append(b, ',')
	b = strconv.AppendUint(b, uint64(r.ProbeProtocol), 10)
	b = append(b, ',')
	b = append(b, formatAddr6(r.ReplyDstAddr)...)
	b = append(b, ',')
	b = append(b, formatAddr6(r.ProbeDstAddr)...)
	for _, v := range []uint64{uint64(r.ProbeSrcPort), uint64(r.ProbeDstPort), uint64(r.ProbeTTL), uint64(r.QuotedTTL)} {
		b = append(b, ',')
		b = strconv.AppendUint(b, v, 10)
	}
	b = append(b, ',')
	b = append(b, formatAddr6(r.ReplySrcAddr)...)
	for _, v := range []uint64{uint64(r.ReplyProtocol), uint64(r.ReplyICMPType), uint64(r.ReplyICMPCode), uint64(r.ReplyTTL), uint64(r.ReplySize)} {
		b = append(b, ',')
		b = strconv.AppendUint(b, v, 10)
	}
	b = append(b, `,"[`...)
	for i, l := range r.ReplyMPLSLabels {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, l.String()...)
	}
	b = append(b, `]",`...)
	b = strconv.AppendUint(b, uint64(r.RTT), 10)
	b = append(b, ',')
	b = append(b, round...)
	return b
}

// CSV formats the reply in the CSV output format, without a newline.
func (r *Reply) CSV(round string) string {
	return string(r.AppendCSV(nil, round))
}

func (l MPLSLabel) String() string {
	return fmt.Sprintf("(%d,%d,%d,%d)", l.Label, l.Experimental, l.BottomOfStack, l.TTL)
}

func (r *Reply) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "capture_timestamp=%d reply_src_addr=%s reply_dst_addr=%s reply_ttl=%d reply_protocol=%d reply_icmp_code=%d reply_icmp_type=%d",
		r.CaptureTimestamp, formatAddr6(r.ReplySrcAddr), formatAddr6(r.ReplyDstAddr), r.ReplyTTL, r.ReplyProtocol, r.ReplyICMPCode, r.ReplyICMPType)
	for _, l := range r.ReplyMPLSLabels {
		fmt.Fprintf(&sb, " reply_mpls_label=%s", l)
	}
	fmt.Fprintf(&sb, " probe_id=%d probe_size=%d probe_protocol=%d probe_ttl=%d probe_dst_addr=%s probe_src_port=%d probe_dst_port=%d quoted_ttl=%d rtt=%g",
		r.ProbeID, r.ProbeSize, r.ProbeProtocol, r.ProbeTTL, formatAddr6(r.ProbeDstAddr), r.ProbeSrcPort, r.ProbeDstPort, r.QuotedTTL, float64(r.RTT)/10)
	return sb.String()
}
