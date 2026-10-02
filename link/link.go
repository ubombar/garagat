// Package link sends and captures raw link-layer packets in pure Go, without
// libpcap. It uses AF_PACKET sockets on Linux and BPF devices (/dev/bpf) on
// macOS and FreeBSD.
package link

import (
	"errors"
	"fmt"
	"time"

	"github.com/ubombar/garagat"
	"golang.org/x/net/bpf"
)

// ErrTimeout is returned by ReadPacket when no packet arrived before the read
// timeout.
var ErrTimeout = errors.New("link: read timeout")

// ErrClosed is returned when using a closed handle.
var ErrClosed = errors.New("link: handle closed")

// Stats are capture statistics, like pcap_stats.
type Stats struct {
	// Received is the number of packets received by the filter.
	Received uint64
	// Dropped is the number of packets dropped because the buffer was full.
	Dropped uint64
	// InterfaceDropped is the number of packets dropped by the interface
	// (not available on every platform).
	InterfaceDropped uint64
}

func (s Stats) String() string {
	return fmt.Sprintf("pcap_received=%d pcap_dropped=%d pcap_interface_dropped=%d", s.Received, s.Dropped, s.InterfaceDropped)
}

// Handle is an open link on a network interface.
type Handle interface {
	// LinkType returns the link-layer header type of the packets.
	LinkType() garagat.LinkType
	// WritePacket sends a packet, starting with the link-layer header.
	WritePacket(data []byte) error
	// ReadPacket returns the next captured packet and its capture time. The
	// data is only valid until the next call. It returns ErrTimeout if no
	// packet arrived before the read timeout.
	ReadPacket() (data []byte, ts time.Time, err error)
	// Stats returns the capture statistics.
	Stats() (Stats, error)
	// Close closes the handle.
	Close() error
}

// Options configure a handle.
type Options struct {
	// Filter is a classic BPF program run in the kernel. Nil accepts every
	// packet.
	Filter []bpf.RawInstruction
	// BufferSize is the kernel capture buffer size in bytes (0 for the
	// default). It may be reduced to fit the platform limits.
	BufferSize int
	// Timeout is the read timeout (0 blocks forever). It also controls how
	// packets are batched on BSD.
	Timeout time.Duration
	// Inbound only captures incoming packets.
	Inbound bool
	// Immediate delivers packets as soon as they arrive (BSD).
	Immediate bool
	// SendOnly opens a handle that is only used to send packets: it does not
	// capture anything.
	SendOnly bool
}

// FilterFunc builds a BPF filter for a link type.
type FilterFunc func(garagat.LinkType) ([]bpf.RawInstruction, error)

// Opener opens a handle on an interface. Open is the default opener; tests can
// use a simulated link instead.
type Opener func(iface string, opts Options, filter FilterFunc) (Handle, error)

// Open opens a raw handle on the interface. filter (optional) is called with
// the link type of the interface to build the kernel filter.
func Open(iface string, opts Options, filter FilterFunc) (Handle, error) {
	return open(iface, opts, filter)
}
