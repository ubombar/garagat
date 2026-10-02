//go:build linux

package link

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/ubombar/garagat"
	"golang.org/x/sys/unix"
)

// ARPHRD_* values from linux/if_arp.h.
const (
	arphrdEther    = 1
	arphrdLoopback = 772
	arphrdNone     = 65534
	arphrdIPGRE    = 778
	arphrdSIT      = 776
	arphrdTunnel   = 768
	arphrdTunnel6  = 769
	arphrdRawIP    = 519
)

type packetHandle struct {
	fd       int
	ifindex  int
	linkType garagat.LinkType
	inbound  bool
	buf      []byte
	oob      []byte
	mu       sync.Mutex
	stats    Stats
	closed   bool
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func linkTypeOf(iface *net.Interface) garagat.LinkType {
	data, err := os.ReadFile("/sys/class/net/" + iface.Name + "/type")
	if err == nil {
		if t, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			switch t {
			case arphrdEther, arphrdLoopback:
				return garagat.LinkTypeEthernet
			case arphrdNone, arphrdIPGRE, arphrdSIT, arphrdTunnel, arphrdTunnel6, arphrdRawIP:
				return garagat.LinkTypeRaw
			}
		}
	}
	if len(iface.HardwareAddr) == 6 || iface.Flags&net.FlagLoopback != 0 {
		return garagat.LinkTypeEthernet
	}
	return garagat.LinkTypeRaw
}

func open(name string, opts Options, filter FilterFunc) (Handle, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("link: %w", err)
	}
	// Create the socket with protocol 0 so that it receives nothing until
	// the filter is attached and the socket is bound.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("link: socket(AF_PACKET): %w (are you root or CAP_NET_RAW?)", err)
	}
	h := &packetHandle{fd: fd, ifindex: iface.Index, linkType: linkTypeOf(iface), inbound: opts.Inbound}
	fail := func(err error) (Handle, error) {
		unix.Close(fd)
		return nil, err
	}
	proto := htons(unix.ETH_P_ALL)
	if opts.SendOnly {
		// Attach a filter that rejects everything so the socket queue
		// stays empty.
		if err := attachFilter(fd, []unix.SockFilter{{Code: 0x06, K: 0}}); err != nil {
			return fail(err)
		}
	} else {
		if filter != nil {
			prog, err := filter(h.linkType)
			if err != nil {
				return fail(err)
			}
			insns := make([]unix.SockFilter, len(prog))
			for i, ins := range prog {
				insns[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
			}
			if err := attachFilter(fd, insns); err != nil {
				return fail(err)
			}
		}
		if opts.BufferSize > 0 {
			if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, opts.BufferSize) != nil {
				_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, opts.BufferSize)
			}
		}
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1); err != nil {
			return fail(fmt.Errorf("link: SO_TIMESTAMPNS: %w", err))
		}
		if opts.Inbound {
			// Linux >= 4.20; the packet type is also checked on receive.
			_ = unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_IGNORE_OUTGOING, 1)
		}
	}
	if opts.Timeout > 0 {
		tv := unix.NsecToTimeval(opts.Timeout.Nanoseconds())
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			return fail(fmt.Errorf("link: SO_RCVTIMEO: %w", err))
		}
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: proto, Ifindex: iface.Index}); err != nil {
		return fail(fmt.Errorf("link: bind %s: %w", name, err))
	}
	h.buf = make([]byte, snapLen)
	h.oob = make([]byte, unix.CmsgSpace(int(unsafe.Sizeof(unix.Timespec{}))))
	return h, nil
}

func attachFilter(fd int, insns []unix.SockFilter) error {
	prog := unix.SockFprog{Len: uint16(len(insns)), Filter: &insns[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		return fmt.Errorf("link: SO_ATTACH_FILTER: %w", err)
	}
	return nil
}

func (h *packetHandle) LinkType() garagat.LinkType { return h.linkType }

func (h *packetHandle) WritePacket(data []byte) error {
	for {
		_, err := unix.Write(h.fd, data)
		if err == unix.EINTR {
			continue
		}
		if err == unix.EBADF {
			return ErrClosed
		}
		if err != nil {
			return fmt.Errorf("link: send: %w", err)
		}
		return nil
	}
}

func (h *packetHandle) ReadPacket() ([]byte, time.Time, error) {
	for {
		n, oobn, flags, from, err := unix.Recvmsg(h.fd, h.buf, h.oob, 0)
		if err != nil {
			switch {
			case err == unix.EAGAIN || err == unix.EWOULDBLOCK:
				return nil, time.Time{}, ErrTimeout
			case err == unix.EINTR:
				continue
			case err == unix.EBADF:
				return nil, time.Time{}, ErrClosed
			}
			return nil, time.Time{}, fmt.Errorf("link: recv: %w", err)
		}
		if ll, ok := from.(*unix.SockaddrLinklayer); ok && h.inbound && ll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		ts := time.Now()
		if oobn > 0 {
			if msgs, err := unix.ParseSocketControlMessage(h.oob[:oobn]); err == nil {
				for _, m := range msgs {
					if m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SCM_TIMESTAMPNS && len(m.Data) >= int(unsafe.Sizeof(unix.Timespec{})) {
						tsp := (*unix.Timespec)(unsafe.Pointer(&m.Data[0]))
						ts = time.Unix(int64(tsp.Sec), int64(tsp.Nsec))
					}
				}
			}
		}
		_ = flags
		return h.buf[:n], ts, nil
	}
}

func (h *packetHandle) Stats() (Stats, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return h.stats, nil
	}
	// The kernel counters are reset on every read.
	s, err := unix.GetsockoptTpacketStats(h.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err != nil {
		return h.stats, fmt.Errorf("link: PACKET_STATISTICS: %w", err)
	}
	h.stats.Received += uint64(s.Packets)
	h.stats.Dropped += uint64(s.Drops)
	return h.stats, nil
}

func (h *packetHandle) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	err := unix.Close(h.fd)
	if errors.Is(err, unix.EBADF) {
		return nil
	}
	return err
}
