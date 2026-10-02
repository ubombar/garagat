//go:build darwin || freebsd

package link

import (
	"errors"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/ubombar/garagat"
	"golang.org/x/sys/unix"
)

type bpfHandle struct {
	fd       int
	linkType garagat.LinkType
	buf      []byte
	pending  []byte
	mu       sync.Mutex
	closed   bool
}

func ioctlPtr(fd int, req uint, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

func ioctlUint32(fd int, req uint, v uint32) error {
	return ioctlPtr(fd, req, unsafe.Pointer(&v))
}

func openBPFDevice() (int, error) {
	// macOS and FreeBSD have a cloning /dev/bpf; fall back to /dev/bpfN.
	if fd, err := unix.Open("/dev/bpf", unix.O_RDWR|unix.O_CLOEXEC, 0); err == nil {
		return fd, nil
	}
	var last error
	for i := 0; i < 256; i++ {
		fd, err := unix.Open(fmt.Sprintf("/dev/bpf%d", i), unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err == nil {
			return fd, nil
		}
		last = err
		if err != unix.EBUSY {
			break
		}
	}
	return -1, fmt.Errorf("link: cannot open a BPF device: %w (are you root, or in the access_bpf group?)", last)
}

// ifreq is struct ifreq, large enough on every BSD.
type ifreq struct {
	name [unix.IFNAMSIZ]byte
	pad  [32]byte
}

func open(name string, opts Options, filter FilterFunc) (Handle, error) {
	fd, err := openBPFDevice()
	if err != nil {
		return nil, err
	}
	fail := func(err error) (Handle, error) {
		unix.Close(fd)
		return nil, err
	}

	// The buffer size must be set before attaching the interface. The
	// kernel caps it (debug.bpf_maxbufsize on macOS), so retry smaller.
	size := uint32(opts.BufferSize)
	if size == 0 || opts.SendOnly {
		size = 1 << 16
	}
	for ; size >= 4096; size /= 2 {
		if ioctlUint32(fd, unix.BIOCSBLEN, size) == nil {
			break
		}
	}
	var ifr ifreq
	if len(name) >= len(ifr.name) {
		return fail(fmt.Errorf("link: interface name too long: %s", name))
	}
	copy(ifr.name[:], name)
	if err := ioctlPtr(fd, unix.BIOCSETIF, unsafe.Pointer(&ifr)); err != nil {
		return fail(fmt.Errorf("link: BIOCSETIF %s: %w", name, err))
	}
	var blen uint32
	if err := ioctlPtr(fd, unix.BIOCGBLEN, unsafe.Pointer(&blen)); err != nil {
		return fail(fmt.Errorf("link: BIOCGBLEN: %w", err))
	}
	var dlt uint32
	if err := ioctlPtr(fd, unix.BIOCGDLT, unsafe.Pointer(&dlt)); err != nil {
		return fail(fmt.Errorf("link: BIOCGDLT: %w", err))
	}
	// We write complete link-layer headers ourselves.
	if err := ioctlUint32(fd, unix.BIOCSHDRCMPLT, 1); err != nil {
		return fail(fmt.Errorf("link: BIOCSHDRCMPLT: %w", err))
	}
	h := &bpfHandle{fd: fd, linkType: garagat.LinkType(dlt), buf: make([]byte, blen)}

	var prog []unix.BpfInsn
	if opts.SendOnly {
		prog = []unix.BpfInsn{{Code: 0x06, K: 0}}
	} else if filter != nil {
		raw, err := filter(h.linkType)
		if err != nil {
			return fail(err)
		}
		for _, ins := range raw {
			prog = append(prog, unix.BpfInsn{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K})
		}
	}
	if len(prog) > 0 {
		p := unix.BpfProgram{Len: uint32(len(prog)), Insns: &prog[0]}
		if err := ioctlPtr(fd, unix.BIOCSETF, unsafe.Pointer(&p)); err != nil {
			return fail(fmt.Errorf("link: BIOCSETF: %w", err))
		}
	}
	if opts.Immediate {
		if err := ioctlUint32(fd, unix.BIOCIMMEDIATE, 1); err != nil {
			return fail(fmt.Errorf("link: BIOCIMMEDIATE: %w", err))
		}
	}
	if opts.Inbound {
		if err := setInbound(fd); err != nil {
			return fail(err)
		}
	}
	if opts.Timeout > 0 {
		tv := unix.NsecToTimeval(opts.Timeout.Nanoseconds())
		if err := ioctlPtr(fd, unix.BIOCSRTIMEOUT, unsafe.Pointer(&tv)); err != nil {
			return fail(fmt.Errorf("link: BIOCSRTIMEOUT: %w", err))
		}
	}
	return h, nil
}

func (h *bpfHandle) LinkType() garagat.LinkType { return h.linkType }

func (h *bpfHandle) WritePacket(data []byte) error {
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

func bpfWordAlign(x int) int {
	return (x + bpfAlignment - 1) &^ (bpfAlignment - 1)
}

func (h *bpfHandle) ReadPacket() ([]byte, time.Time, error) {
	for {
		if len(h.pending) > 0 {
			hdrSize := int(unsafe.Sizeof(unix.BpfHdr{}))
			if len(h.pending) < hdrSize {
				h.pending = nil
				continue
			}
			hdr := (*unix.BpfHdr)(unsafe.Pointer(&h.pending[0]))
			start := int(hdr.Hdrlen)
			end := start + int(hdr.Caplen)
			if end > len(h.pending) {
				h.pending = nil
				continue
			}
			data := h.pending[start:end]
			ts := time.Unix(int64(hdr.Tstamp.Sec), int64(hdr.Tstamp.Usec)*1000)
			next := bpfWordAlign(end)
			if next >= len(h.pending) {
				h.pending = nil
			} else {
				h.pending = h.pending[next:]
			}
			return data, ts, nil
		}
		n, err := unix.Read(h.fd, h.buf)
		if err != nil {
			switch err {
			case unix.EINTR:
				continue
			case unix.EAGAIN:
				return nil, time.Time{}, ErrTimeout
			case unix.EBADF:
				return nil, time.Time{}, ErrClosed
			}
			return nil, time.Time{}, fmt.Errorf("link: read: %w", err)
		}
		if n == 0 {
			return nil, time.Time{}, ErrTimeout
		}
		h.pending = h.buf[:n]
	}
}

func (h *bpfHandle) Stats() (Stats, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return Stats{}, ErrClosed
	}
	var s unix.BpfStat
	if err := ioctlPtr(h.fd, unix.BIOCGSTATS, unsafe.Pointer(&s)); err != nil {
		return Stats{}, fmt.Errorf("link: BIOCGSTATS: %w", err)
	}
	return Stats{Received: uint64(s.Recv), Dropped: uint64(s.Drop)}, nil
}

func (h *bpfHandle) Close() error {
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
