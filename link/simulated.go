package link

import (
	"sync"
	"time"

	"github.com/ubombar/garagat"
	"golang.org/x/net/bpf"
)

// Responder returns the raw IP replies (no link-layer header) to a raw IP
// packet sent on a simulated link, and the delay before they arrive.
type Responder func(packet []byte) (replies [][]byte, delay time.Duration)

// Simulated is an in-memory link with no link-layer header (LinkTypeRaw).
// Packets written to it are passed to a Responder and the replies are
// delivered to every handle opened on it. It lets tools built on garagat be
// tested without privileges or network access.
type Simulated struct {
	responder Responder
	mu        sync.Mutex
	handles   []*simHandle
	sent      [][]byte
}

// NewSimulated returns a simulated link.
func NewSimulated(responder Responder) *Simulated {
	return &Simulated{responder: responder}
}

// Sent returns a copy of the packets written to the link.
func (s *Simulated) Sent() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.sent...)
}

// Open opens a handle on the simulated link. It has the Opener signature.
func (s *Simulated) Open(_ string, opts Options, filter FilterFunc) (Handle, error) {
	h := &simHandle{sim: s, timeout: opts.Timeout, ch: make(chan simPacket, 1<<16), sendOnly: opts.SendOnly}
	if filter != nil && !opts.SendOnly {
		raw, err := filter(garagat.LinkTypeRaw)
		if err != nil {
			return nil, err
		}
		insns, _ := bpf.Disassemble(raw)
		if h.vm, err = bpf.NewVM(insns); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	s.handles = append(s.handles, h)
	s.mu.Unlock()
	return h, nil
}

type simPacket struct {
	data []byte
	ts   time.Time
}

type simHandle struct {
	sim      *Simulated
	vm       *bpf.VM
	timeout  time.Duration
	ch       chan simPacket
	sendOnly bool
	mu       sync.Mutex
	stats    Stats
	closed   bool
}

func (h *simHandle) LinkType() garagat.LinkType { return garagat.LinkTypeRaw }

func (h *simHandle) WritePacket(data []byte) error {
	h.mu.Lock()
	closed := h.closed
	h.mu.Unlock()
	if closed {
		return ErrClosed
	}
	pkt := append([]byte(nil), data...)
	s := h.sim
	s.mu.Lock()
	s.sent = append(s.sent, pkt)
	handles := append([]*simHandle(nil), s.handles...)
	s.mu.Unlock()
	if s.responder == nil {
		return nil
	}
	replies, delay := s.responder(pkt)
	if len(replies) == 0 {
		return nil
	}
	deliver := func() {
		ts := time.Now()
		for _, r := range replies {
			for _, o := range handles {
				o.deliver(simPacket{data: r, ts: ts})
			}
		}
	}
	if delay > 0 {
		time.AfterFunc(delay, deliver)
	} else {
		deliver()
	}
	return nil
}

func (h *simHandle) deliver(p simPacket) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.sendOnly {
		return
	}
	if h.vm != nil {
		if n, err := h.vm.Run(p.data); err != nil || n == 0 {
			return
		}
	}
	h.stats.Received++
	select {
	case h.ch <- p:
	default:
		h.stats.Dropped++
	}
}

func (h *simHandle) ReadPacket() ([]byte, time.Time, error) {
	var timer <-chan time.Time
	if h.timeout > 0 {
		t := time.NewTimer(h.timeout)
		defer t.Stop()
		timer = t.C
	}
	select {
	case p := <-h.ch:
		return p.data, p.ts, nil
	case <-timer:
		return nil, time.Time{}, ErrTimeout
	}
}

func (h *simHandle) Stats() (Stats, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.stats, nil
}

func (h *simHandle) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	return nil
}
