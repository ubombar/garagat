package prober

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ubombar/garagat"
	"github.com/ubombar/garagat/link"
	"github.com/ubombar/garagat/pcapfile"
)

// SnifferStatistics are the sniffer counters.
type SnifferStatistics struct {
	ReceivedCount        uint64
	ReceivedInvalidCount uint64
	// ICMPDistinctInclDest is the number of distinct reply sources.
	ICMPDistinctInclDest int
	// ICMPDistinctExclDest is the number of distinct time exceeded sources.
	ICMPDistinctExclDest int
}

func (s SnifferStatistics) String() string {
	return fmt.Sprintf("packets_received=%d packets_received_invalid=%d icmp_distinct_incl_dest=%d icmp_distinct_excl_dest=%d",
		s.ReceivedCount, s.ReceivedInvalidCount, s.ICMPDistinctInclDest, s.ICMPDistinctExclDest)
}

// Sniffer captures replies and writes them in CSV format.
type Sniffer struct {
	handle         link.Handle
	out            *bufio.Writer
	pcap           *pcapfile.Writer
	pcapFile       *os.File
	round          string
	caracalID      uint16
	integrityCheck bool
	logger         *Logger

	stop    atomic.Bool
	done    chan struct{}
	started bool

	mu        sync.Mutex
	linkStats link.Stats
	closed    bool
	received  uint64
	invalid   uint64
	all       map[netip.Addr]struct{}
	path      map[netip.Addr]struct{}
	err       error
}

// NewSniffer opens the interface for capture.
func NewSniffer(cfg *Config, out io.Writer) (*Sniffer, error) {
	opener := cfg.Opener
	if opener == nil {
		opener = link.Open
	}
	// A buffer of 64M is enough to store ~1M ICMPv6 Time Exceeded replies.
	// The 100ms timeout batches deliveries and lets us check the stop flag;
	// packets are timestamped by the kernel so it does not affect the RTT.
	h, err := opener(cfg.Interface, link.Options{
		BufferSize: 64 * 1024 * 1024,
		Timeout:    100 * time.Millisecond,
		Inbound:    true,
	}, link.ReplyFilter)
	if err != nil {
		return nil, err
	}
	s := &Sniffer{
		handle:         h,
		out:            bufio.NewWriterSize(out, 1<<16),
		round:          cfg.round(),
		caracalID:      cfg.CaracalID,
		integrityCheck: cfg.IntegrityCheck,
		logger:         cfg.Logger,
		done:           make(chan struct{}),
		all:            map[netip.Addr]struct{}{},
		path:           map[netip.Addr]struct{}{},
	}
	if cfg.OutputFilePcap != "" {
		f, err := os.Create(cfg.OutputFilePcap)
		if err != nil {
			h.Close()
			return nil, err
		}
		w, err := pcapfile.NewWriter(f, uint32(h.LinkType()))
		if err != nil {
			f.Close()
			h.Close()
			return nil, err
		}
		s.pcap, s.pcapFile = w, f
	}
	cfg.Logger.Infof("sniffer_filter=%s", replyFilterString)
	return s, nil
}

const replyFilterString = "(ip and icmp and (icmp[icmptype] = icmp-echoreply or icmp[icmptype] = icmp-timxceed or icmp[icmptype] = icmp-unreach))" +
	" or (ip6 and icmp6 and (icmp6[icmp6type] = icmp6-echoreply or icmp6[icmp6type] = icmp6-timeexceeded or icmp6[icmp6type] = icmp6-destinationunreach))"

// Start writes the CSV header and starts the capture loop.
func (s *Sniffer) Start() {
	s.out.WriteString(garagat.CSVHeader + "\n")
	s.out.Flush()
	s.started = true
	go s.loop()
}

func (s *Sniffer) loop() {
	defer close(s.done)
	lt := s.handle.LinkType()
	var line []byte
	for !s.stop.Load() {
		data, ts, err := s.handle.ReadPacket()
		if errors.Is(err, link.ErrTimeout) {
			s.flush()
			continue
		}
		if err != nil {
			s.mu.Lock()
			s.err = err
			s.mu.Unlock()
			s.logger.Errorf("sniffer: %v", err)
			return
		}
		reply, ok := garagat.Parse(data, lt, ts.UnixMicro())
		s.mu.Lock()
		if ok && (!s.integrityCheck || reply.IsValid(s.caracalID)) {
			if s.logger.Enabled(LevelTrace) {
				s.logger.Tracef("%s", reply)
			}
			s.all[reply.ReplySrcAddr] = struct{}{}
			if reply.IsTimeExceeded() {
				s.path[reply.ReplySrcAddr] = struct{}{}
			}
			line = reply.AppendCSV(line[:0], s.round)
			line = append(line, '\n')
			s.out.Write(line)
		} else {
			if s.logger.Enabled(LevelTrace) {
				s.logger.Tracef("invalid_packet_hex=%s", hex.EncodeToString(data))
			}
			s.invalid++
		}
		if s.pcap != nil {
			s.pcap.WritePacket(ts, data, len(data))
		}
		s.received++
		s.mu.Unlock()
	}
}

func (s *Sniffer) flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.out.Flush()
	if s.pcap != nil {
		s.pcap.Flush()
	}
}

// Stop stops the capture loop, flushes the output and closes the link.
func (s *Sniffer) Stop() error {
	if s.started {
		s.stop.Store(true)
		<-s.done
		s.started = false
	}
	s.flush()
	if s.pcapFile != nil {
		s.pcapFile.Close()
		s.pcapFile = nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		// Read the kernel counters before closing the link.
		if st, err := s.handle.Stats(); err == nil {
			s.linkStats = st
		}
		s.handle.Close()
		s.closed = true
	}
	return s.err
}

// Statistics returns the sniffer counters.
func (s *Sniffer) Statistics() SnifferStatistics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SnifferStatistics{
		ReceivedCount:        s.received,
		ReceivedInvalidCount: s.invalid,
		ICMPDistinctInclDest: len(s.all),
		ICMPDistinctExclDest: len(s.path),
	}
}

// LinkStatistics returns the kernel capture statistics.
func (s *Sniffer) LinkStatistics() link.Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		if st, err := s.handle.Stats(); err == nil {
			s.linkStats = st
		}
	}
	return s.linkStats
}
