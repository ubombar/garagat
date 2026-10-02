package prober

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ubombar/garagat"
	"github.com/ubombar/garagat/link"
)

// ProberStatistics are the probing loop counters.
type ProberStatistics struct {
	Read                  uint64
	Sent                  uint64
	Failed                uint64
	FilteredLowTTL        uint64
	FilteredHighTTL       uint64
	FilteredPrefixExcl    uint64
	FilteredPrefixNotIncl uint64
}

func (s ProberStatistics) String() string {
	return fmt.Sprintf("probes_read=%d packets_sent=%d packets_failed=%d filtered_low_ttl=%d filtered_high_ttl=%d filtered_prefix_excl=%d filtered_prefix_not_incl=%d",
		s.Read, s.Sent, s.Failed, s.FilteredLowTTL, s.FilteredHighTTL, s.FilteredPrefixExcl, s.FilteredPrefixNotIncl)
}

// Statistics are the statistics of a probing run.
type Statistics struct {
	Prober  ProberStatistics
	Sniffer SnifferStatistics
	Link    link.Stats
}

// Iterator returns the next probe, or false when there are no more probes.
type Iterator func() (garagat.Probe, bool)

// ReaderIterator iterates over the probes of a CSV stream, logging and
// skipping invalid lines.
func ReaderIterator(r io.Reader, logger *Logger) Iterator {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	return func() (garagat.Probe, bool) {
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r")
			if line == "" {
				continue
			}
			p, err := garagat.ParseProbe(line)
			if err != nil {
				logger.Warnf("line=%s error=%v", line, err)
				continue
			}
			return p, true
		}
		if err := sc.Err(); err != nil {
			logger.Errorf("reading probes: %v", err)
		}
		return garagat.Probe{}, false
	}
}

// ProbeReader probes the CSV probe specifications read from r.
func ProbeReader(ctx context.Context, cfg Config, r io.Reader) (Statistics, error) {
	if cfg.Logger == nil {
		cfg.Logger = DefaultLogger()
	}
	return Probe(ctx, cfg, ReaderIterator(r, cfg.Logger))
}

// Probe sends the probes returned by it and writes the replies to
// cfg.Output. When ctx is cancelled it stops sending, waits for the last
// replies and returns.
func Probe(ctx context.Context, cfg Config, it Iterator) (Statistics, error) {
	var stats Statistics
	if cfg.Logger == nil {
		cfg.Logger = DefaultLogger()
	}
	if cfg.Output == nil {
		cfg.Output = os.Stdout
	}
	if err := cfg.Validate(); err != nil {
		return stats, err
	}
	logger := cfg.Logger
	logger.Infof("%s", cfg)

	var excl, incl *garagat.LPM
	if cfg.PrefixExclFile != "" {
		logger.Infof("Loading excluded prefixes...")
		excl = garagat.NewLPM()
		if err := excl.InsertFile(cfg.PrefixExclFile); err != nil {
			return stats, err
		}
	}
	if cfg.PrefixInclFile != "" {
		logger.Infof("Loading included prefixes...")
		incl = garagat.NewLPM()
		if err := incl.InsertFile(cfg.PrefixInclFile); err != nil {
			return stats, err
		}
	}

	sniffer, err := NewSniffer(&cfg, cfg.Output)
	if err != nil {
		return stats, err
	}
	sniffer.Start()
	defer sniffer.Stop()

	sender, err := NewSender(&cfg)
	if err != nil {
		return stats, err
	}
	defer sender.Close()

	rl, err := garagat.NewRateLimiter(cfg.ProbingRate, cfg.BatchSize, cfg.RateLimitingMethod)
	if err != nil {
		return stats, err
	}

	var ps ProberStatistics
	var psMu sync.Mutex
	snapshot := func() ProberStatistics {
		psMu.Lock()
		defer psMu.Unlock()
		return ps
	}
	update := func(f func()) {
		psMu.Lock()
		f()
		psMu.Unlock()
	}
	logStats := func() {
		logger.Infof("%s", rl.Statistics())
		logger.Infof("%s", snapshot())
		logger.Infof("%s", sniffer.Statistics())
		logger.Infof("%s", sniffer.LinkStatistics())
	}

	stopStats := make(chan struct{})
	statsDone := make(chan struct{})
	go func() {
		defer close(statsDone)
		if cfg.StatsInterval <= 0 {
			<-stopStats
			return
		}
		t := time.NewTicker(cfg.StatsInterval)
		defer t.Stop()
		for {
			select {
			case <-stopStats:
				return
			case <-t.C:
				logStats()
			}
		}
	}()

	trace := logger.Enabled(LevelTrace)
loop:
	for ctx.Err() == nil {
		p, ok := it()
		if !ok {
			break
		}
		update(func() { ps.Read++ })

		if cfg.FilterMinTTL >= 0 && int(p.TTL) < cfg.FilterMinTTL {
			if trace {
				logger.Tracef("%s filter=ttl_too_low", p)
			}
			update(func() { ps.FilteredLowTTL++ })
			continue
		}
		if cfg.FilterMaxTTL >= 0 && int(p.TTL) > cfg.FilterMaxTTL {
			if trace {
				logger.Tracef("%s filter=ttl_too_high", p)
			}
			update(func() { ps.FilteredHighTTL++ })
			continue
		}
		// Do not send probes to excluded prefixes (deny list).
		if excl != nil && excl.Contains(p.DstAddr) {
			if trace {
				logger.Tracef("%s filter=prefix_excluded", p)
			}
			update(func() { ps.FilteredPrefixExcl++ })
			continue
		}
		// Only send probes to included prefixes (allow list).
		if incl != nil && !incl.Contains(p.DstAddr) {
			if trace {
				logger.Tracef("%s filter=prefix_not_included", p)
			}
			update(func() { ps.FilteredPrefixNotIncl++ })
			continue
		}

		for i := uint64(0); i < cfg.NPackets; i++ {
			if trace {
				logger.Tracef("%s id=%d packet=%d", p, p.Checksum(cfg.CaracalID), i+1)
			}
			if err := sender.Send(p); err != nil {
				logger.Errorf("%s error=%v", p, err)
				update(func() { ps.Failed++ })
			} else {
				update(func() { ps.Sent++ })
			}
			if p.WaitUs > 0 {
				time.Sleep(time.Duration(p.WaitUs) * time.Microsecond)
			}
			// Rate limit every `batch_size` packets sent.
			if (ps.Sent+ps.Failed)%cfg.BatchSize == 0 {
				rl.Wait()
			}
		}
		if cfg.MaxProbes > 0 && ps.Sent >= cfg.MaxProbes {
			logger.Tracef("max_probes reached, exiting...")
			break loop
		}
	}

	logger.Infof("Waiting %gs to allow the sniffer to get the last flying responses...", cfg.SnifferWaitTime.Seconds())
	time.Sleep(cfg.SnifferWaitTime)
	err = sniffer.Stop()

	close(stopStats)
	<-statsDone
	logStats()

	stats.Prober = snapshot()
	stats.Sniffer = sniffer.Statistics()
	stats.Link = sniffer.LinkStatistics()
	return stats, err
}
