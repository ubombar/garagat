//go:build integration

package link_test

import (
	"errors"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/ubombar/garagat"
	. "github.com/ubombar/garagat/link"
	"github.com/ubombar/garagat/neighbors"
)

// TestIntegrationCapture captures the replies to the system ping with every
// combination of handle options.
func TestIntegrationCapture(t *testing.T) {
	v4, _, err := neighbors.DefaultRoutes()
	if err != nil || !v4.Gateway.IsValid() {
		t.Skip("no IPv4 default gateway")
	}
	if out, err := exec.Command("ping", "-c", "2", v4.Gateway.String()).CombinedOutput(); err != nil {
		t.Skipf("the gateway does not answer ping: %v\n%s", err, out)
	}
	for _, c := range []struct {
		name string
		opts Options
		f    FilterFunc
	}{
		{"plain", Options{Timeout: 100 * time.Millisecond}, nil},
		{"immediate", Options{Timeout: 100 * time.Millisecond, Immediate: true}, nil},
		{"inbound", Options{Timeout: 100 * time.Millisecond, Inbound: true}, nil},
		{"filter", Options{Timeout: 100 * time.Millisecond}, ReplyFilter},
		{"buffer", Options{Timeout: 100 * time.Millisecond, BufferSize: 64 << 20}, nil},
		{"sniffer", Options{Timeout: 100 * time.Millisecond, BufferSize: 64 << 20, Inbound: true}, ReplyFilter},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, err := Open(v4.Interface, c.opts, c.f)
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			go exec.Command("ping", "-c", "3", "-i", "0.2", v4.Gateway.String()).Run()
			deadline := time.Now().Add(2 * time.Second)
			replies, packets, timeouts := 0, 0, 0
			for time.Now().Before(deadline) {
				data, ts, err := h.ReadPacket()
				if errors.Is(err, ErrTimeout) {
					timeouts++
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				packets++
				if time.Since(ts) > time.Minute || time.Until(ts) > time.Minute {
					t.Errorf("bad timestamp %v", ts)
				}
				if r, ok := garagat.Parse(data, h.LinkType(), ts.UnixMicro()); ok && r.IsEchoReply() {
					replies++
				}
			}
			st, _ := h.Stats()
			t.Logf("link_type=%d packets=%d echo_replies=%d timeouts=%d %s", h.LinkType(), packets, replies, timeouts, st)
			if replies == 0 {
				t.Error("no echo reply captured")
			}
		})
	}
}

// TestIntegrationLoopbackCapture captures the system ping to 127.0.0.1 on
// the loopback interface.
func TestIntegrationLoopbackCapture(t *testing.T) {
	name := "lo"
	if runtime.GOOS != "linux" {
		name = "lo0"
	}
	h, err := Open(name, Options{Timeout: 100 * time.Millisecond, BufferSize: 1 << 20}, ReplyFilter)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	go exec.Command("ping", "-c", "3", "-i", "0.2", "127.0.0.1").Run()
	deadline := time.Now().Add(2 * time.Second)
	replies := 0
	for time.Now().Before(deadline) {
		data, ts, err := h.ReadPacket()
		if errors.Is(err, ErrTimeout) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		r, ok := garagat.Parse(data, h.LinkType(), ts.UnixMicro())
		t.Logf("%d bytes ok=%v %x", len(data), ok, data[:min(len(data), 48)])
		if ok && r.IsEchoReply() {
			replies++
		}
	}
	if replies == 0 {
		t.Error("no echo reply captured")
	}
}
