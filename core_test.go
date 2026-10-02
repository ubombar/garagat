package garagat

import (
	"bytes"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ubombar/garagat/pcapfile"
)

func TestCaracalChecksum(t *testing.T) {
	const id, dst, port, ttl = 2064386465, 134743044, 24000, 7
	c := CaracalChecksum(id, dst, port, ttl)
	if CaracalChecksum(id, dst-1, port, ttl+2) == c {
		t.Error("collision on dst/ttl")
	}
	if CaracalChecksum(id, dst, port+2, ttl) == c {
		t.Error("collision on port")
	}
	// The sum wraps on 32 bits like caracal.
	if CaracalChecksum(0xFFFFFFFF, 2, 0, 0) != ChecksumFinish(1) {
		t.Error("sum does not wrap on 32 bits")
	}
}

func TestIPChecksum(t *testing.T) {
	// RFC 1071 example; caracal reads words in host (little-endian) order so
	// its expected values are byte-swapped compared to these.
	data1 := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	data2 := []byte{0x01, 0x00, 0x03, 0xf2, 0xf5, 0xf4, 0xf7, 0xf6}
	if got := ChecksumFold(ChecksumAdd(0, data1)); got != 0xddf2 {
		t.Errorf("fold(data1) = %x", got)
	}
	if got := ChecksumFold(ChecksumAdd(0, data2)); got != 0xf2dd {
		t.Errorf("fold(data2) = %x", got)
	}
	// Wikipedia example.
	data3 := []byte{0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7}
	if got := IPChecksum(data3); got != 0xb861 {
		t.Errorf("IPChecksum(data3) = %x", got)
	}
	// Odd number of bytes.
	data4 := []byte{0x95, 0xea, 0xd0, 0xcc, 0x7d, 0x55, 0x04}
	if got := IPChecksum(data4); got != 0x17f3 {
		t.Errorf("IPChecksum(data4) = %x", got)
	}
}

func TestTimestamp(t *testing.T) {
	enc := EncodeTimestamp(TimestampNow())
	time.Sleep(250 * time.Millisecond)
	diff := TimestampDifference(TimestampNow(), enc)
	if diff/10 < 245 || diff/10 > 300 {
		t.Errorf("difference = %d tenth of ms", diff)
	}
	for i := uint64(0); i < 65535; i++ {
		if dec := DecodeTimestamp(131069+i, EncodeTimestamp(131069)); dec != 131069 {
			t.Fatalf("decode(%d) = %d", 131069+i, dec)
		}
	}
	if TimestampDifference(10, EncodeTimestamp(5)) != 5 {
		t.Error("small timestamps")
	}
}

func TestParseAddr(t *testing.T) {
	for in, want := range map[string]string{
		"192.168.123.254":      "192.168.123.254",
		"134743044":            "8.8.4.4",
		"8.8.4.4":              "8.8.4.4",
		"::ffff:8.8.4.4":       "8.8.4.4",
		"2001:4860:4860::8888": "2001:4860:4860::8888",
	} {
		a, err := ParseAddr(in)
		if err != nil {
			t.Fatal(err)
		}
		if FormatAddr(a) != want {
			t.Errorf("%s -> %s, want %s", in, FormatAddr(a), want)
		}
	}
	for _, in := range []string{"8.8.4.4.0", "2001:4860:4860::8888::0000", "a", "", "fe80::1%eth0", "4294967296"} {
		if _, err := ParseAddr(in); err == nil {
			t.Errorf("ParseAddr(%q) succeeded", in)
		}
	}
}

func TestParseProbe(t *testing.T) {
	cases := []struct{ in, str string }{
		{"0.0.0.0,1,2,3,udp", "dst_addr=0.0.0.0 src_port=1 dst_port=2 ttl=3 protocol=udp flow_label=0 wait_us=0"},
		{"134743044,0010,1000,050,icmp", "dst_addr=8.8.4.4 src_port=10 dst_port=1000 ttl=50 protocol=icmp flow_label=0 wait_us=0"},
		{"::ffff:8.8.4.4,10,1000,50,icmp", "dst_addr=8.8.4.4 src_port=10 dst_port=1000 ttl=50 protocol=icmp flow_label=0 wait_us=0"},
		{"2001:4860:4860::8888,10,1000,50,icmp6,1", "dst_addr=2001:4860:4860::8888 src_port=10 dst_port=1000 ttl=50 protocol=icmp6 flow_label=1 wait_us=0"},
		{"0.0.0.0,1,2,3,udp,1,42", "dst_addr=0.0.0.0 src_port=1 dst_port=2 ttl=3 protocol=udp flow_label=1 wait_us=42"},
	}
	for _, c := range cases {
		p, err := ParseProbe(c.in)
		if err != nil {
			t.Fatal(err)
		}
		if p.String() != c.str {
			t.Errorf("%s:\n got %s\nwant %s", c.in, p, c.str)
		}
		p2, err := ParseProbe(p.CSV())
		if err != nil || !p2.Equal(p) {
			t.Errorf("%s: CSV round trip failed: %v", c.in, err)
		}
	}
	p, _ := ParseProbe("2001:4860:4860::8888,10,1000,50,icmp6,1")
	if p.L3() != IPv6 || p.Protocol != ICMPv6 {
		t.Error("wrong protocols")
	}
	p, _ = ParseProbe("8.8.8.8,10,1000,50,udp")
	if p.L3() != IPv4 {
		t.Error("wrong L3")
	}
	for _, in := range []string{
		"8.8.8.8,1,2,3",            // missing fields
		"8.8.8.8,1,2,3,icmp,5,6,7", // extra fields
		"a,b,c,d",
		"8.8.8.8,131072,131072,1,icmp",
		"8.8.8.8,1,2,512,icmp",
		"8.8.8.8,1,2,3,icmp,-1",
		"8.8.8.8,1,2,3,tcp",
	} {
		if _, err := ParseProbe(in); err == nil {
			t.Errorf("ParseProbe(%q) succeeded", in)
		}
	}
}

func TestProbeChecksumMatchesCaracal(t *testing.T) {
	// caracal reads the last 32 bits of the address in host order.
	p, _ := ParseProbe("8.8.4.4,24000,0,7,icmp")
	if got, want := p.Checksum(1), CaracalChecksum(1, 0x04040808, 24000, 7); got != want {
		t.Errorf("checksum = %d, want %d", got, want)
	}
}

func TestLPM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prefixes.txt")
	os.WriteFile(path, []byte("192.168.150.0/24\n# Some comment\n::ffff:192.168.160.0/120\nabcd:abcd::/32\naaaa:bbbb:cccc::/48\n\n"), 0o644)
	l := NewLPM()
	if err := l.InsertFile(path); err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]bool{
		"192.168.150.0": true, "192.168.150.42": true, "192.168.150.255": true, "192.168.151.1": false,
		"192.168.160.1": true, "::ffff:192.168.160.1": true, "192.168.161.1": false, "::ffff:192.168.161.1": false,
		"abcd:abcd::1": true, "abcd:1234::1": false, "aaaa:bbbb:cccc::1": true, "aaaa:bbbb:dddd::1": false,
	} {
		got, err := l.Lookup(in)
		if err != nil || got != want {
			t.Errorf("Lookup(%s) = %v, %v; want %v", in, got, err, want)
		}
	}
	a, _ := ParseAddr("aaaa:bbbb:cccc::2")
	b, _ := ParseAddr("192.168.150.1")
	if !l.Contains(a) || !l.Contains(b) {
		t.Error("Contains failed")
	}
	if l.InsertFile("zzz") == nil {
		t.Error("expected missing file error")
	}
	if l.Insert("zzz") == nil {
		t.Error("expected parse error")
	}
	if _, err := l.Lookup("zzz"); err == nil {
		t.Error("expected lookup error")
	}
	all := NewLPM()
	all.Insert("0.0.0.0/0")
	if !all.Contains(netip.MustParseAddr("1.2.3.4")) || all.Contains(netip.MustParseAddr("::1")) {
		t.Error("default route")
	}
	host := NewLPM()
	host.Insert("10.0.0.1")
	if !host.Contains(netip.MustParseAddr("10.0.0.1")) || host.Contains(netip.MustParseAddr("10.0.0.2")) {
		t.Error("host prefix")
	}
}

func TestRateLimiter(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	cases := []struct {
		rate, steps, calls uint64
	}{{500, 1, 250}, {500, 10, 25}, {100_000, 100, 250}}
	for _, c := range cases {
		rl, err := NewRateLimiter(c.rate, c.steps, RateAuto)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		for range c.calls {
			rl.Wait()
		}
		elapsed := time.Since(start)
		want := time.Duration(c.calls*c.steps) * time.Second / time.Duration(c.rate)
		if elapsed < want*8/10 || elapsed > want*3 {
			t.Errorf("rate=%d steps=%d: %v, want ~%v", c.rate, c.steps, elapsed, want)
		}
		if r := rl.Statistics().AverageRate(); r < float64(c.rate)/2 || r > float64(c.rate)*2 {
			t.Errorf("average rate %g", r)
		}
	}
	if _, err := NewRateLimiter(0, 1, RateAuto); err == nil {
		t.Error("expected error for rate 0")
	}
	none, _ := NewRateLimiter(1, 1, RateNone)
	start := time.Now()
	none.Wait()
	none.Wait()
	if time.Since(start) > 100*time.Millisecond {
		t.Error("method none waited")
	}
	for _, s := range []string{"auto", "active", "sleep", "none"} {
		m, err := ParseRateLimitingMethod(s)
		if err != nil || m.String() != s {
			t.Errorf("method %s", s)
		}
	}
	if _, err := ParseRateLimitingMethod("x"); err == nil {
		t.Error("expected error")
	}
}

func TestPcapRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w, err := pcapfile.NewWriter(&buf, 1)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.UnixMicro(1613155623845580)
	w.WritePacket(ts, []byte{1, 2, 3}, 3)
	w.WritePacket(ts.Add(time.Second), []byte{4}, 60)
	w.Flush()
	r, err := pcapfile.NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.Next()
	if err != nil || !p.Timestamp.Equal(ts) || !bytes.Equal(p.Data, []byte{1, 2, 3}) || r.LinkType() != 1 {
		t.Fatalf("first packet: %+v %v", p, err)
	}
	p, err = r.Next()
	if err != nil || p.OrigLen != 60 {
		t.Fatalf("second packet: %+v %v", p, err)
	}
	if _, err = r.Next(); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
	if _, err := pcapfile.NewReader(bytes.NewReader(make([]byte, 24))); err == nil {
		t.Error("expected bad magic")
	}
}
