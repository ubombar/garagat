package garagat

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// LPM is a longest-prefix-match set of IPv4 and IPv6 prefixes. It replaces
// liblpm in caracal. IPv4 and IPv4-mapped prefixes are stored in the same
// table.
type LPM struct {
	v4, v6 *lpmNode
}

type lpmNode struct {
	child [2]*lpmNode
	set   bool
}

// NewLPM returns an empty LPM.
func NewLPM() *LPM {
	return &LPM{v4: &lpmNode{}, v6: &lpmNode{}}
}

// parsePrefix parses "a.b.c.d/n", "x::/n", "::ffff:a.b.c.d/n" or a plain
// address (a host prefix). IPv4-mapped prefixes are converted to IPv4.
func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("LPM: failed to parse %s", s)
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("LPM: failed to parse %s", s)
	}
	if p.Addr().Is4In6() {
		bits := p.Bits() - 96
		if bits < 0 {
			return netip.Prefix{}, fmt.Errorf("LPM: failed to parse %s", s)
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), bits)
	}
	return p.Masked(), nil
}

// Insert inserts a prefix such as "192.0.2.0/24" or "2001:db8::/32".
func (l *LPM) Insert(s string) error {
	p, err := parsePrefix(s)
	if err != nil {
		return err
	}
	l.InsertPrefix(p)
	return nil
}

// InsertPrefix inserts a prefix.
func (l *LPM) InsertPrefix(p netip.Prefix) {
	addr := p.Addr().Unmap()
	n := l.root(addr)
	b := addr.AsSlice()
	for i := 0; i < p.Bits(); i++ {
		bit := (b[i/8] >> (7 - i%8)) & 1
		if n.child[bit] == nil {
			n.child[bit] = &lpmNode{}
		}
		n = n.child[bit]
	}
	n.set = true
}

// InsertFile inserts one prefix per line. Lines starting with # and empty
// lines are ignored.
func (l *LPM) InsertFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%s does not exists: %w", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := l.Insert(line); err != nil {
			return err
		}
	}
	return sc.Err()
}

// Lookup parses s and reports whether it is covered by a prefix.
func (l *LPM) Lookup(s string) (bool, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return false, fmt.Errorf("LPM: failed to parse %s", s)
	}
	return l.Contains(a), nil
}

// Contains reports whether the address is covered by a prefix.
func (l *LPM) Contains(a netip.Addr) bool {
	a = a.Unmap()
	n := l.root(a)
	if n.set {
		return true
	}
	b := a.AsSlice()
	for i := 0; i < len(b)*8; i++ {
		n = n.child[(b[i/8]>>(7-i%8))&1]
		if n == nil {
			return false
		}
		if n.set {
			return true
		}
	}
	return false
}

func (l *LPM) root(a netip.Addr) *lpmNode {
	if a.Is4() {
		return l.v4
	}
	return l.v6
}
