// compare reads the pcaps captured while caracal and garagat ran, and
// compares the probes they sent byte for byte. Fields that depend on the
// send time (ICMP sequence / UDP checksum and the two payload tweak bytes)
// are reported separately.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/ubombar/garagat/pcapfile"
)

type probe struct {
	raw  []byte // from the IP header
	norm []byte
}

func probes(path, mac string) []probe {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	r, err := pcapfile.NewReader(f)
	if err != nil {
		panic(err)
	}
	var out []probe
	for {
		p, err := r.Next()
		if err == io.EOF {
			return out
		}
		d := p.Data
		if len(d) < 34 || binary.BigEndian.Uint16(d[12:]) != 0x0800 || fmt.Sprintf("%x", d[6:12]) != mac {
			continue
		}
		ip := d[14:]
		l4 := ip[20:]
		isProbe := (ip[9] == 1 && l4[0] == 8) || ip[9] == 17
		if !isProbe {
			continue
		}
		raw := append([]byte(nil), ip[:binary.BigEndian.Uint16(ip[2:])]...)
		norm := append([]byte(nil), raw...)
		n4 := norm[20:]
		if norm[9] == 1 {
			n4[6], n4[7] = 0, 0 // sequence = timestamp
		} else {
			n4[6], n4[7] = 0, 0 // checksum = timestamp
		}
		n4[8], n4[9] = 0, 0 // payload tweak bytes
		out = append(out, probe{raw, norm})
	}
}

func main() {
	a := probes(os.Args[1], os.Args[2])
	b := probes(os.Args[3], os.Args[4])
	fmt.Printf("caracal sent %d probes, garagat sent %d probes\n", len(a), len(b))
	n := min(len(a), len(b))
	diff := 0
	for i := 0; i < n; i++ {
		if !bytes.Equal(a[i].norm, b[i].norm) {
			diff++
			fmt.Printf("probe %d differs:\n caracal %x\n garagat %x\n", i, a[i].raw, b[i].raw)
		}
	}
	fmt.Printf("%d/%d probes identical outside the timestamp fields\n", n-diff, n)
	if diff > 0 || len(a) != len(b) {
		os.Exit(1)
	}
}
