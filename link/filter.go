package link

import (
	"fmt"

	"github.com/ubombar/garagat"
	"golang.org/x/net/bpf"
)

// prog is a tiny BPF assembler with labels for forward jumps.
type prog struct {
	insns  []bpf.Instruction
	fixups []fixup
	labels map[string]int
}

type fixup struct {
	at     int
	jt, jf string
	jump   string
}

func newProg() *prog { return &prog{labels: map[string]int{}} }

func (p *prog) add(i bpf.Instruction) { p.insns = append(p.insns, i) }

// jeq jumps to label jt if A == val, else falls through (or to jf).
func (p *prog) jif(cond bpf.JumpTest, val uint32, jt, jf string) {
	p.fixups = append(p.fixups, fixup{at: len(p.insns), jt: jt, jf: jf})
	p.add(bpf.JumpIf{Cond: cond, Val: val})
}

func (p *prog) label(name string) { p.labels[name] = len(p.insns) }

func (p *prog) assemble() ([]bpf.RawInstruction, error) {
	for _, f := range p.fixups {
		ji := p.insns[f.at].(bpf.JumpIf)
		resolve := func(l string) (uint8, error) {
			if l == "" {
				return 0, nil
			}
			target, ok := p.labels[l]
			if !ok {
				return 0, fmt.Errorf("bpf: unknown label %s", l)
			}
			skip := target - f.at - 1
			if skip < 0 || skip > 255 {
				return 0, fmt.Errorf("bpf: invalid jump to %s", l)
			}
			return uint8(skip), nil
		}
		var err error
		if ji.SkipTrue, err = resolve(f.jt); err != nil {
			return nil, err
		}
		if ji.SkipFalse, err = resolve(f.jf); err != nil {
			return nil, err
		}
		p.insns[f.at] = ji
	}
	return bpf.Assemble(p.insns)
}

const snapLen = 262144

// ipStart emits the instructions that dispatch on the IP version and returns
// the offset of the IP header. It jumps to "ip4" or "ip6" and rejects other
// packets.
func ipStart(p *prog, lt garagat.LinkType) (uint32, error) {
	switch lt {
	case garagat.LinkTypeEthernet, garagat.LinkTypeLinuxSLL:
		off := uint32(12)
		l3 := uint32(garagat.EthernetHeaderSize)
		if lt == garagat.LinkTypeLinuxSLL {
			off, l3 = 14, 16
		}
		p.add(bpf.LoadAbsolute{Off: off, Size: 2})
		p.jif(bpf.JumpEqual, 0x0800, "ip4", "")
		p.jif(bpf.JumpEqual, 0x86DD, "ip6", "reject")
		return l3, nil
	case garagat.LinkTypeNull, garagat.LinkTypeLoop, garagat.LinkTypeRawBSD,
		garagat.LinkTypeRawOBSD, garagat.LinkTypeRaw, garagat.LinkTypeIPv4, garagat.LinkTypeIPv6:
		l3 := uint32(0)
		if lt == garagat.LinkTypeNull || lt == garagat.LinkTypeLoop {
			l3 = 4
		}
		p.add(bpf.LoadAbsolute{Off: l3, Size: 1})
		p.add(bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 4})
		p.jif(bpf.JumpEqual, 4, "ip4", "")
		p.jif(bpf.JumpEqual, 6, "ip6", "reject")
		return l3, nil
	}
	return 0, fmt.Errorf("unsupported link type %d", lt)
}

// ReplyFilter returns a kernel filter equivalent to caracal's pcap filter:
//
//	(ip and icmp and (icmp[icmptype] = icmp-echoreply or icmp[icmptype] = icmp-timxceed or icmp[icmptype] = icmp-unreach))
//	or (ip6 and icmp6 and (icmp6[icmp6type] = icmp6-echoreply or icmp6[icmp6type] = icmp6-timeexceeded or icmp6[icmp6type] = icmp6-destinationunreach))
func ReplyFilter(lt garagat.LinkType) ([]bpf.RawInstruction, error) {
	p := newProg()
	l3, err := ipStart(p, lt)
	if err != nil {
		return nil, err
	}
	// IPv4: protocol ICMP, first fragment, type 0, 3 or 11.
	p.label("ip4")
	p.add(bpf.LoadAbsolute{Off: l3 + 9, Size: 1})
	p.jif(bpf.JumpNotEqual, uint32(garagat.ProtoICMP), "reject", "")
	p.add(bpf.LoadAbsolute{Off: l3 + 6, Size: 2})
	p.jif(bpf.JumpBitsSet, 0x1FFF, "reject", "")
	p.add(bpf.LoadMemShift{Off: l3})
	p.add(bpf.LoadIndirect{Off: l3, Size: 1})
	p.jif(bpf.JumpEqual, 0, "accept", "")
	p.jif(bpf.JumpEqual, 3, "accept", "")
	p.jif(bpf.JumpEqual, 11, "accept", "reject")
	// IPv6: next header ICMPv6, type 129, 1 or 3.
	p.label("ip6")
	p.add(bpf.LoadAbsolute{Off: l3 + 6, Size: 1})
	p.jif(bpf.JumpNotEqual, uint32(garagat.ProtoICMPv6), "reject", "")
	p.add(bpf.LoadAbsolute{Off: l3 + 40, Size: 1})
	p.jif(bpf.JumpEqual, 129, "accept", "")
	p.jif(bpf.JumpEqual, 1, "accept", "")
	p.jif(bpf.JumpEqual, 3, "accept", "reject")
	p.label("accept")
	p.add(bpf.RetConstant{Val: snapLen})
	p.label("reject")
	p.add(bpf.RetConstant{Val: 0})
	return p.assemble()
}

// NeighborFilter accepts ARP replies and ICMPv6 neighbor advertisements, used
// to resolve the gateway MAC address.
func NeighborFilter(lt garagat.LinkType) ([]bpf.RawInstruction, error) {
	if lt != garagat.LinkTypeEthernet {
		return nil, fmt.Errorf("neighbor resolution needs an Ethernet link")
	}
	p := newProg()
	p.add(bpf.LoadAbsolute{Off: 12, Size: 2})
	p.jif(bpf.JumpEqual, 0x0806, "arp", "")
	p.jif(bpf.JumpEqual, 0x86DD, "ip6", "reject")
	p.label("arp")
	p.add(bpf.LoadAbsolute{Off: 20, Size: 2})
	p.jif(bpf.JumpEqual, 2, "accept", "reject")
	p.label("ip6")
	p.add(bpf.LoadAbsolute{Off: 20, Size: 1})
	p.jif(bpf.JumpNotEqual, uint32(garagat.ProtoICMPv6), "reject", "")
	p.add(bpf.LoadAbsolute{Off: 54, Size: 1})
	p.jif(bpf.JumpEqual, 136, "accept", "reject")
	p.label("accept")
	p.add(bpf.RetConstant{Val: snapLen})
	p.label("reject")
	p.add(bpf.RetConstant{Val: 0})
	return p.assemble()
}
