package neighbors

import (
	"encoding/binary"
	"net/netip"
	"os"
	"runtime"
	"testing"

	"github.com/ubombar/garagat"
	"github.com/ubombar/garagat/pcapfile"
)

func TestARP(t *testing.T) {
	src := [6]byte{0xb0, 0x7b, 0x25, 0xb7, 0xab, 0xd8}
	srcIP := netip.MustParseAddr("192.168.1.5")
	target := netip.MustParseAddr("192.168.1.1")
	req := BuildARPRequest(src, srcIP, target)
	if len(req) != 42 || binary.BigEndian.Uint16(req[12:]) != 0x0806 || binary.BigEndian.Uint16(req[20:]) != 1 {
		t.Fatalf("bad request %x", req)
	}
	// Turn the request into a reply from the target.
	reply := append([]byte(nil), req...)
	gw := [6]byte{1, 2, 3, 4, 5, 6}
	copy(reply[0:6], src[:])
	copy(reply[6:12], gw[:])
	binary.BigEndian.PutUint16(reply[20:], 2)
	copy(reply[22:28], gw[:])
	copy(reply[28:32], req[38:42])
	copy(reply[32:38], src[:])
	copy(reply[38:42], req[28:32])
	mac, ok := ParseARPReply(reply, target)
	if !ok || mac != gw {
		t.Fatalf("ParseARPReply = %x %v", mac, ok)
	}
	if _, ok := ParseARPReply(reply, srcIP); ok {
		t.Error("reply from the wrong address accepted")
	}
	if _, ok := ParseARPReply(req, target); ok {
		t.Error("request accepted as a reply")
	}
}

func TestARPFixture(t *testing.T) {
	f, err := os.Open("../testdata/arp.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := pcapfile.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	replies := 0
	for {
		p, err := r.Next()
		if err != nil {
			break
		}
		if len(p.Data) >= 42 && binary.BigEndian.Uint16(p.Data[20:]) == 2 {
			sender := netip.AddrFrom4([4]byte(p.Data[28:32]))
			mac, ok := ParseARPReply(p.Data, sender)
			if !ok || [6]byte(p.Data[22:28]) != mac {
				t.Errorf("fixture reply not parsed")
			}
			replies++
		}
	}
	if replies == 0 {
		t.Skip("no ARP reply in the fixture")
	}
}

func TestNDP(t *testing.T) {
	src := [6]byte{0xf4, 0x30, 0xb9, 0x58, 0xc6, 0x44}
	srcIP := netip.MustParseAddr("fe80::1")
	target := netip.MustParseAddr("fe80::7ed4:a8ff:fea0:c7d4")
	ns := BuildNeighborSolicitation(src, srcIP, target)
	ip := ns[garagat.EthernetHeaderSize:]
	if [6]byte(ns[0:6]) != [6]byte{0x33, 0x33, 0xff, 0xa0, 0xc7, 0xd4} {
		t.Errorf("bad multicast MAC %x", ns[0:6])
	}
	if netip.AddrFrom16([16]byte(ip[24:40])) != netip.MustParseAddr("ff02::1:ffa0:c7d4") {
		t.Errorf("bad solicited-node address")
	}
	icmp := ip[garagat.IPv6HeaderSize:]
	sum := garagat.ChecksumAdd(0, icmp) + garagat.IPv6PseudoHeaderSum([16]byte(ip[8:24]), [16]byte(ip[24:40]), garagat.ProtoICMPv6, uint32(len(icmp)))
	if garagat.ChecksumFold(sum) != 0 {
		t.Error("invalid ICMPv6 checksum")
	}

	// Neighbor advertisement with a target link-layer address option.
	gw := [6]byte{0x7c, 0xd4, 0xa8, 0xa0, 0xc7, 0xd4}
	na := make([]byte, garagat.EthernetHeaderSize+garagat.IPv6HeaderSize+32)
	copy(na[6:12], []byte{9, 9, 9, 9, 9, 9})
	binary.BigEndian.PutUint16(na[12:], 0x86DD)
	na[garagat.EthernetHeaderSize] = 0x60
	na[garagat.EthernetHeaderSize+6] = garagat.ProtoICMPv6
	body := na[garagat.EthernetHeaderSize+garagat.IPv6HeaderSize:]
	body[0] = 136
	tb := target.As16()
	copy(body[8:24], tb[:])
	body[24], body[25] = 2, 1
	copy(body[26:32], gw[:])
	mac, ok := ParseNeighborAdvertisement(na, target)
	if !ok || mac != gw {
		t.Fatalf("ParseNeighborAdvertisement = %x %v", mac, ok)
	}
	if _, ok := ParseNeighborAdvertisement(na, srcIP); ok {
		t.Error("advertisement for the wrong target accepted")
	}
	// Without the option, the Ethernet source is used.
	body[24] = 0
	if mac, _ := ParseNeighborAdvertisement(na[:len(na)-8], target); mac != [6]byte{9, 9, 9, 9, 9, 9} {
		t.Errorf("fallback MAC %x", mac)
	}
}

func TestLocalInterface(t *testing.T) {
	iface := DefaultInterface()
	if iface == "" {
		t.Skip("no interface")
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "freebsd" {
		if _, _, err := DefaultRoutes(); err != nil {
			t.Errorf("DefaultRoutes: %v", err)
		}
	}
	if _, err := SourceIPv4("does-not-exist0"); err == nil {
		t.Error("expected error")
	}
	if _, err := MAC("does-not-exist0"); err == nil {
		t.Error("expected error")
	}
}

func TestSolicitedNode(t *testing.T) {
	if got := solicitedNode(netip.MustParseAddr("2001:db8::1:2:3")); got != netip.MustParseAddr("ff02::1:ff02:3") {
		t.Errorf("solicitedNode = %s", got)
	}
}
