package garagat

import "encoding/binary"

// For the IP checksum computation, see RFC 1071 and
// https://tools.ietf.org/html/draft-heikkila-ip-checksum-00.
//
// All functions here work on big-endian (network order) 16-bit words, so the
// returned checksums can be written with binary.BigEndian.PutUint16.

// CaracalChecksum computes the value garagat (and caracal) stores in the IPv4
// ID field of a probe, to check that a reply matches a probe it sent.
// dstAddr is the last 32 bits of the destination address read as a
// little-endian integer, see Probe.Checksum.
func CaracalChecksum(caracalID uint32, dstAddr uint32, srcPort uint16, ttl uint8) uint16 {
	// The sum wraps on 32 bits, as in caracal.
	return ChecksumFinish(uint64(caracalID + dstAddr + uint32(srcPort) + uint32(ttl)))
}

// ChecksumAdd adds the big-endian 16-bit words of data to sum. A trailing odd
// byte is padded with a zero byte.
func ChecksumAdd(sum uint64, data []byte) uint64 {
	for len(data) >= 8 {
		sum += uint64(binary.BigEndian.Uint16(data)) +
			uint64(binary.BigEndian.Uint16(data[2:])) +
			uint64(binary.BigEndian.Uint16(data[4:])) +
			uint64(binary.BigEndian.Uint16(data[6:]))
		data = data[8:]
	}
	for len(data) >= 2 {
		sum += uint64(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint64(data[0]) << 8
	}
	return sum
}

// ChecksumFold folds the sum into 16 bits (one's complement addition).
func ChecksumFold(sum uint64) uint16 {
	return uint16(sum % 65535)
}

// ChecksumFinish folds the sum and takes its one's complement.
func ChecksumFinish(sum uint64) uint16 {
	return ^ChecksumFold(sum)
}

// IPChecksum computes the Internet checksum of data.
func IPChecksum(data []byte) uint16 {
	return ChecksumFinish(ChecksumAdd(0, data))
}

// IPv4PseudoHeaderSum sums the IPv4 pseudo-header.
func IPv4PseudoHeaderSum(src, dst [4]byte, protocol uint8, length uint16) uint64 {
	sum := ChecksumAdd(0, src[:])
	sum = ChecksumAdd(sum, dst[:])
	return sum + uint64(protocol) + uint64(length)
}

// IPv6PseudoHeaderSum sums the IPv6 pseudo-header.
func IPv6PseudoHeaderSum(src, dst [16]byte, protocol uint8, length uint32) uint64 {
	sum := ChecksumAdd(0, src[:])
	sum = ChecksumAdd(sum, dst[:])
	return sum + uint64(length>>16) + uint64(length&0xFFFF) + uint64(protocol)
}
