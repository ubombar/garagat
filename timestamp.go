package garagat

import "time"

// Probes carry the send time, in tenths of milliseconds modulo 65535, in a
// 16-bit field (the ICMP sequence number or the UDP checksum). The RTT is
// recovered from the capture time of the reply.

// TenthMs converts a duration since the Unix epoch to tenths of milliseconds.
func TenthMs(d time.Duration) uint64 {
	return uint64(d / (100 * time.Microsecond))
}

// TimestampNow returns the current time in tenths of milliseconds.
func TimestampNow() uint64 {
	return TenthMs(time.Duration(time.Now().UnixNano()))
}

// EncodeTimestamp encodes a timestamp on 16 bits.
func EncodeTimestamp(timestamp uint64) uint16 {
	return uint16(timestamp % 65535)
}

// DecodeTimestamp returns the latest time before timestamp whose encoding is
// remainder.
func DecodeTimestamp(timestamp uint64, remainder uint16) uint64 {
	// quotient = ceil(timestamp / 65535) - 1
	var quotient uint64
	if timestamp > 0 {
		quotient = (timestamp+65534)/65535 - 1
	}
	decoded := quotient*65535 + uint64(remainder)
	if decoded > timestamp {
		return decoded - 65535
	}
	return decoded
}

// TimestampDifference returns timestamp minus the decoded remainder, in tenths
// of milliseconds.
func TimestampDifference(timestamp uint64, remainder uint16) uint16 {
	return uint16(timestamp - DecodeTimestamp(timestamp, remainder))
}
