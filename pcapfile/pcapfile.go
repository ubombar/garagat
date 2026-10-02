// Package pcapfile reads and writes classic libpcap capture files in pure Go.
package pcapfile

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	magicMicros      = 0xA1B2C3D4
	magicNanos       = 0xA1B23C4D
	globalHeaderSize = 24
	recordHeaderSize = 16
	defaultSnapLen   = 262144
	versionMajor     = 2
	versionMinor     = 4
)

// Packet is a captured packet.
type Packet struct {
	Timestamp time.Time
	// OrigLen is the length of the packet on the wire.
	OrigLen int
	// Data is the captured bytes. It is only valid until the next call to
	// Reader.Next.
	Data []byte
}

// Reader reads packets from a pcap file.
type Reader struct {
	r        *bufio.Reader
	order    binary.ByteOrder
	nanos    bool
	linkType uint32
	snapLen  uint32
	hdr      [recordHeaderSize]byte
	buf      []byte
}

// NewReader reads the pcap global header from r.
func NewReader(r io.Reader) (*Reader, error) {
	br := bufio.NewReader(r)
	var hdr [globalHeaderSize]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, fmt.Errorf("pcapfile: reading header: %w", err)
	}
	rd := &Reader{r: br}
	switch {
	case binary.LittleEndian.Uint32(hdr[:]) == magicMicros:
		rd.order = binary.LittleEndian
	case binary.BigEndian.Uint32(hdr[:]) == magicMicros:
		rd.order = binary.BigEndian
	case binary.LittleEndian.Uint32(hdr[:]) == magicNanos:
		rd.order, rd.nanos = binary.LittleEndian, true
	case binary.BigEndian.Uint32(hdr[:]) == magicNanos:
		rd.order, rd.nanos = binary.BigEndian, true
	default:
		return nil, errors.New("pcapfile: unknown magic number (pcapng is not supported)")
	}
	rd.snapLen = rd.order.Uint32(hdr[16:])
	rd.linkType = rd.order.Uint32(hdr[20:]) & 0x0FFFFFFF
	return rd, nil
}

// LinkType returns the link-layer header type of the file.
func (r *Reader) LinkType() uint32 { return r.linkType }

// SnapLen returns the snapshot length of the file.
func (r *Reader) SnapLen() uint32 { return r.snapLen }

// Next reads the next packet. It returns io.EOF at the end of the file.
func (r *Reader) Next() (Packet, error) {
	if _, err := io.ReadFull(r.r, r.hdr[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return Packet{}, fmt.Errorf("pcapfile: truncated record header")
		}
		return Packet{}, err
	}
	sec := int64(r.order.Uint32(r.hdr[0:]))
	frac := int64(r.order.Uint32(r.hdr[4:]))
	capLen := r.order.Uint32(r.hdr[8:])
	origLen := r.order.Uint32(r.hdr[12:])
	if capLen > 1<<26 {
		return Packet{}, fmt.Errorf("pcapfile: invalid capture length %d", capLen)
	}
	if cap(r.buf) < int(capLen) {
		r.buf = make([]byte, capLen)
	}
	r.buf = r.buf[:capLen]
	if _, err := io.ReadFull(r.r, r.buf); err != nil {
		return Packet{}, fmt.Errorf("pcapfile: truncated packet: %w", err)
	}
	if !r.nanos {
		frac *= 1000
	}
	return Packet{Timestamp: time.Unix(sec, frac), OrigLen: int(origLen), Data: r.buf}, nil
}

// Writer writes packets to a pcap file with microsecond timestamps.
type Writer struct {
	w *bufio.Writer
}

// NewWriter writes the pcap global header to w.
func NewWriter(w io.Writer, linkType uint32) (*Writer, error) {
	bw := bufio.NewWriter(w)
	var hdr [globalHeaderSize]byte
	binary.LittleEndian.PutUint32(hdr[0:], magicMicros)
	binary.LittleEndian.PutUint16(hdr[4:], versionMajor)
	binary.LittleEndian.PutUint16(hdr[6:], versionMinor)
	binary.LittleEndian.PutUint32(hdr[16:], defaultSnapLen)
	binary.LittleEndian.PutUint32(hdr[20:], linkType)
	if _, err := bw.Write(hdr[:]); err != nil {
		return nil, err
	}
	return &Writer{w: bw}, nil
}

// WritePacket writes a packet record.
func (w *Writer) WritePacket(ts time.Time, data []byte, origLen int) error {
	var hdr [recordHeaderSize]byte
	binary.LittleEndian.PutUint32(hdr[0:], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(hdr[4:], uint32(ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(hdr[8:], uint32(len(data)))
	binary.LittleEndian.PutUint32(hdr[12:], uint32(origLen))
	if _, err := w.w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.w.Write(data)
	return err
}

// Flush flushes buffered records to the underlying writer.
func (w *Writer) Flush() error { return w.w.Flush() }
