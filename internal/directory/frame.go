package directory

import (
	"bytes"
	"errors"
	"io"

	"github.com/go-ldap/ldap/v3"
)

const (
	maximumReadBytes  = 32 << 20
	maximumFrameBytes = 2 << 20
	maximumFrameDepth = 16
	maximumFrameNodes = 32768
	maximumReadNodes  = 262144
)

// frameReader bounds LDAP's definite-length BER before handing it to the
// dependency. It checks framing only; LDAP operations remain the library's job.
// Limits are local to this connection, not mutations of upstream global limits.
type frameReader struct {
	source         io.Reader
	pending        *bytes.Reader
	remaining      int
	remainingNodes int
	err            error
}

func newFrameReader(source io.Reader) *frameReader {
	return &frameReader{source: source, remaining: maximumReadBytes, remainingNodes: maximumReadNodes}
}

func (r *frameReader) Read(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if r.pending != nil && r.pending.Len() != 0 {
		return r.pending.Read(data)
	}
	if r.err != nil {
		return 0, r.err
	}
	frame, err := r.frame()
	if err != nil {
		r.err = err
		return 0, err
	}
	r.pending = bytes.NewReader(frame)
	return r.pending.Read(data)
}

func (r *frameReader) frame() ([]byte, error) {
	var header [6]byte
	if _, err := io.ReadFull(r.source, header[:2]); err != nil {
		return nil, err
	}
	if header[0] != 0x30 {
		return nil, ErrRead
	}
	extra := 0
	if header[1]&0x80 != 0 {
		extra = int(header[1] & 0x7f)
		if extra == 0 || extra > 4 {
			return nil, ErrRead
		}
		if _, err := io.ReadFull(r.source, header[2:2+extra]); err != nil {
			return nil, truncatedFrame(err)
		}
	}
	length, size, ok := frameHeader(header[:2+extra])
	if !ok || length > maximumFrameBytes-size || length > r.remaining-size {
		return nil, ErrRead
	}
	frame := make([]byte, size+length)
	copy(frame, header[:size])
	if _, err := io.ReadFull(r.source, frame[size:]); err != nil {
		return nil, truncatedFrame(err)
	}
	nodes := 0
	if !validFrame(frame, 0, &nodes) || !validControlValues(frame, &nodes) || nodes > r.remainingNodes {
		return nil, ErrRead
	}
	r.remaining -= len(frame)
	r.remainingNodes -= nodes
	return frame, nil
}

func truncatedFrame(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// frameHeader rejects indefinite lengths and high-tag encodings, neither of
// which is needed for these LDAP response operations. Check before converting
// to int so oversized lengths cannot wrap on a 32-bit target.
func frameHeader(data []byte) (length, size int, ok bool) {
	if len(data) < 2 || data[0]&0x1f == 0x1f {
		return 0, 0, false
	}
	if data[1]&0x80 == 0 {
		return int(data[1]), 2, true
	}
	extra := int(data[1] & 0x7f)
	if extra == 0 || extra > 4 || extra > len(data)-2 {
		return 0, 0, false
	}
	var value uint64
	for _, digit := range data[2 : 2+extra] {
		value = value<<8 | uint64(digit)
	}
	if value > maximumFrameBytes {
		return 0, 0, false
	}
	return int(value), 2 + extra, true
}

func validFrame(data []byte, depth int, nodes *int) bool {
	if depth >= maximumFrameDepth || *nodes >= maximumFrameNodes {
		return false
	}
	(*nodes)++
	length, size, ok := frameHeader(data)
	if !ok || length != len(data)-size {
		return false
	}
	if data[0]&0x20 == 0 {
		return true
	}
	for content := data[size:]; len(content) != 0; {
		length, size, ok := frameHeader(content)
		if !ok || length > len(content)-size || !validFrame(content[:size+length], depth+1, nodes) {
			return false
		}
		content = content[size+length:]
	}
	return true
}

// Paging values carry a second BER document inside an OCTET STRING. Bound that
// document too; outer framing alone would miss its depth/allocation budget.
// Other unsolicited controls are unsupported and rejected before decoding.
func validControlValues(frame []byte, nodes *int) bool {
	message, ok := frameChildren(frame, 3)
	if !ok {
		return false
	}
	if len(message) < 3 {
		return true
	}
	controls := message[2]
	if controls[0] != 0xa0 {
		return false
	}
	items, ok := frameChildren(controls, 1)
	if !ok || len(items) != 1 || items[0][0] != 0x30 {
		return false
	}
	fields, ok := frameChildren(items[0], 3)
	if !ok || len(fields) < 2 {
		return false
	}
	oid, ok := frameValue(fields[0], 0x04)
	if !ok || !bytes.Equal(oid, []byte(ldap.ControlTypePaging)) {
		return false
	}
	if len(fields) == 3 {
		critical, ok := frameValue(fields[1], 0x01)
		if !ok || len(critical) != 1 {
			return false
		}
	}
	value, ok := frameValue(fields[len(fields)-1], 0x04)
	if !ok || len(value) == 0 || value[0] != 0x30 || !validFrame(value, 0, nodes) {
		return false
	}
	paging, ok := frameChildren(value, 2)
	if !ok || len(paging) != 2 {
		return false
	}
	size, ok := frameValue(paging[0], 0x02)
	if !ok || len(size) == 0 || len(size) > 5 || size[0]&0x80 != 0 || len(size) == 5 && size[0] != 0 {
		return false
	}
	cookie, ok := frameValue(paging[1], 0x04)
	return ok && len(cookie) <= 4096
}

func frameChildren(frame []byte, maximum int) ([][]byte, bool) {
	length, size, ok := frameHeader(frame)
	if !ok || length != len(frame)-size || frame[0]&0x20 == 0 {
		return nil, false
	}
	children := [][]byte{}
	for content := frame[size:]; len(content) != 0; {
		length, size, ok := frameHeader(content)
		if !ok || length > len(content)-size || len(children) >= maximum {
			return nil, false
		}
		children = append(children, content[:size+length])
		content = content[size+length:]
	}
	return children, true
}

func frameValue(frame []byte, tag byte) ([]byte, bool) {
	length, size, ok := frameHeader(frame)
	if !ok || length != len(frame)-size || frame[0] != tag {
		return nil, false
	}
	return frame[size:], true
}
