package directory

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestFrameReaderBoundsBeforeDecoding(t *testing.T) {
	valid := []byte{0x30, 3, 2, 1, 1}
	reader := newFrameReader(bytes.NewReader(append(bytes.Clone(valid), valid...)))
	data, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(data, append(bytes.Clone(valid), valid...)) {
		t.Fatalf("valid framing: %x, %v", data, err)
	}
	deep := []byte{2, 1, 1}
	for range maximumFrameDepth {
		if len(deep) > 127 {
			t.Fatal("synthetic short-length fixture exceeded its encoding")
		}
		deep = append([]byte{0x30, byte(len(deep) & 0x7f)}, deep...)
	}
	tests := [][]byte{
		{0x30, 0x80}, {0x30, 0x85}, {0x31, 0}, {0x30, 0x84, 0xff, 0xff, 0xff, 0xff},
		{0x30, 2, 2, 1}, {0x30, 3, 0x1f, 1, 0}, {0x30, 3}, {0x30, 0x81}, deep,
	}
	for _, frame := range tests {
		reader := newFrameReader(bytes.NewReader(frame))
		if data, err := io.ReadAll(reader); err == nil || len(data) != 0 {
			t.Fatalf("unsafe framing escaped: %x, %v", data, err)
		}
		if _, err := reader.Read(make([]byte, 1)); err == nil {
			t.Fatal("framing failure reset")
		}
	}
	reader = newFrameReader(bytes.NewReader(valid))
	reader.remaining = len(valid) - 1
	if _, err := io.ReadAll(reader); !errors.Is(err, ErrRead) {
		t.Fatalf("connection budget ignored: %v", err)
	}
	nodes := maximumFrameNodes
	if validFrame(valid, 0, &nodes) {
		t.Fatal("node budget ignored")
	}
	reader = newFrameReader(bytes.NewReader(valid))
	reader.remainingNodes = 1
	if _, err := io.ReadAll(reader); !errors.Is(err, ErrRead) {
		t.Fatalf("connection node budget ignored: %v", err)
	}
}

func FuzzFrameReader(f *testing.F) {
	f.Add([]byte{0x30, 3, 2, 1, 1})
	f.Add([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maximumFrameBytes {
			t.Skip()
		}
		reader := newFrameReader(bytes.NewReader(data))
		reader.remaining = maximumFrameBytes
		output, err := io.ReadAll(reader)
		if len(output) > maximumFrameBytes {
			t.Fatal("framing exceeded quota")
		}
		if err == nil && !bytes.Equal(data, output) {
			t.Fatal("framing rewrote input")
		}
	})
}
