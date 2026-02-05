// Copyright 2025 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"testing"
)

func TestDecodeVarint(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		wantValue uint64
		wantLen   int
		wantErr   bool
	}{
		{"1-byte min", []byte{0x00}, 0, 1, false},
		{"1-byte max", []byte{0x3f}, 63, 1, false},
		{"1-byte mid", []byte{0x25}, 37, 1, false},
		{"2-byte min", []byte{0x40, 0x00}, 0, 2, false},
		{"2-byte max", []byte{0x7f, 0xff}, 16383, 2, false},
		{"2-byte mid", []byte{0x7b, 0xbd}, 15293, 2, false},
		{"4-byte min", []byte{0x80, 0x00, 0x00, 0x00}, 0, 4, false},
		{"4-byte max", []byte{0xbf, 0xff, 0xff, 0xff}, 1073741823, 4, false},
		{"4-byte mid", []byte{0x9d, 0x7f, 0x3e, 0x7d}, 494878333, 4, false},
		{"8-byte min", []byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0, 8, false},
		{"8-byte max", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 4611686018427387903, 8, false},
		{"empty", []byte{}, 0, 0, true},
		{"2-byte truncated", []byte{0x40}, 0, 0, true},
		{"4-byte truncated", []byte{0x80, 0x00, 0x00}, 0, 0, true},
		{"8-byte truncated", []byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotValue, gotLen, err := DecodeVarint(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeVarint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if gotValue != tt.wantValue {
					t.Errorf("DecodeVarint() value = %d, want %d", gotValue, tt.wantValue)
				}
				if gotLen != tt.wantLen {
					t.Errorf("DecodeVarint() length = %d, want %d", gotLen, tt.wantLen)
				}
			}
		})
	}
}

func TestEncodeVarint(t *testing.T) {
	tests := []struct {
		name  string
		value uint64
		want  []byte
	}{
		{"1-byte min", 0, []byte{0x00}},
		{"1-byte max", 63, []byte{0x3f}},
		{"1-byte mid", 37, []byte{0x25}},
		{"2-byte min", 64, []byte{0x40, 0x40}},
		{"2-byte max", 16383, []byte{0x7f, 0xff}},
		{"2-byte mid", 15293, []byte{0x7b, 0xbd}},
		{"4-byte min", 16384, []byte{0x80, 0x00, 0x40, 0x00}},
		{"4-byte max", 1073741823, []byte{0xbf, 0xff, 0xff, 0xff}},
		{"4-byte mid", 494878333, []byte{0x9d, 0x7f, 0x3e, 0x7d}},
		{"8-byte min", 1073741824, []byte{0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00}},
		{"8-byte max", 4611686018427387903, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeVarint(tt.value)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("EncodeVarint(%d) = %x, want %x", tt.value, got, tt.want)
			}
		})
	}
}

func TestEncodeVarintPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("EncodeVarint did not panic for value > 2^62-1")
		}
	}()
	EncodeVarint(4611686018427387904) // 2^62
}

func TestVarintLen(t *testing.T) {
	tests := []struct {
		value   uint64
		wantLen int
	}{
		{0, 1},
		{63, 1},
		{64, 2},
		{16383, 2},
		{16384, 4},
		{1073741823, 4},
		{1073741824, 8},
		{4611686018427387903, 8},
	}

	for _, tt := range tests {
		got := VarintLen(tt.value)
		if got != tt.wantLen {
			t.Errorf("VarintLen(%d) = %d, want %d", tt.value, got, tt.wantLen)
		}
	}
}

func TestVarintLenPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("VarintLen did not panic for value > 2^62-1")
		}
	}()
	VarintLen(4611686018427387904) // 2^62
}

func TestVarintRoundTrip(t *testing.T) {
	values := []uint64{
		0, 1, 37, 63, 64, 151, 16383, 16384, 494878333,
		1073741823, 1073741824, 4611686018427387903,
	}

	for _, original := range values {
		encoded := EncodeVarint(original)
		decoded, length, err := DecodeVarint(encoded)
		if err != nil {
			t.Errorf("DecodeVarint failed for value %d: %v", original, err)
			continue
		}
		if decoded != original {
			t.Errorf("Round trip failed: original=%d, decoded=%d", original, decoded)
		}
		if length != len(encoded) {
			t.Errorf("Length mismatch: returned=%d, encoded=%d", length, len(encoded))
		}
	}
}
