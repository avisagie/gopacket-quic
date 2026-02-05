// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import "fmt"

// QUIC Variable-Length Integer Encoding (RFC 9000 Section 16)
//
// QUIC variable-length integers encode values from 0 to 2^62-1 using 1, 2, 4, or 8 bytes.
// The two most significant bits of the first byte indicate the total length:
//   00 = 1 byte  (values 0-63)
//   01 = 2 bytes (values 0-16383)
//   10 = 4 bytes (values 0-1073741823)
//   11 = 8 bytes (values 0-4611686018427387903)

const (
	maxVarint1 = 63                      // 2^6 - 1
	maxVarint2 = 16383                   // 2^14 - 1
	maxVarint4 = 1073741823              // 2^30 - 1
	maxVarint8 = 4611686018427387903     // 2^62 - 1
)

// DecodeVarint decodes a QUIC variable-length integer from the given byte slice.
// Returns the decoded value, the number of bytes consumed, and any error.
func DecodeVarint(data []byte) (value uint64, length int, err error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("cannot decode varint from empty slice")
	}

	firstByte := data[0]
	prefix := firstByte >> 6 // Extract top 2 bits

	switch prefix {
	case 0: // 1-byte encoding
		return uint64(firstByte & 0x3f), 1, nil

	case 1: // 2-byte encoding
		if len(data) < 2 {
			return 0, 0, fmt.Errorf("insufficient bytes for 2-byte varint: have %d, need 2", len(data))
		}
		value = uint64(firstByte&0x3f)<<8 | uint64(data[1])
		return value, 2, nil

	case 2: // 4-byte encoding
		if len(data) < 4 {
			return 0, 0, fmt.Errorf("insufficient bytes for 4-byte varint: have %d, need 4", len(data))
		}
		value = uint64(firstByte&0x3f)<<24 |
			uint64(data[1])<<16 |
			uint64(data[2])<<8 |
			uint64(data[3])
		return value, 4, nil

	case 3: // 8-byte encoding
		if len(data) < 8 {
			return 0, 0, fmt.Errorf("insufficient bytes for 8-byte varint: have %d, need 8", len(data))
		}
		value = uint64(firstByte&0x3f)<<56 |
			uint64(data[1])<<48 |
			uint64(data[2])<<40 |
			uint64(data[3])<<32 |
			uint64(data[4])<<24 |
			uint64(data[5])<<16 |
			uint64(data[6])<<8 |
			uint64(data[7])
		return value, 8, nil

	default:
		// Should never reach here due to 2-bit prefix
		return 0, 0, fmt.Errorf("invalid varint prefix: %d", prefix)
	}
}

// EncodeVarint encodes a value as a QUIC variable-length integer.
// Returns the encoded bytes or panics if the value is too large.
func EncodeVarint(value uint64) []byte {
	if value <= maxVarint1 {
		// 1-byte encoding
		return []byte{byte(value)}
	} else if value <= maxVarint2 {
		// 2-byte encoding
		return []byte{
			byte(0x40 | (value >> 8)),
			byte(value),
		}
	} else if value <= maxVarint4 {
		// 4-byte encoding
		return []byte{
			byte(0x80 | (value >> 24)),
			byte(value >> 16),
			byte(value >> 8),
			byte(value),
		}
	} else if value <= maxVarint8 {
		// 8-byte encoding
		return []byte{
			byte(0xc0 | (value >> 56)),
			byte(value >> 48),
			byte(value >> 40),
			byte(value >> 32),
			byte(value >> 24),
			byte(value >> 16),
			byte(value >> 8),
			byte(value),
		}
	}
	panic(fmt.Sprintf("value %d exceeds maximum QUIC varint (2^62-1)", value))
}

// VarintLen returns the encoded length in bytes for a given value.
func VarintLen(value uint64) int {
	if value <= maxVarint1 {
		return 1
	} else if value <= maxVarint2 {
		return 2
	} else if value <= maxVarint4 {
		return 4
	} else if value <= maxVarint8 {
		return 8
	}
	panic(fmt.Sprintf("value %d exceeds maximum QUIC varint (2^62-1)", value))
}
