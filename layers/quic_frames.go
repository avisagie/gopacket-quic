// Copyright 2025 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import "fmt"

// QUICFrame is the interface for all QUIC frame types
type QUICFrame interface {
	FrameType() uint8
}

// QUIC Frame Type constants (RFC 9000 Section 12.4)
const (
	QUICFrameTypePadding         = 0x00
	QUICFrameTypePing            = 0x01
	QUICFrameTypeAck             = 0x02
	QUICFrameTypeAckECN          = 0x03
	QUICFrameTypeResetStream     = 0x04
	QUICFrameTypeStopSending     = 0x05
	QUICFrameTypeCrypto          = 0x06
	QUICFrameTypeNewToken        = 0x07
	QUICFrameTypeStreamBase      = 0x08 // 0x08-0x0f are STREAM frames
	QUICFrameTypeMaxData         = 0x10
	QUICFrameTypeMaxStreamData   = 0x11
	QUICFrameTypeMaxStreams      = 0x12
	QUICFrameTypeDataBlocked     = 0x14
	QUICFrameTypeStreamDataBlocked = 0x15
	QUICFrameTypeStreamsBlocked  = 0x16
	QUICFrameTypeNewConnectionID = 0x18
	QUICFrameTypeRetireConnectionID = 0x19
	QUICFrameTypePathChallenge   = 0x1a
	QUICFrameTypePathResponse    = 0x1b
	QUICFrameTypeConnectionClose = 0x1c
	QUICFrameTypeConnectionCloseApp = 0x1d
	QUICFrameTypeHandshakeDone   = 0x1e
)

// QUICPaddingFrame represents a PADDING frame (0x00)
type QUICPaddingFrame struct {
	Length int // Number of padding bytes
}

func (f *QUICPaddingFrame) FrameType() uint8 { return QUICFrameTypePadding }

// QUICPingFrame represents a PING frame (0x01)
type QUICPingFrame struct{}

func (f *QUICPingFrame) FrameType() uint8 { return QUICFrameTypePing }

// QUICAckRange represents an ACK range
type QUICAckRange struct {
	Gap    uint64
	Length uint64
}

// QUICAckFrame represents an ACK frame (0x02-0x03)
type QUICAckFrame struct {
	LargestAcknowledged uint64
	AckDelay            uint64
	AckRangeCount       uint64
	FirstAckRange       uint64
	AckRanges           []QUICAckRange
	ECNCounts           *QUICECNCounts // Present only for ACK_ECN (0x03)
}

func (f *QUICAckFrame) FrameType() uint8 {
	if f.ECNCounts != nil {
		return QUICFrameTypeAckECN
	}
	return QUICFrameTypeAck
}

// QUICECNCounts represents ECN counts in ACK_ECN frames
type QUICECNCounts struct {
	ECT0Count uint64
	ECT1Count uint64
	ECNCount  uint64
}

// QUICCryptoFrame represents a CRYPTO frame (0x06)
type QUICCryptoFrame struct {
	Offset uint64
	Length uint64
	Data   []byte
}

func (f *QUICCryptoFrame) FrameType() uint8 { return QUICFrameTypeCrypto }

// QUICStreamFrame represents a STREAM frame (0x08-0x0f)
type QUICStreamFrame struct {
	StreamID uint64
	Offset   uint64
	Length   uint64
	Data     []byte
	Fin      bool
}

func (f *QUICStreamFrame) FrameType() uint8 {
	typ := uint8(QUICFrameTypeStreamBase)
	if f.Fin {
		typ |= 0x01
	}
	if len(f.Data) > 0 {
		typ |= 0x02 // LEN bit
	}
	if f.Offset > 0 {
		typ |= 0x04 // OFF bit
	}
	return typ
}

// QUICConnectionCloseFrame represents a CONNECTION_CLOSE frame (0x1c-0x1d)
type QUICConnectionCloseFrame struct {
	ErrorCode       uint64
	TriggerFrameType uint64 // Only for 0x1c (renamed from FrameType to avoid conflict)
	ReasonLength    uint64
	ReasonPhrase    string
	IsApplication   bool // true for 0x1d, false for 0x1c
}

func (f *QUICConnectionCloseFrame) FrameType() uint8 {
	if f.IsApplication {
		return QUICFrameTypeConnectionCloseApp
	}
	return QUICFrameTypeConnectionClose
}

// ParseFrames parses QUIC frames from a decrypted payload
func ParseFrames(payload []byte) ([]QUICFrame, error) {
	var frames []QUICFrame
	offset := 0

	for offset < len(payload) {
		if offset >= len(payload) {
			break
		}

		// Read frame type (varint)
		frameType, n, err := DecodeVarint(payload[offset:])
		if err != nil {
			return frames, fmt.Errorf("failed to decode frame type at offset %d: %w", offset, err)
		}
		offset += n

		switch {
		case frameType == QUICFrameTypePadding:
			// PADDING frames - skip consecutive 0x00 bytes
			paddingLen := 1
			for offset < len(payload) && payload[offset] == 0x00 {
				paddingLen++
				offset++
			}
			frames = append(frames, &QUICPaddingFrame{Length: paddingLen})

		case frameType == QUICFrameTypePing:
			frames = append(frames, &QUICPingFrame{})

		case frameType == QUICFrameTypeAck || frameType == QUICFrameTypeAckECN:
			frame, n, err := parseAckFrame(payload[offset:], frameType == QUICFrameTypeAckECN)
			if err != nil {
				return frames, fmt.Errorf("failed to parse ACK frame: %w", err)
			}
			offset += n
			frames = append(frames, frame)

		case frameType == QUICFrameTypeCrypto:
			frame, n, err := parseCryptoFrame(payload[offset:])
			if err != nil {
				return frames, fmt.Errorf("failed to parse CRYPTO frame: %w", err)
			}
			offset += n
			frames = append(frames, frame)

		case frameType >= 0x08 && frameType <= 0x0f:
			// STREAM frames
			frame, n, err := parseStreamFrame(payload[offset:], uint8(frameType))
			if err != nil {
				return frames, fmt.Errorf("failed to parse STREAM frame: %w", err)
			}
			offset += n
			frames = append(frames, frame)

		case frameType == QUICFrameTypeConnectionClose || frameType == QUICFrameTypeConnectionCloseApp:
			frame, n, err := parseConnectionCloseFrame(payload[offset:], frameType == QUICFrameTypeConnectionCloseApp)
			if err != nil {
				return frames, fmt.Errorf("failed to parse CONNECTION_CLOSE frame: %w", err)
			}
			offset += n
			frames = append(frames, frame)

		default:
			// Unknown frame type - cannot continue parsing safely
			return frames, fmt.Errorf("unknown frame type: 0x%02x at offset %d", frameType, offset-n)
		}
	}

	return frames, nil
}

// parseAckFrame parses an ACK or ACK_ECN frame
func parseAckFrame(data []byte, hasECN bool) (*QUICAckFrame, int, error) {
	offset := 0
	frame := &QUICAckFrame{}

	// Largest Acknowledged
	val, n, err := DecodeVarint(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	frame.LargestAcknowledged = val
	offset += n

	// ACK Delay
	val, n, err = DecodeVarint(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	frame.AckDelay = val
	offset += n

	// ACK Range Count
	val, n, err = DecodeVarint(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	frame.AckRangeCount = val
	offset += n

	// First ACK Range
	val, n, err = DecodeVarint(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	frame.FirstAckRange = val
	offset += n

	// Additional ACK Ranges
	for i := uint64(0); i < frame.AckRangeCount; i++ {
		var ackRange QUICAckRange

		// Gap
		val, n, err = DecodeVarint(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		ackRange.Gap = val
		offset += n

		// ACK Range Length
		val, n, err = DecodeVarint(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		ackRange.Length = val
		offset += n

		frame.AckRanges = append(frame.AckRanges, ackRange)
	}

	// ECN Counts (if ACK_ECN)
	if hasECN {
		ecn := &QUICECNCounts{}

		// ECT(0) Count
		val, n, err = DecodeVarint(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		ecn.ECT0Count = val
		offset += n

		// ECT(1) Count
		val, n, err = DecodeVarint(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		ecn.ECT1Count = val
		offset += n

		// ECN-CE Count
		val, n, err = DecodeVarint(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		ecn.ECNCount = val
		offset += n

		frame.ECNCounts = ecn
	}

	return frame, offset, nil
}

// parseCryptoFrame parses a CRYPTO frame
func parseCryptoFrame(data []byte) (*QUICCryptoFrame, int, error) {
	offset := 0
	frame := &QUICCryptoFrame{}

	// Offset
	val, n, err := DecodeVarint(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	frame.Offset = val
	offset += n

	// Length
	val, n, err = DecodeVarint(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	frame.Length = val
	offset += n

	// Data
	if offset+int(frame.Length) > len(data) {
		return nil, 0, fmt.Errorf("CRYPTO frame data truncated: need %d bytes, have %d", frame.Length, len(data)-offset)
	}
	frame.Data = data[offset : offset+int(frame.Length)]
	offset += int(frame.Length)

	return frame, offset, nil
}

// parseStreamFrame parses a STREAM frame
func parseStreamFrame(data []byte, frameTypeByte uint8) (*QUICStreamFrame, int, error) {
	offset := 0
	frame := &QUICStreamFrame{}

	// Extract flags from frame type byte
	frame.Fin = (frameTypeByte & 0x01) != 0
	hasLen := (frameTypeByte & 0x02) != 0
	hasOff := (frameTypeByte & 0x04) != 0

	// Stream ID
	val, n, err := DecodeVarint(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	frame.StreamID = val
	offset += n

	// Offset (if present)
	if hasOff {
		val, n, err = DecodeVarint(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		frame.Offset = val
		offset += n
	}

	// Length (if present)
	if hasLen {
		val, n, err = DecodeVarint(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		frame.Length = val
		offset += n

		// Read data
		if offset+int(frame.Length) > len(data) {
			return nil, 0, fmt.Errorf("STREAM frame data truncated")
		}
		frame.Data = data[offset : offset+int(frame.Length)]
		offset += int(frame.Length)
	} else {
		// No length field - data extends to end of packet
		frame.Length = uint64(len(data) - offset)
		frame.Data = data[offset:]
		offset = len(data)
	}

	return frame, offset, nil
}

// parseConnectionCloseFrame parses a CONNECTION_CLOSE frame
func parseConnectionCloseFrame(data []byte, isApp bool) (*QUICConnectionCloseFrame, int, error) {
	offset := 0
	frame := &QUICConnectionCloseFrame{
		IsApplication: isApp,
	}

	// Error Code
	val, n, err := DecodeVarint(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	frame.ErrorCode = val
	offset += n

	// Trigger Frame Type (only for non-application close)
	if !isApp {
		val, n, err = DecodeVarint(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		frame.TriggerFrameType = val
		offset += n
	}

	// Reason Phrase Length
	val, n, err = DecodeVarint(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	frame.ReasonLength = val
	offset += n

	// Reason Phrase
	if frame.ReasonLength > 0 {
		if offset+int(frame.ReasonLength) > len(data) {
			return nil, 0, fmt.Errorf("CONNECTION_CLOSE reason phrase truncated")
		}
		frame.ReasonPhrase = string(data[offset : offset+int(frame.ReasonLength)])
		offset += int(frame.ReasonLength)
	}

	return frame, offset, nil
}
