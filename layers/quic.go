// Copyright 2025 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
)

// QUIC represents a QUIC packet (RFC 9000).
//
// This implementation supports stateless parsing and decryption of QUIC Initial
// packets, allowing extraction of CRYPTO frames containing TLS ClientHello.
// Other packet types are parsed but not decrypted (requires connection state).
type QUIC struct {
	BaseLayer

	// Header fields
	HeaderForm      bool           // true = long header, false = short header
	FixedBit        bool           // Must be 1 (except VN packets)
	PacketType      QUICPacketType // Initial, 0-RTT, Handshake, Retry, 1-RTT
	Version         uint32
	DCID            []byte // Destination Connection ID
	SCID            []byte // Source Connection ID (long header only)
	Token           []byte // Token (Initial and Retry packets)
	PacketNumberLen uint8  // 1-4 bytes
	PacketNumber    uint64

	// Payload
	Frames           []QUICFrame // Decoded frames (if payload was decrypted)
	DecryptedPayload []byte      // Decrypted payload (Initial packets only)
	DecryptionError  error       // Error during decryption (if any)

	// Raw packet data for reconstruction
	rawPacketNumber []byte
}

// QUICPacketType represents the type of QUIC packet
type QUICPacketType uint8

const (
	QUICPacketTypeInitial            QUICPacketType = 0 // 0b00
	QUICPacketType0RTT               QUICPacketType = 1 // 0b01
	QUICPacketTypeHandshake          QUICPacketType = 2 // 0b10
	QUICPacketTypeRetry              QUICPacketType = 3 // 0b11
	QUICPacketType1RTT               QUICPacketType = 4 // Short header
	QUICPacketTypeVersionNegotiation QUICPacketType = 5 // Version = 0
)

func (q QUICPacketType) String() string {
	switch q {
	case QUICPacketTypeInitial:
		return "Initial"
	case QUICPacketType0RTT:
		return "0-RTT"
	case QUICPacketTypeHandshake:
		return "Handshake"
	case QUICPacketTypeRetry:
		return "Retry"
	case QUICPacketType1RTT:
		return "1-RTT"
	case QUICPacketTypeVersionNegotiation:
		return "Version Negotiation"
	default:
		return fmt.Sprintf("Unknown(%d)", q)
	}
}

// LayerType returns LayerTypeQUIC
func (q *QUIC) LayerType() gopacket.LayerType {
	return LayerTypeQUIC
}

// CanDecode returns the set of layer types that this layer can decode
func (q *QUIC) CanDecode() gopacket.LayerClass {
	return LayerTypeQUIC
}

// NextLayerType returns the layer type contained within this layer
func (q *QUIC) NextLayerType() gopacket.LayerType {
	// QUIC payloads are encrypted; frames are not separate layers
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes a QUIC packet from raw bytes
func (q *QUIC) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 1 {
		return fmt.Errorf("QUIC packet too short: %d bytes", len(data))
	}

	offset := 0
	firstByte := data[offset]
	offset++

	// Parse header form (bit 7)
	q.HeaderForm = (firstByte & 0x80) != 0

	if q.HeaderForm {
		// Long Header (RFC 9000 Section 17.2)
		return q.decodeLongHeader(data, df)
	}
	// Short Header (RFC 9000 Section 17.3)
	return q.decodeShortHeader(data, df)
}

// decodeLongHeader decodes a QUIC long header packet
func (q *QUIC) decodeLongHeader(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 6 {
		df.SetTruncated()
		return fmt.Errorf("QUIC long header too short: %d bytes", len(data))
	}

	offset := 0
	firstByte := data[offset]
	offset++

	q.HeaderForm = true
	q.FixedBit = (firstByte & 0x40) != 0

	// Parse version (4 bytes)
	q.Version = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Check for Version Negotiation packet (version = 0)
	if q.Version == 0 {
		q.PacketType = QUICPacketTypeVersionNegotiation
		return q.decodeVersionNegotiation(data, offset, df)
	}

	// Parse packet type (bits 4-5 of first byte)
	longPacketType := (firstByte >> 4) & 0x03
	switch longPacketType {
	case 0:
		q.PacketType = QUICPacketTypeInitial
	case 1:
		q.PacketType = QUICPacketType0RTT
	case 2:
		q.PacketType = QUICPacketTypeHandshake
	case 3:
		q.PacketType = QUICPacketTypeRetry
	}

	// Parse DCID length and DCID
	if offset >= len(data) {
		df.SetTruncated()
		return fmt.Errorf("truncated at DCID length")
	}
	dcidLen := int(data[offset])
	offset++

	if dcidLen > 20 {
		return fmt.Errorf("invalid DCID length: %d", dcidLen)
	}

	if offset+dcidLen > len(data) {
		df.SetTruncated()
		return fmt.Errorf("truncated at DCID")
	}
	q.DCID = data[offset : offset+dcidLen]
	offset += dcidLen

	// Parse SCID length and SCID
	if offset >= len(data) {
		df.SetTruncated()
		return fmt.Errorf("truncated at SCID length")
	}
	scidLen := int(data[offset])
	offset++

	if scidLen > 20 {
		return fmt.Errorf("invalid SCID length: %d", scidLen)
	}

	if offset+scidLen > len(data) {
		df.SetTruncated()
		return fmt.Errorf("truncated at SCID")
	}
	q.SCID = data[offset : offset+scidLen]
	offset += scidLen

	// Handle packet-type-specific fields
	switch q.PacketType {
	case QUICPacketTypeInitial:
		// Parse token (varint length + data)
		tokenLen, varLen, err := DecodeVarint(data[offset:])
		if err != nil {
			return fmt.Errorf("failed to decode token length: %w", err)
		}
		offset += varLen

		if tokenLen > 0 {
			if offset+int(tokenLen) > len(data) {
				df.SetTruncated()
				return fmt.Errorf("truncated at token")
			}
			q.Token = data[offset : offset+int(tokenLen)]
			offset += int(tokenLen)
		}

		// Parse length and payload
		return q.decodeLongHeaderPayload(data, offset, df)

	case QUICPacketType0RTT, QUICPacketTypeHandshake:
		// Parse length and payload
		return q.decodeLongHeaderPayload(data, offset, df)

	case QUICPacketTypeRetry:
		// Retry packets have special format (no packet number)
		// Token is the rest of the packet minus 16-byte integrity tag
		if offset+16 > len(data) {
			df.SetTruncated()
			return fmt.Errorf("retry packet too short")
		}
		q.Token = data[offset : len(data)-16]
		q.Contents = data[:len(data)]
		q.BaseLayer.Payload = nil
		return nil
	}

	return nil
}

// decodeLongHeaderPayload decodes the payload portion of a long header packet
func (q *QUIC) decodeLongHeaderPayload(data []byte, offset int, df gopacket.DecodeFeedback) error {
	// Parse packet length (varint)
	packetLen, varLen, err := DecodeVarint(data[offset:])
	if err != nil {
		return fmt.Errorf("failed to decode packet length: %w", err)
	}
	offset += varLen

	// Packet length includes packet number + payload
	if offset+int(packetLen) > len(data) {
		df.SetTruncated()
		return fmt.Errorf("truncated at packet payload: need %d bytes, have %d", offset+int(packetLen), len(data))
	}

	payloadEnd := offset + int(packetLen)

	// For Initial packets, attempt decryption
	if q.PacketType == QUICPacketTypeInitial && len(q.DCID) > 0 {
		err := q.decryptInitialPacket(data, offset, payloadEnd)
		if err != nil {
			q.DecryptionError = err
			// Continue parsing even if decryption fails
		}
	}

	// If decryption failed or not attempted, store encrypted payload
	if q.DecryptedPayload == nil {
		// Store the protected payload (we can't determine packet number without decryption)
		q.Contents = data[:payloadEnd]
		q.BaseLayer.Payload = data[offset:payloadEnd]
	} else {
		// Decryption succeeded, parse frames
		q.Contents = data[:payloadEnd]
		frames, err := ParseFrames(q.DecryptedPayload)
		if err != nil {
			return fmt.Errorf("failed to parse frames: %w", err)
		}
		q.Frames = frames
	}

	return nil
}

// decryptInitialPacket attempts to decrypt an Initial packet using DCID-derived keys
func (q *QUIC) decryptInitialPacket(data []byte, pnOffset, payloadEnd int) error {
	// Derive initial secrets from DCID
	clientSecret, _ := DeriveInitialSecrets(q.DCID)
	key, iv, hp := DeriveTrafficKeys(clientSecret)

	// Make a copy of the packet data to modify during header protection removal
	packet := make([]byte, len(data))
	copy(packet, data)

	// Remove header protection to reveal packet number
	pnLength, pn, err := RemoveHeaderProtection(packet, pnOffset, hp)
	if err != nil {
		return fmt.Errorf("header protection removal failed: %w", err)
	}

	q.PacketNumber = pn
	q.PacketNumberLen = uint8(pnLength)

	// Extract encrypted payload (after packet number)
	payloadOffset := pnOffset + pnLength
	if payloadOffset >= payloadEnd {
		return fmt.Errorf("no payload after packet number")
	}
	encryptedPayload := packet[payloadOffset:payloadEnd]

	// Header for AEAD is from start up to and including packet number
	header := packet[:payloadOffset]

	// Decrypt payload
	decrypted, err := DecryptPayload(header, encryptedPayload, pn, key, iv)
	if err != nil {
		return fmt.Errorf("payload decryption failed: %w", err)
	}

	q.DecryptedPayload = decrypted
	return nil
}

// decodeShortHeader decodes a QUIC short header (1-RTT) packet
func (q *QUIC) decodeShortHeader(data []byte, df gopacket.DecodeFeedback) error {
	// Short headers cannot be fully decoded without connection state
	// We can only parse the fixed bit and store the rest as payload
	q.HeaderForm = false
	q.PacketType = QUICPacketType1RTT

	firstByte := data[0]
	q.FixedBit = (firstByte & 0x40) != 0

	// DCID length is not encoded in short header - requires connection state
	// Packet number length is protected - requires connection state
	// For now, just store entire packet as Contents
	q.Contents = data
	q.BaseLayer.Payload = data[1:]

	return nil
}

// decodeVersionNegotiation decodes a Version Negotiation packet
func (q *QUIC) decodeVersionNegotiation(data []byte, offset int, df gopacket.DecodeFeedback) error {
	// Parse DCID
	if offset >= len(data) {
		df.SetTruncated()
		return fmt.Errorf("truncated at DCID length")
	}
	dcidLen := int(data[offset])
	offset++

	if offset+dcidLen > len(data) {
		df.SetTruncated()
		return fmt.Errorf("truncated at DCID")
	}
	q.DCID = data[offset : offset+dcidLen]
	offset += dcidLen

	// Parse SCID
	if offset >= len(data) {
		df.SetTruncated()
		return fmt.Errorf("truncated at SCID length")
	}
	scidLen := int(data[offset])
	offset++

	if offset+scidLen > len(data) {
		df.SetTruncated()
		return fmt.Errorf("truncated at SCID")
	}
	q.SCID = data[offset : offset+scidLen]
	offset += scidLen

	// Rest is supported versions (4 bytes each)
	q.Contents = data
	q.BaseLayer.Payload = data[offset:]

	return nil
}

// SerializeTo writes the serialized form of this layer into the SerializationBuffer
func (q *QUIC) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic serialization support - can be extended as needed
	return fmt.Errorf("QUIC serialization not yet implemented")
}

// Payload returns the QUIC payload
func (q *QUIC) Payload() []byte {
	return q.BaseLayer.Payload
}

// decodeQUIC decodes a QUIC packet
func decodeQUIC(data []byte, p gopacket.PacketBuilder) error {
	quic := &QUIC{}
	err := quic.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(quic)
	p.SetApplicationLayer(quic)
	return nil
}
