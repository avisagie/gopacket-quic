// Copyright 2025 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.
package layers

import (
	"bytes"
	"testing"

	"github.com/google/gopacket"
)

func TestQUICPacketTypeString(t *testing.T) {
	tests := []struct {
		ptype QUICPacketType
		want  string
	}{
		{QUICPacketTypeInitial, "Initial"},
		{QUICPacketType0RTT, "0-RTT"},
		{QUICPacketTypeHandshake, "Handshake"},
		{QUICPacketTypeRetry, "Retry"},
		{QUICPacketType1RTT, "1-RTT"},
		{QUICPacketTypeVersionNegotiation, "Version Negotiation"},
		{QUICPacketType(99), "Unknown(99)"},
	}

	for _, tt := range tests {
		if got := tt.ptype.String(); got != tt.want {
			t.Errorf("QUICPacketType.String() = %q, want %q", got, tt.want)
		}
	}
}

func TestQUICShortHeader(t *testing.T) {
	// Short header packet (1-RTT)
	data := []byte{
		0x40, // Short header, fixed bit set
		0x01, 0x02, 0x03, 0x04, // Some payload
	}

	quic := &QUIC{}
	err := quic.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("DecodeFromBytes failed: %v", err)
	}

	if quic.HeaderForm != false {
		t.Errorf("HeaderForm = %v, want false", quic.HeaderForm)
	}
	if quic.PacketType != QUICPacketType1RTT {
		t.Errorf("PacketType = %v, want 1-RTT", quic.PacketType)
	}
	if quic.FixedBit != true {
		t.Errorf("FixedBit = %v, want true", quic.FixedBit)
	}
}

func TestQUICInitialPacket(t *testing.T) {
	// Initial packet structure
	data := []byte{
		0xc0,                   // Long header, Initial packet (bits 4-5 = 00)
		0x00, 0x00, 0x00, 0x01, // Version 1
		0x08,                                           // DCID length = 8
		0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, // DCID
		0x00, // SCID length = 0
		0x00, // Token length = 0
		0x08, // Packet length (varint: 8 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Protected payload (packet number + encrypted data)
	}

	quic := &QUIC{}
	err := quic.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("DecodeFromBytes failed: %v", err)
	}

	if quic.HeaderForm != true {
		t.Errorf("HeaderForm = %v, want true", quic.HeaderForm)
	}
	if quic.PacketType != QUICPacketTypeInitial {
		t.Errorf("PacketType = %v, want Initial", quic.PacketType)
	}
	if quic.Version != 0x00000001 {
		t.Errorf("Version = 0x%08x, want 0x00000001", quic.Version)
	}
	if !bytes.Equal(quic.DCID, []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}) {
		t.Errorf("DCID = %x, want 8394c8f03e515708", quic.DCID)
	}
	if len(quic.SCID) != 0 {
		t.Errorf("SCID length = %d, want 0", len(quic.SCID))
	}
}

func TestQUICVersionNegotiation(t *testing.T) {
	data := []byte{
		0xc0,                   // Long header
		0x00, 0x00, 0x00, 0x00, // Version 0 = Version Negotiation
		0x08,                                           // DCID length
		0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, // DCID
		0x00,                   // SCID length
		0x00, 0x00, 0x00, 0x01, // Supported version: v1
	}

	quic := &QUIC{}
	err := quic.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("DecodeFromBytes failed: %v", err)
	}

	if quic.PacketType != QUICPacketTypeVersionNegotiation {
		t.Errorf("PacketType = %v, want Version Negotiation", quic.PacketType)
	}
	if quic.Version != 0 {
		t.Errorf("Version = %d, want 0", quic.Version)
	}
}

func TestQUICRetryPacket(t *testing.T) {
	data := []byte{
		0xf0,                   // Long header, Retry packet (bits 4-5 = 11)
		0x00, 0x00, 0x00, 0x01, // Version 1
		0x08,                                           // DCID length
		0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, // DCID
		0x00,                                                                                                       // SCID length
		0xde, 0xad, 0xbe, 0xef,                                                                                     // Token
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Integrity tag (16 bytes)
	}

	quic := &QUIC{}
	err := quic.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("DecodeFromBytes failed: %v", err)
	}

	if quic.PacketType != QUICPacketTypeRetry {
		t.Errorf("PacketType = %v, want Retry", quic.PacketType)
	}
	if !bytes.Equal(quic.Token, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Errorf("Token = %x, want deadbeef", quic.Token)
	}
}

func TestQUICInvalidPacket(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty packet", []byte{}},
		{"truncated long header", []byte{0xc0, 0x00, 0x00}},
		{"truncated DCID", []byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x01}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			quic := &QUIC{}
			err := quic.DecodeFromBytes(tt.data, gopacket.NilDecodeFeedback)
			if err == nil {
				t.Error("Expected error for invalid packet, got nil")
			}
		})
	}
}

func TestQUICLayerType(t *testing.T) {
	quic := &QUIC{}
	if quic.LayerType() != LayerTypeQUIC {
		t.Errorf("LayerType() = %v, want LayerTypeQUIC", quic.LayerType())
	}
	if quic.CanDecode() != LayerTypeQUIC {
		t.Errorf("CanDecode() = %v, want LayerTypeQUIC", quic.CanDecode())
	}
	if quic.NextLayerType() != gopacket.LayerTypePayload {
		t.Errorf("NextLayerType() = %v, want LayerTypePayload", quic.NextLayerType())
	}
}
