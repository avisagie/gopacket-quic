# QUIC Layer Implementation Plan for GoPacket

## Project Goal
Implement a basic, stateless QUIC layer for the `google/gopacket` library that supports:
- QUIC v1 (RFC 9000) packet parsing
- Initial packet decryption (stateless, using DCID-derived keys per RFC 9001)
- Frame parsing within decrypted payloads
- Clean integration with GoPacket's layer architecture

## Design Principles

1. **Stateless per-packet decoding** - no connection tracking, no reassembly
2. **GoPacket conventions** - follow existing layer patterns (TCP, UDP, DNS, etc.)
3. **Frames are structs, not layers** - QUIC frames are data structures within the QUIC layer
4. **RFC 9000/9001 compliance** - focus on QUIC v1 standard
5. **Cybersecurity use case** - enable TLS ClientHello extraction from Initial packets

## Architecture

### File Structure
```
gopacket/layers/
├── quic.go              # Main QUIC layer implementation
├── quic_crypto.go       # Initial packet decryption (RFC 9001)
├── quic_frames.go       # Frame type definitions and parsing
├── quic_varint.go       # Variable-length integer codec
├── quic_test.go         # Unit tests
└── quic_crypto_test.go  # Decryption tests with RFC test vectors
```

### Core Types

```go
// Main QUIC Layer
type QUIC struct {
    BaseLayer
    
    // Header fields
    HeaderForm      bool   // true = long header, false = short header
    FixedBit        bool
    PacketType      QUICPacketType // Initial, 0-RTT, Handshake, Retry, 1-RTT
    Version         uint32
    DCID            []byte
    SCID            []byte
    Token           []byte // For Initial and Retry packets
    PacketNumberLen uint8  // 1-4 bytes
    PacketNumber    uint64
    
    // Payload
    Frames           []QUICFrame
    DecryptedPayload []byte
    DecryptionError  error // If decryption failed
}

// Packet Types
type QUICPacketType uint8
const (
    QUICPacketTypeInitial QUICPacketType = iota
    QUICPacketType0RTT
    QUICPacketTypeHandshake
    QUICPacketTypeRetry
    QUICPacketType1RTT
)

// Frame Interface
type QUICFrame interface {
    FrameType() uint8
}

// Frame Types
type PaddingFrame struct{}
type PingFrame struct{}
type AckFrame struct {
    LargestAcknowledged uint64
    AckDelay            uint64
    AckRanges           []AckRange
}
type AckRange struct {
    Gap    uint64
    Length uint64
}
type CryptoFrame struct {
    Offset uint64
    Length uint64
    Data   []byte
}
type StreamFrame struct {
    StreamID uint64
    Offset   uint64
    Length   uint64
    Data     []byte
    Fin      bool
}
type ConnectionCloseFrame struct {
    ErrorCode   uint64
    FrameType   uint64
    ReasonPhrase string
}
```

## Implementation Checklist

### Phase 1: Foundation (Priority 1)

- [ ] **VARINT codec** (`quic_varint.go`)
  - [ ] `DecodeVarint(data []byte) (value uint64, length int, err error)`
  - [ ] `EncodeVarint(value uint64) []byte`
  - [ ] Unit tests with edge cases (0, 1, max values)

- [ ] **Layer registration**
  - [ ] Register `LayerTypeQUIC` with gopacket
  - [ ] Implement `gopacket.Layer` interface
  - [ ] Implement `gopacket.DecodingLayer` interface
  - [ ] Register for decoding from UDP port 443 (default QUIC port)

- [ ] **Long header parsing** (`quic.go`)
  - [ ] Header form bit detection
  - [ ] Fixed bit validation
  - [ ] Packet type extraction (2 bits)
  - [ ] Version parsing (4 bytes)
  - [ ] DCID length + DCID extraction
  - [ ] SCID length + SCID extraction
  - [ ] Token parsing for Initial packets (varint length + data)
  - [ ] Packet length parsing (varint)
  - [ ] Packet number length determination (protected, 2 bits)

### Phase 2: Initial Packet Decryption (Priority 1)

- [ ] **Key derivation** (`quic_crypto.go`)
  - [ ] RFC 9001 initial salt constant (v1: `0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a`)
  - [ ] `DeriveInitialSecrets(dcid []byte) (clientSecret, serverSecret []byte)`
    - [ ] HKDF-Extract with salt and DCID
    - [ ] HKDF-Expand for client_initial_secret
    - [ ] HKDF-Expand for server_initial_secret
  - [ ] `DeriveTrafficKeys(secret []byte) (key, iv, hp []byte)`
    - [ ] Derive AEAD key (AES-128)
    - [ ] Derive AEAD IV (12 bytes)
    - [ ] Derive header protection key (16 bytes)

- [ ] **Header protection removal** (`quic_crypto.go`)
  - [ ] `RemoveHeaderProtection(packet []byte, hpKey []byte) (pnLength int, pn uint64, err error)`
  - [ ] Extract sample (16 bytes starting 4 bytes after packet number field)
  - [ ] Generate mask using AES-ECB with hp key
  - [ ] XOR first byte to reveal packet number length
  - [ ] XOR packet number bytes to reveal actual packet number

- [ ] **Payload decryption** (`quic_crypto.go`)
  - [ ] `DecryptPayload(encryptedPayload, header []byte, pn uint64, key, iv []byte) ([]byte, error)`
  - [ ] Construct nonce = IV XOR packet_number (padded to 12 bytes)
  - [ ] Use AES-128-GCM with associated data = QUIC header
  - [ ] Return decrypted payload or error

- [ ] **Integration into DecodeFromBytes**
  - [ ] Detect Initial packet type
  - [ ] Derive keys from DCID
  - [ ] Remove header protection to get packet number
  - [ ] Decrypt payload
  - [ ] Store decrypted payload and proceed to frame parsing

### Phase 3: Frame Parsing (Priority 1)

- [ ] **Frame parsing loop** (`quic_frames.go`)
  - [ ] `ParseFrames(payload []byte) ([]QUICFrame, error)`
  - [ ] Iterate through payload, reading frame type (varint)
  - [ ] Dispatch to frame-specific parser based on type
  - [ ] Handle multiple frames in single packet

- [ ] **Essential frame parsers** (`quic_frames.go`)
  - [ ] **PADDING** (0x00) - skip bytes
  - [ ] **PING** (0x01) - no payload
  - [ ] **ACK** (0x02-0x03)
    - [ ] Largest Acknowledged (varint)
    - [ ] ACK Delay (varint)
    - [ ] ACK Range Count (varint)
    - [ ] First ACK Range (varint)
    - [ ] Additional ACK Ranges (Gap + Length pairs)
  - [ ] **CRYPTO** (0x06) ⭐ **CRITICAL**
    - [ ] Offset (varint)
    - [ ] Length (varint)
    - [ ] Data (length bytes)
  - [ ] **CONNECTION_CLOSE** (0x1c-0x1d)
    - [ ] Error Code (varint)
    - [ ] Frame Type (varint, only for 0x1c)
    - [ ] Reason Phrase Length (varint)
    - [ ] Reason Phrase (string)

- [ ] **Optional but useful frame parsers**
  - [ ] **STREAM** (0x08-0x0f)
    - [ ] Parse flags from frame type byte (OFF, LEN, FIN)
    - [ ] Stream ID (varint)
    - [ ] Offset (varint, if OFF flag)
    - [ ] Length (varint, if LEN flag)
    - [ ] Data

### Phase 4: Testing (Priority 1)

- [ ] **RFC test vectors** (`quic_crypto_test.go`)
  - [ ] Use RFC 9001 Appendix A test vectors
  - [ ] Test key derivation with known DCID
  - [ ] Test header protection removal
  - [ ] Test payload decryption
  - [ ] Verify against expected output

- [ ] **Packet parsing tests** (`quic_test.go`)
  - [ ] Initial packet with CRYPTO frame containing ClientHello
  - [ ] Retry packet
  - [ ] Version Negotiation packet
  - [ ] Malformed packets (error handling)
  - [ ] Multiple frames in single packet

- [ ] **Integration tests**
  - [ ] Capture real QUIC Initial packet from Chrome/Firefox
  - [ ] Parse and decrypt with gopacket
  - [ ] Verify CRYPTO frame extraction
  - [ ] Compare with Wireshark dissector output

### Phase 5: Short Header Support (Priority 2 - Document Limitations)

- [ ] **Short header parsing** (`quic.go`)
  - [ ] Header form = 0
  - [ ] Extract Spin bit, Key Phase bit, Packet Number Length
  - [ ] Parse DCID (no length field - requires connection state)
  - [ ] Parse Packet Number (1-4 bytes, protected)
  - [ ] **Document**: Decryption requires connection state (out of scope)

- [ ] **LayerPayload() behavior**
  - [ ] For decrypted Initial packets: return decrypted payload
  - [ ] For other packets: return encrypted payload
  - [ ] Document that users need external state for reassembly

### Phase 6: Polish (Priority 3)

- [ ] **Error handling**
  - [ ] Graceful handling of decryption failures
  - [ ] Store error in `DecryptionError` field
  - [ ] Continue parsing what's possible
  - [ ] Log parse errors appropriately

- [ ] **Documentation**
  - [ ] Package-level godoc
  - [ ] Per-function documentation
  - [ ] Example usage in godoc
  - [ ] README section on QUIC support and limitations

- [ ] **Performance**
  - [ ] Minimize allocations in hot paths
  - [ ] Benchmark critical functions (varint, decryption)
  - [ ] Profile with real packet captures

- [ ] **Version support**
  - [ ] Explicitly support QUIC v1 (0x00000001)
  - [ ] Detect Version Negotiation (0x00000000)
  - [ ] Optionally add QUIC v2 support (0x6b3343cf)

## Key Dependencies

- `crypto/aes` - AES-128 for AEAD and header protection
- `crypto/cipher` - GCM mode
- `crypto/sha256` - For HKDF
- `golang.org/x/crypto/hkdf` - Key derivation
- `github.com/google/gopacket` - Layer interface

## What This Implementation Does NOT Include

❌ **Handshake packet decryption** - requires server keys (connection state)  
❌ **1-RTT packet decryption** - requires negotiated keys (connection state)  
❌ **CRYPTO frame reassembly** - stateful operation across packets  
❌ **TLS ClientHello parsing** - users can use TLS libraries on extracted data  
❌ **Connection tracking** - not GoPacket's responsibility  
❌ **Loss detection, congestion control** - transport logic  
❌ **Connection migration, path validation** - connection management  

## Usage Example

```go
package main

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

func main() {
    handle, _ := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    
    for packet := range packetSource.Packets() {
        quicLayer := packet.Layer(layers.LayerTypeQUIC)
        if quicLayer != nil {
            quic := quicLayer.(*layers.QUIC)
            
            if quic.PacketType == layers.QUICPacketTypeInitial {
                fmt.Printf("Initial packet, DCID: %x\n", quic.DCID)
                
                for _, frame := range quic.Frames {
                    if cf, ok := frame.(*layers.CryptoFrame); ok {
                        fmt.Printf("CRYPTO frame at offset %d, length %d\n", 
                            cf.Offset, cf.Length)
                        // TLS ClientHello is in cf.Data
                        // User must handle reassembly if fragmented
                    }
                }
            }
        }
    }
}
```

## Success Criteria

✅ Can parse QUIC v1 Initial packets  
✅ Can decrypt Initial packet payloads using DCID  
✅ Can extract CRYPTO frames with TLS data  
✅ Passes all RFC 9001 test vectors  
✅ Clean GoPacket layer interface implementation  
✅ Comprehensive unit test coverage  
✅ Documented limitations for stateful operations  

## References

- RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
- RFC 9001: Using TLS to Secure QUIC
- RFC 9002: QUIC Loss Detection and Congestion Control
- GoPacket documentation: https://pkg.go.dev/github.com/google/gopacket

