# GoPacket - Claude Context Document

## Project Overview
GoPacket is a Go library for packet decoding and processing. It provides comprehensive support for parsing network packets across various protocols (Ethernet, IP, TCP, UDP, TLS, DNS, etc.).

**Repository**: `github.com/google/gopacket`
**Language**: Go (minimum version 1.5, some features require 1.9+)
**License**: BSD-style

## Core Architecture

### Layer System
GoPacket uses a layered approach to packet decoding:
- **Layer Interface**: Base interface for all protocol layers (`base.go:19-27`)
- **Layer Types**: LinkLayer (L2), NetworkLayer (L3), TransportLayer (L4), ApplicationLayer (L7)
- **Lazy Decoding**: Packets can be decoded on-demand to improve performance

### Key Components

#### 1. Base Package (`/`)
- `base.go` - Layer interface definitions
- `decode.go` - Decoding infrastructure
- `packet.go` - Core packet types and handling (26KB)
- `parser.go` - Packet parsing logic (12KB)
- `layertype.go` - Layer type registration system
- `layerclass.go` - Layer classification
- `flows.go` - Network flow tracking

#### 2. Layers Package (`/layers`)
Contains 131+ files implementing various protocols:
- **Transport**: `tcp.go`, `udp.go`, `sctp.go`, `rudp.go`, `udplite.go`
- **Application**: `tls*.go`, `dns.go`, HTTP assembly, etc.
- **Network**: IPv4, IPv6, ICMP, ARP, etc.
- **Link**: Ethernet, 802.11 (WiFi), etc.

#### 3. Packet Sources
- `pcap/` - libpcap bindings for live capture
- `pcapgo/` - Pure Go pcap file reading
- `afpacket/` - Linux AF_PACKET interface
- `pfring/` - PF_RING support
- `bsdbpf/` - BSD BPF support

#### 4. Processing
- `tcpassembly/` - TCP stream reassembly
- `reassembly/` - Generic reassembly framework
- `ip4defrag/` - IPv4 defragmentation
- `defrag/` - Generic defragmentation

## TLS Implementation (Reference for QUIC)

The TLS implementation spans multiple files in `/layers`:

### Main Files
1. **tls.go** (284 lines) - Core TLS layer structure
   - `TLS` struct with slices for different record types
   - `TLSRecordHeader` - Common header for all TLS records
   - `decodeTLS()` - Entry point decoder function
   - `decodeTLSRecords()` - Recursive record parsing
   - `SerializeTo()` - Packet serialization

2. **tls_alert.go** - Alert record handling
   - Alert levels and descriptions
   - String representations

3. **tls_appdata.go** - Application data records
   - Encrypted payload handling

4. **tls_cipherspec.go** - ChangeCipherSpec records
   - Simple 1-byte message handling

5. **tls_handshake.go** - Handshake records
   - Mostly TODO (basic structure only)

6. **tls_test.go** - Unit tests

### TLS Layer Pattern
```go
// 1. Define record types as constants
type TLSType uint8
const (
    TLSChangeCipherSpec TLSType = 20
    TLSAlert            TLSType = 21
    // ...
)

// 2. Main layer struct holds slices of different record types
type TLS struct {
    BaseLayer
    ChangeCipherSpec []TLSChangeCipherSpecRecord
    Handshake        []TLSHandshakeRecord
    AppData          []TLSAppDataRecord
    Alert            []TLSAlertRecord
}

// 3. Each record type embeds TLSRecordHeader
type TLSRecordHeader struct {
    ContentType TLSType
    Version     TLSVersion
    Length      uint16
}

// 4. Implement decodeFromBytes for each record type
func (t *TLSAlertRecord) decodeFromBytes(h TLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error

// 5. Main decoder recursively processes multiple records
func (t *TLS) decodeTLSRecords(data []byte, df gopacket.DecodeFeedback) error
```

### Layer Registration
In `layertypes.go:144`:
```go
LayerTypeTLS = gopacket.RegisterLayerType(140,
    gopacket.LayerTypeMetadata{Name: "TLS", Decoder: gopacket.DecodeFunc(decodeTLS)})
```

### Port Mapping
In `ports.go:62-74`, TLS is automatically decoded for well-known ports:
```go
var tcpPortLayerType = [65536]gopacket.LayerType{
    443:  LayerTypeTLS,  // https
    636:  LayerTypeTLS,  // ldaps
    989:  LayerTypeTLS,  // ftps-data
    990:  LayerTypeTLS,  // ftps
    992:  LayerTypeTLS,  // telnets
    993:  LayerTypeTLS,  // imaps
    994:  LayerTypeTLS,  // ircs
    995:  LayerTypeTLS,  // pop3s
    5061: LayerTypeTLS,  // sips
}
```

## Adding QUIC Support - Implementation Plan

QUIC (Quick UDP Internet Connections) is a transport protocol developed by Google, now standardized as RFC 9000. It runs over UDP and provides features similar to TCP+TLS but with improved performance.

### QUIC Protocol Characteristics
- **Transport**: UDP-based (default port 443)
- **Encryption**: Built-in TLS 1.3 (cannot be disabled)
- **Multiplexing**: Multiple streams in single connection
- **Header Format**:
  - Long header (initial packets): flags, version, DCID, SCID, payload length
  - Short header (established): flags, DCID, packet number, encrypted payload
- **Version**: Currently QUIC v1 (0x00000001), also supports v2 (0x6b3343cf)

### Files to Create

1. **layers/quic.go** - Main QUIC layer (similar to tls.go)
   ```go
   type QUIC struct {
       BaseLayer
       HeaderForm      QUICHeaderForm  // Long or Short
       LongHeader      *QUICLongHeader
       ShortHeader     *QUICShortHeader
       Payload         []byte // Encrypted payload
   }
   ```

2. **layers/quic_long_header.go** - Long header format
   - Initial, 0-RTT, Handshake, Retry packet types
   - Version negotiation
   - Connection IDs (DCID, SCID)

3. **layers/quic_short_header.go** - Short header format (1-RTT)
   - Minimal header for established connections
   - Spin bit, key phase

4. **layers/quic_frames.go** (optional but recommended)
   - Frame types: STREAM, ACK, CRYPTO, CONNECTION_CLOSE, etc.
   - Frame parsing from decrypted payload

5. **layers/quic_test.go** - Unit tests

### Integration Points

1. **Register Layer Type** in `layertypes.go`:
   ```go
   LayerTypeQUIC = gopacket.RegisterLayerType(XXX,
       gopacket.LayerTypeMetadata{Name: "QUIC", Decoder: gopacket.DecodeFunc(decodeQUIC)})
   ```

2. **UDP Port Mapping** in `ports.go`:
   ```go
   var udpPortLayerType = [65536]gopacket.LayerType{
       443:  LayerTypeQUIC,  // QUIC over HTTPS port
       // Add other common QUIC ports
   }
   ```

3. **Detection Logic**: QUIC packets start with specific bit patterns:
   - Long header: First bit = 1
   - Short header: First bit = 0
   - Version field helps confirm QUIC vs. other UDP traffic

### Implementation Notes

- **Start Simple**: Focus on header parsing first, payload will be encrypted
- **Version Support**: Handle version negotiation packets
- **Connection IDs**: Variable length (0-20 bytes)
- **Packet Numbers**: Variable length encoding (1-4 bytes)
- **No Decryption**: Like TLS application data, QUIC payload is encrypted
  - Store as opaque `[]byte`
  - Full decryption requires TLS 1.3 key material (out of scope)

### Testing Resources
- RFC 9000 - QUIC: A UDP-Based Multiplexed and Secure Transport
- RFC 9001 - Using TLS to Secure QUIC
- RFC 9002 - QUIC Loss Detection and Congestion Control
- Wireshark QUIC captures for test data

## Development Workflow

### Building & Testing
```bash
# Run local checks (format, lint, vet, test)
./gc

# Run tests
go test ./...

# Run benchmarks
go test -bench=. ./...

# Run specific layer tests
go test ./layers -run TestTLS
```

### Code Style
- Must pass: `go fmt`, `go vet`, `golint`
- Follow [Effective Go](http://golang.org/doc/effective_go.html)
- Use CamelCase for enums with acronyms capitalized
- Export all public types/functions with comments
- Add `String()` methods to enum types

### Error Handling
- Always report errors via `return` or `ErrorLayer`
- Use `df.SetTruncated()` for incomplete packets
- Return partial layer data if useful before error
- Don't trust bytes after first error

### Performance Guidelines
- Minimize allocations - use `[]byte` slices from input
- Don't copy data unnecessarily
- Pre-allocate common-case structs
- Test with benchmarks for performance changes
- Focus optimization on common protocols

## Useful Commands

```bash
# Find layer implementations
ls layers/*.go | wc -l  # 131 files

# Search for specific patterns
grep -r "LayerType.*RegisterLayerType" layers/

# View examples
ls examples/

# Check git status
git status
```

## Current State (2025-10-09)
- Branch: master
- Clean working directory
- Recent commits include layer type updates and fuzzing fixes

## Next Steps for QUIC Implementation
1. Study QUIC RFC 9000 packet structure
2. Create `layers/quic.go` with basic QUIC struct
3. Implement long header parsing
4. Implement short header parsing
5. Register QUIC layer type
6. Add UDP port mapping (443)
7. Write tests with sample QUIC packets
8. Test against real QUIC traffic (Chrome, curl with HTTP/3)
