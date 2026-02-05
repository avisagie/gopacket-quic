// Copyright 2025 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source tree.

package layers

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"testing"

	"github.com/google/gopacket"
)

// All 3 Initial packets from Chrome connecting to gstatic.com
// CRYPTO frames must be reassembled across all 3 to get complete ClientHello
var realQUICInitialPacket2, _ = hex.DecodeString(
	"c10000000108f370ab999fcac10c0040560004939deec34bcbf02afc42f7017f6ea15f291157fe665fd1b851d298561a0bff93a9d9246f3dcc1980796bb84842700c98eeeee88e104ad3c80e9929e5bd9c338e326ee85286daac2c9cfe4cd3216579eca702b425447961be7f04a3d00233a4eba88571028f953f548fa3b05bd0dae69c12a5cd505366307bf0d3c60847b711e1853acf89a9dbfb3524b82db74ddbf985cf3c43ea11e15a65a69da49329c658c57fad42b98b8da014ddbde5c2647fa32d15d8ee0812face931dfcbce6b8f0cd58a1d33e6094497c30fa5a604f6c3fedd84eb3ac3aabc714efe27b24dbb20e942172afd299c66287b610abfd537ef0ef5843a673cf02ce102576ca5541b5019f69aa5bdd235cab156c0ec9e10e2c52cffc67c10e4a3727f5c6100f3d41cffb13c88242e252bea1701a85db7b3a3727ede654387e2698e8b469c91362bff5165f06ef67f86d506a09969d433f41e3fd99fb415d887295008a90b37e71f7ab43d17f8c71a313fd400757cced029203b01ffdc95e1f5f7aedf2200161e967def64640a7bba69852414be3b1d3d3d7250a5dd1a22f92e0f0218ab44f7d8a06234aae29a0da8377986ccd1e9088f1a27fb7d5454bff3c180a1f052f0331955c243456352e8823492d3e9dc285fe2e205455a1294d40f8627faae17a85f170291ba15bfddb248063638432e1fbab4e1f2d3a84428f57da34eeb13197c9c339de85c008f493689981529d1dbc8346a07db41b996c5fd961b534a0b1ccc845a089de082c35093d8d29e27a91655fb219e9ead68470ccec483eb23b0563844836658a3ce9133b48a27d7933d1403d76f645e83de0cf158c975748c92c439e16a56a1af404dca31ce7dcacfa989a891da3015040b8c1bbabe645a89b800c6baf8a6f51263f91486fde74b9e18d382e1ec5a7f94fa78123066fcc1ec4a9771a85c65bd2e771b19b8c6bc5702818ecbd476eab764534daae2a843b5c20d6b5ac68c6849235b2ee3a4a655f0e03d2efb2bfe8b5a956b3043579b902701b7f5a858f9b40ee31bfd63cbdb1fc9a8243c1d5d4efc80ffc7d3128cd027a6615b40fdb6514025d0c7b74a48fcdd7bebbb8a674c35a9bc713fbce2cbb83ce0731f8f2f202b8403308a6b2d41c1191d153b035e62a9b4fbd0fb97c3b3f471c495dac7860859d505fdf7e50982f2579533659f5bbec0e306ce2b5bde05759b0756c89be44ac05626a0b5bc4b11397d8a17e29b2c071f6ef3b2dbbc7c298c59e0f5566d5be1a95b2a9391224963995ca495b75f58ff7a0f8dc81e6a7b0d1f6547cfb09cbe8da5a47d65785d1fe0063418ee54b0f9ee9c7efd85245805dded43812f4b740bcad7d8b30e811105beebf41264a4cfc4a23298c733eaef958c0d5b0bef9dd9a2ba3cb39db206d29ba7c3247e762023fa8b5fc1977e4ccb4426fc20eab311ff1e284dd829e0ac0d09f1a895617620cf5eeaf0f48a9365b6978df0c6db44c99d5e684d685b84900ba1593cea4e7ff0cd3f0956eef0fd5e254a972a5f68e8f968da6a5162e6b2c71979ba4cde72a7e2a4a93deea444a06076d8114b8ac0fda8ef8bd406abdacf19a24743ee10f2622372535fc5b85fcd3017787a3e60a80cff45d65d6c916e525b6e7de3c461547ac131636ab2a6b493631397a758ca365421e97116fa0a44040915ebb32ae1d064e30b8d0bb649d04502fbb7b4996387df40177cf3b01cbdc7314292d85472a5a6c196eaddd29c8774be8")

var realQUICInitialPacket3, _ = hex.DecodeString(
	"cb0000000108f370ab999fcac10c0040560004939deec34bcbf02afc42f7017f6ea15f291157fe665fd1b851d298561a0bff93a9d9246f3dcc1980796bb84842700c98eeeee88e104ad3c80e9929e5bd9c338e326ee85286daac2c9cfe4cd3216579eca702b4254479c46f4cf2f1307beab06aade308208e72384ffa0818db61e1ca85ab50d62f30ba731004faffa3e14f6f3b70e462a7a55c33ed43576798eda9ca892240042d698737538ec1cacebe12e8aaba1538015be914cfca5ac2eabea9b4ed3d99f50ccfaa8baefea5dd59fbb7e99e2b6dbd30c13a55519067e77ba893d7a5536d0f59d7f0ab2453d4ad496b4c575fe248d978e722c6403b118d845899ef33bd77790705c02857f6c1940ba9e070e5abf155546ab1a3bd052eb5fa3ade977674fbc6d79f657a9d34671ef787108dfbb8b26864201709226b81d52b4069b6b9a6b0225fc473f158c0f006e375f4f575e455211c588bada518adc3f83ad9786e1f8b37d5468d03a82e99b794da19de4634bf3982c19959325100966d9c22a84f3b82763d8aaa48684276e25fbdb78be9b2124d7a67bb6a56ab7137562c322e68616310619b3601e64a7571d3b27222a5f4f0ef2342ddd3b4ddcc52b484dc87f90af0f37f807ac00ac3ae575df1a0b03cbb1830f4735650c6ba58914a3317e02e3603ef46b51cfe866e3bd0d7b135258fa0403aa45b768e82cfc77ecb803b7c84ad1a6a8d5eff80dbdeccf9b3c345d24a452412f1b1a27f5581f9fcd1d9a98106ffadb7166ed9c1e470203321d86ba0df4c573e1804d8bf2f456fcf0b836ab7a2075f35dcdaebbef46ce0813f990a1b9b95ea4827b91fa2b04b81374f1d2d15b2c7a03fa092fc1135f65f71a44a430c8ecefac240a7d647ca6ccc61562fb5b49b3567e5d7b376fa9c402a219dbbb2d0e2b512de34f91bf34cd4d7a2b97a06612849b7e88618978f778999a8089b00e1f1580f5b5445bb93f277166517c2bb7fc164f4322e43cc237dd5418e4468a9c03597f638152218418afaefcd759ed92137e4e8078139fd7399b061d4e3e5c4210b2438b85af5f65549cb58bcac7fcdfe08a0fee05d7a12d48cf9965df42247ff29f736018425d3cd753475fa5a228265e94018f9af1b15f54e4c49462fd3e7577c9dbd706edd679e50a1723be43be83fe9084ce1e42bb8aca0eb189c4a1d4a8d613a9350acc74868c5683c900f554c95e1200c6fd7f41b8332676bf0dae9a1d0977a7eb1b242b02ae260f86c974f77824d23bc04da40dc8932845f23ec7b8212c3a2a6afa42d92de70bcc5ac32e87ef88eab1f53b8f15ec83134c27eabd4a9fc90abe716f23b562f39c6927d0892d14394b4d753cbd0397142abad4f7204770d9ce58d551b015713c0731cb7abed6cdde65e913b20897601da5b04f5a977c6ba05aaee655c94489a9a2229e90ca3ba623cf1b95430fb9e7dd16f68af7a89c21721748d942e2637899572284663a794023f127a0aac49cdc621577d861cf58006991b56f8779f1bca1218564fcb2581afc1007d2b35ba4760e269fdeeb5cb5aa211854dd5210e4bde6aec1efafd54daf7bd57887402edc66766987a852023e345d704be3e87d4e3a67cc46c8bb11de6fa8cc325b6e770d4316eb6b8f384ae4f2a6b99a1829719f8dbe1266c2e84279a13f7f678ed2031f1534e2124414743dfa751bd57a902a65486b8ee0ca8c7e199647197274c5a71582bd3d10f7eb6dec39e84fae1b7b7f2fd566138f9093aa1c0c2")

// Real QUIC Initial packet captured from Chrome connecting to gstatic.com
// This is the first of 3 packets needed to reassemble the complete ClientHello
var realQUICInitialPacket1, _ = hex.DecodeString(
	"c30000000108f370ab999fcac10c0040560004939deec34bcbf02afc42f7017f6ea15f291157fe665fd1b851d298561a0bff93a9d9246f3dcc1980796bb84842700c98eeeee88e104ad3c80e9929e5bd9c338e326ee85286daac2c9cfe4cd3216579eca702b42544793cbd2b3fd5acf0fed016b8f6ad394bb9e96593b41746d3903e2c2fd4c720de15b4db1e5ed5e351d395086e28f766a3a3c5896d95c899e1e5ab802032681cba6ac09bde30094d2f87f91c9e3d3dcf8ea3169ff1dcbfab39d3c9fbc1b4ff7197e2b3020ea3d33656b2f55cb753a28ad26af6824c60f359c6ed07689dc996a9ef15fcdee2a2ddb4167c670a3506cc4395b7647eb5d64ffa3867ceb99209925284607e2ce04d4475d6e7c977ebe5b1c742d9177d4e223e62fa3e070757d2ab42c8e013b05e4ede551b2ab518cbcfd103c5ab2dd4a4a1f48fa6d7544f5bf4c11cc2857895f69875203c16fd3531901daa387f8d09c7f8a37360e0a6cc0a8a5e7bb71d00bbe221fc3cbcdf004f9e0ce25b043f26bb866e98ce3d822d67491ef3c567fc7e89aeb89369db326ec0c99f6aa85c02e04e11d7a082bb430390145c12b3d6d523f449e800b56cce1c136507fa0d8450f5cfa699e9d224bb3a920ad28c591c72004eba4c39e1532d33f75ddcf192ab873e9bc0bd21e1fcb039461956f398abb771ff41a3949df44c0531c103af361e9ada7c84708c033ebc5b5bd4f9420819582574a0b78468e247718500217a9f5cf4b686105b2bedbe9305bb486933381cfaaae826737d198b81850f28d636877aab910274ffaa9c6cbfa39ea96e3d89aeeacaa36aaea494d5aa115cb51b666aef8a0cede274900cbd183ec0ecd9c20f9759129379a81f6afa15ec8d5d672fcbaeedd337059e270b6443ea9121484a4690afb40689553d17d7985d1fce64a68a3ece12d067c49d11dc370092c742cd34bc9c162559fda7fc605ca322b2f5cda8dd73e0d0d88aa3480c1f461473dc143eb92d711f1244f71af3955ad918592c77b2bdcb42e2d74ad8cf03eb9e332627622840b4bf067ef60063008b359b5f5c4025f47b3c81f938e294d60b380061706e1b61a64cc6434465de36cf7effb87b95f1cbddc2e1b741853dc8c756140724d43408c54a805da9b44b9c00411326ea9f58725bad78bce5567ae2970a985b671a18f905ba34b4edce14abf0d8516e1f1f18435e83ce3f83bdc42b22881c77fc0ecbefd9fa10f33db0108ab6a2a37a95fd6d37642142ebfc44a2ff9ad8dbf8ec8745f6d344e81a10e5995807fe715f555896765198544bd79f9a775b9d5c9c3be5daccbb3bff4438ea95a64c0bbb3677f51b9ffd6499a1054239906d7b3f2c3f91dd27201b5784a35fdac846cdd5e5ab9cc6a3bcffadcbe3e9aa4ea218b99c41365e46171ccc3337fe3cc247be4b24a28b5d192c18a78aeafea9876b11f7ffaadd9f88622744b2de4eb85c62abf3ff9bf7a1ac33953bf6b9b3d1aea385451722ad0e94bb853318c96addf8aa78a66f51ed75fbc5cb8bf9ca408ec9f9bcee0588a95ae8475d13324ceee0d937e050ad9cc688b4176a7809cd08bc8d1b44ea9458df3b759dd377d88ee9377a5eafb45995e8f6c9c9942345c1e5ddcf24b4b86e564f0eec3a072e8c42d8b8985fd0756fd060fbf1b8a53d4f5cd391c264b118416c014c320998165e45a774313197985082e42d7a6211660a991913e428ffeed29e2e6b0bb3947abcf0759100abc1694580c9246457fe16919d867b07f9")

func TestQUICRealInitialPacket(t *testing.T) {
	quic := &QUIC{}
	err := quic.DecodeFromBytes(realQUICInitialPacket1, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("DecodeFromBytes failed: %v", err)
	}

	// Verify header fields
	if !quic.HeaderForm {
		t.Error("Expected long header (HeaderForm=true)")
	}
	if quic.PacketType != QUICPacketTypeInitial {
		t.Errorf("PacketType = %v, want Initial", quic.PacketType)
	}
	if quic.Version != 0x00000001 {
		t.Errorf("Version = 0x%08x, want 0x00000001", quic.Version)
	}

	// Verify DCID
	expectedDCID, _ := hex.DecodeString("f370ab999fcac10c")
	if string(quic.DCID) != string(expectedDCID) {
		t.Errorf("DCID = %x, want %x", quic.DCID, expectedDCID)
	}

	// Verify token is present (this Initial has a retry token)
	if len(quic.Token) == 0 {
		t.Error("Expected non-empty token")
	}
	t.Logf("Token length: %d bytes", len(quic.Token))

	// Check decryption result
	if quic.DecryptionError != nil {
		t.Logf("Decryption error (may be expected): %v", quic.DecryptionError)
	}

	if quic.DecryptedPayload != nil {
		t.Logf("Successfully decrypted %d bytes", len(quic.DecryptedPayload))
	}

	// Check for parsed frames
	if len(quic.Frames) > 0 {
		t.Logf("Parsed %d frames:", len(quic.Frames))
		for i, frame := range quic.Frames {
			switch f := frame.(type) {
			case *QUICCryptoFrame:
				t.Logf("  Frame %d: CRYPTO offset=%d length=%d", i, f.Offset, f.Length)
			case *QUICPaddingFrame:
				t.Logf("  Frame %d: PADDING length=%d", i, f.Length)
			case *QUICPingFrame:
				t.Logf("  Frame %d: PING", i)
			case *QUICAckFrame:
				t.Logf("  Frame %d: ACK largest=%d", i, f.LargestAcknowledged)
			default:
				t.Logf("  Frame %d: type=0x%02x", i, frame.FrameType())
			}
		}
	} else if quic.DecryptedPayload == nil {
		t.Log("No frames parsed (decryption may have failed)")
	}
}

func TestQUICRealPacketKeyDerivation(t *testing.T) {
	// Test that we can derive the correct keys for this DCID
	dcid, _ := hex.DecodeString("f370ab999fcac10c")
	
	clientSecret, serverSecret := DeriveInitialSecrets(dcid)
	
	t.Logf("Client Initial Secret: %x", clientSecret)
	t.Logf("Server Initial Secret: %x", serverSecret)
	
	key, iv, hp := DeriveTrafficKeys(clientSecret)
	
	t.Logf("Client Key: %x", key)
	t.Logf("Client IV: %x", iv)
	t.Logf("Client HP: %x", hp)
	
	// Verify key lengths
	if len(key) != 16 {
		t.Errorf("Key length = %d, want 16", len(key))
	}
	if len(iv) != 12 {
		t.Errorf("IV length = %d, want 12", len(iv))
	}
	if len(hp) != 16 {
		t.Errorf("HP length = %d, want 16", len(hp))
	}
}

// parseClientHelloSNI extracts the SNI (Server Name Indication) from a TLS ClientHello.
// The input should be the raw handshake message starting with the handshake type byte.
// Returns empty string if SNI extension is not found.
func parseClientHelloSNI(data []byte) (string, error) {
	if len(data) < 4 {
		return "", fmt.Errorf("data too short for handshake header")
	}

	// Handshake header
	handshakeType := data[0]
	if handshakeType != 0x01 {
		return "", fmt.Errorf("not a ClientHello (type=0x%02x)", handshakeType)
	}
	handshakeLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+handshakeLen {
		return "", fmt.Errorf("incomplete ClientHello")
	}

	// ClientHello body starts at offset 4
	offset := 4

	// Version (2 bytes)
	if offset+2 > len(data) {
		return "", fmt.Errorf("truncated at version")
	}
	offset += 2

	// Random (32 bytes)
	if offset+32 > len(data) {
		return "", fmt.Errorf("truncated at random")
	}
	offset += 32

	// Session ID
	if offset+1 > len(data) {
		return "", fmt.Errorf("truncated at session ID length")
	}
	sessionIDLen := int(data[offset])
	offset++
	if offset+sessionIDLen > len(data) {
		return "", fmt.Errorf("truncated at session ID")
	}
	offset += sessionIDLen

	// Cipher Suites
	if offset+2 > len(data) {
		return "", fmt.Errorf("truncated at cipher suites length")
	}
	cipherSuitesLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	if offset+cipherSuitesLen > len(data) {
		return "", fmt.Errorf("truncated at cipher suites")
	}
	offset += cipherSuitesLen

	// Compression Methods
	if offset+1 > len(data) {
		return "", fmt.Errorf("truncated at compression methods length")
	}
	compMethodsLen := int(data[offset])
	offset++
	if offset+compMethodsLen > len(data) {
		return "", fmt.Errorf("truncated at compression methods")
	}
	offset += compMethodsLen

	// Extensions
	if offset+2 > len(data) {
		return "", fmt.Errorf("truncated at extensions length")
	}
	extensionsLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	extensionsEnd := offset + extensionsLen
	if extensionsEnd > len(data) {
		return "", fmt.Errorf("truncated at extensions")
	}

	// Parse extensions looking for SNI (type 0x0000)
	for offset+4 <= extensionsEnd {
		extType := int(data[offset])<<8 | int(data[offset+1])
		extLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		if offset+extLen > extensionsEnd {
			return "", fmt.Errorf("truncated extension")
		}

		if extType == 0x0000 { // server_name extension
			// Server Name List
			if extLen < 2 {
				return "", fmt.Errorf("SNI extension too short")
			}
			// listLen := int(data[offset])<<8 | int(data[offset+1])
			offset += 2

			// Server Name entry
			if offset+3 > extensionsEnd {
				return "", fmt.Errorf("truncated SNI entry")
			}
			nameType := data[offset]
			nameLen := int(data[offset+1])<<8 | int(data[offset+2])
			offset += 3

			if nameType == 0x00 { // host_name
				if offset+nameLen > extensionsEnd {
					return "", fmt.Errorf("truncated SNI hostname")
				}
				return string(data[offset : offset+nameLen]), nil
			}
		}

		offset += extLen
	}

	return "", nil // SNI not found
}

// TestQUICCryptoReassembly tests reassembling CRYPTO frames across multiple packets
// to reconstruct the complete TLS ClientHello
func TestQUICCryptoReassembly(t *testing.T) {
	packets := [][]byte{realQUICInitialPacket1, realQUICInitialPacket2, realQUICInitialPacket3}

	// Collect all CRYPTO frames from all packets
	type cryptoFragment struct {
		offset uint64
		data   []byte
	}
	var fragments []cryptoFragment

	for i, packetData := range packets {
		quic := &QUIC{}
		err := quic.DecodeFromBytes(packetData, gopacket.NilDecodeFeedback)
		if err != nil {
			t.Fatalf("Packet %d: DecodeFromBytes failed: %v", i+1, err)
		}

		if quic.DecryptionError != nil {
			t.Fatalf("Packet %d: Decryption failed: %v", i+1, quic.DecryptionError)
		}

		for _, frame := range quic.Frames {
			if cf, ok := frame.(*QUICCryptoFrame); ok {
				fragments = append(fragments, cryptoFragment{
					offset: cf.Offset,
					data:   cf.Data,
				})
			}
		}
	}

	t.Logf("Collected %d CRYPTO fragments", len(fragments))

	// Sort fragments by offset
	sort.Slice(fragments, func(i, j int) bool {
		return fragments[i].offset < fragments[j].offset
	})

	// Find the maximum offset + length to determine buffer size
	var maxEnd uint64
	for _, f := range fragments {
		end := f.offset + uint64(len(f.data))
		if end > maxEnd {
			maxEnd = end
		}
	}

	// Reassemble CRYPTO data
	reassembled := make([]byte, maxEnd)
	for _, f := range fragments {
		copy(reassembled[f.offset:], f.data)
	}

	t.Logf("Reassembled %d bytes of CRYPTO data", len(reassembled))

	// Verify it's a TLS ClientHello
	// CRYPTO frames contain raw TLS handshake messages (no record layer)
	// ClientHello: type=0x01, length=3 bytes (24-bit big-endian)
	if len(reassembled) < 4 {
		t.Fatal("Reassembled data too short for TLS handshake header")
	}

	handshakeType := reassembled[0]
	handshakeLen := uint32(reassembled[1])<<16 | uint32(reassembled[2])<<8 | uint32(reassembled[3])

	t.Logf("TLS Handshake: type=0x%02x, length=%d", handshakeType, handshakeLen)

	if handshakeType != 0x01 {
		t.Errorf("Expected ClientHello (type=0x01), got type=0x%02x", handshakeType)
	}

	// Expected length is 2238 bytes (from tshark output)
	if handshakeLen != 2238 {
		t.Logf("Note: Handshake length=%d (expected 2238 from tshark)", handshakeLen)
	}

	// Verify we have enough data for the full ClientHello
	if uint32(len(reassembled)) < 4+handshakeLen {
		t.Errorf("Incomplete ClientHello: have %d bytes, need %d", len(reassembled), 4+handshakeLen)
	} else {
		t.Logf("Complete ClientHello reassembled successfully!")
	}

	// Parse some ClientHello fields as additional verification
	// ClientHello structure after type+length:
	//   - Version: 2 bytes (offset 4)
	//   - Random: 32 bytes (offset 6)
	//   - Session ID length: 1 byte (offset 38)
	if len(reassembled) >= 39 {
		version := binary.BigEndian.Uint16(reassembled[4:6])
		sessionIDLen := reassembled[38]
		t.Logf("ClientHello: version=0x%04x, sessionIDLen=%d", version, sessionIDLen)

		// TLS 1.2 in legacy field (actual version in supported_versions extension)
		if version != 0x0303 {
			t.Logf("Note: Legacy version=0x%04x (expected 0x0303 for TLS 1.3 ClientHello)", version)
		}
	}

	// Extract and verify SNI
	sni, err := parseClientHelloSNI(reassembled)
	if err != nil {
		t.Fatalf("Failed to parse SNI: %v", err)
	}

	t.Logf("SNI (Server Name): %s", sni)

	expectedSNI := "ssl.gstatic.com"
	if sni != expectedSNI {
		t.Errorf("SNI = %q, want %q", sni, expectedSNI)
	}
}
