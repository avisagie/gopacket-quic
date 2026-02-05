// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
)

// QUIC Initial Packet Decryption (RFC 9001)
//
// This file implements stateless decryption of QUIC Initial packets using
// DCID-derived keys per RFC 9001. This allows extraction of CRYPTO frames
// containing TLS ClientHello from Initial packets without connection state.

// RFC 9001 Section 5.2 - Initial Secrets
// Salt for QUIC v1 (0x00000001)
var quicV1Salt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

// RFC 9001 Section 5.1 - Labels for HKDF-Expand
var (
	labelClientIn = []byte("client in")
	labelServerIn = []byte("server in")
	labelQUICKey  = []byte("quic key")
	labelQUICIV   = []byte("quic iv")
	labelQUICHP   = []byte("quic hp")
)

// hkdfExtract implements HKDF-Extract from RFC 5869
func hkdfExtract(h func() hash.Hash, secret, salt []byte) []byte {
	if salt == nil {
		salt = make([]byte, h().Size())
	}
	mac := hmac.New(h, salt)
	mac.Write(secret)
	return mac.Sum(nil)
}

// hkdfExpand implements HKDF-Expand from RFC 5869
func hkdfExpand(h func() hash.Hash, prk, info []byte, length int) []byte {
	hashLen := h().Size()
	n := (length + hashLen - 1) / hashLen

	if n > 255 {
		panic("hkdf: requested too much output")
	}

	var (
		t    []byte
		okm  = make([]byte, 0, n*hashLen)
		buf  = make([]byte, 0, hashLen+len(info)+1)
		mac  = hmac.New(h, prk)
	)

	for i := 1; i <= n; i++ {
		mac.Reset()
		buf = buf[:0]
		buf = append(buf, t...)
		buf = append(buf, info...)
		buf = append(buf, byte(i))
		mac.Write(buf)
		t = mac.Sum(nil)
		okm = append(okm, t...)
	}

	return okm[:length]
}

// hkdfExpandLabel implements HKDF-Expand-Label from RFC 8446 Section 7.1
func hkdfExpandLabel(secret []byte, label []byte, context []byte, length int) []byte {
	hkdfLabel := make([]byte, 0, 2+1+len("tls13 ")+len(label)+1+len(context))
	hkdfLabel = append(hkdfLabel, byte(length>>8), byte(length))
	hkdfLabel = append(hkdfLabel, byte(len("tls13 ")+len(label)))
	hkdfLabel = append(hkdfLabel, []byte("tls13 ")...)
	hkdfLabel = append(hkdfLabel, label...)
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)

	return hkdfExpand(sha256.New, secret, hkdfLabel, length)
}

// DeriveInitialSecrets derives client and server initial secrets from DCID
// using the QUIC v1 salt and HKDF-Extract (RFC 9001 Section 5.2)
func DeriveInitialSecrets(dcid []byte) (clientSecret, serverSecret []byte) {
	// Extract initial secret using HKDF-Extract with salt and DCID
	initialSecret := hkdfExtract(sha256.New, dcid, quicV1Salt)

	// Expand to client_initial_secret
	clientSecret = hkdfExpandLabel(initialSecret, labelClientIn, nil, 32)

	// Expand to server_initial_secret
	serverSecret = hkdfExpandLabel(initialSecret, labelServerIn, nil, 32)

	return clientSecret, serverSecret
}

// DeriveTrafficKeys derives AEAD key, IV, and header protection key from a traffic secret
// (RFC 9001 Section 5.1)
func DeriveTrafficKeys(secret []byte) (key, iv, hp []byte) {
	// Derive AEAD key (AES-128, 16 bytes)
	key = hkdfExpandLabel(secret, labelQUICKey, nil, 16)

	// Derive AEAD IV (12 bytes for GCM)
	iv = hkdfExpandLabel(secret, labelQUICIV, nil, 12)

	// Derive header protection key (16 bytes for AES-128)
	hp = hkdfExpandLabel(secret, labelQUICHP, nil, 16)

	return key, iv, hp
}

// RemoveHeaderProtection removes header protection from a QUIC packet
// and returns the packet number length and value (RFC 9001 Section 5.4)
//
// The packet parameter should contain the entire QUIC packet starting from the first byte.
// The pnOffset parameter indicates where the protected packet number field starts.
// The hpKey is the header protection key derived from the traffic secret.
func RemoveHeaderProtection(packet []byte, pnOffset int, hpKey []byte) (pnLength int, pn uint64, err error) {
	// Sample starts 4 bytes after the start of the packet number field
	sampleOffset := pnOffset + 4
	if sampleOffset+16 > len(packet) {
		return 0, 0, fmt.Errorf("packet too short for header protection sample: need %d bytes, have %d", sampleOffset+16, len(packet))
	}
	sample := packet[sampleOffset : sampleOffset+16]

	// Generate mask using AES-ECB
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, sample)

	// Unmask the first byte to get packet number length
	// For long headers: bits 0-1 are protected
	firstByte := packet[0] ^ (mask[0] & 0x0f)
	packet[0] = firstByte

	// Extract packet number length (last 2 bits of first byte)
	pnLength = int(firstByte&0x03) + 1

	// Verify we have enough bytes for packet number
	if pnOffset+pnLength > len(packet) {
		return 0, 0, fmt.Errorf("packet too short for packet number: need %d bytes, have %d", pnOffset+pnLength, len(packet))
	}

	// Unmask packet number bytes
	for i := 0; i < pnLength; i++ {
		packet[pnOffset+i] ^= mask[1+i]
	}

	// Decode packet number (big-endian)
	pn = 0
	for i := 0; i < pnLength; i++ {
		pn = (pn << 8) | uint64(packet[pnOffset+i])
	}

	return pnLength, pn, nil
}

// DecryptPayload decrypts a QUIC packet payload using AES-128-GCM
// (RFC 9001 Section 5.3)
//
// The header parameter should contain the entire packet header (before packet number through
// the end of packet number). The encryptedPayload is everything after the packet number.
// The pn is the packet number, and key/iv are derived from the traffic secret.
func DecryptPayload(header, encryptedPayload []byte, pn uint64, key, iv []byte) ([]byte, error) {
	// Create AES-128-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	// Construct nonce by XORing IV with packet number (RFC 9001 Section 5.3)
	nonce := make([]byte, 12)
	copy(nonce, iv)
	// Packet number is XORed into the last bytes of the IV
	pnBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(pnBytes, pn)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= pnBytes[i]
	}

	// Decrypt with associated data = packet header
	plaintext, err := aesgcm.Open(nil, nonce, encryptedPayload, header)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// GetSaltForVersion returns the initial salt for a given QUIC version
func GetSaltForVersion(version uint32) ([]byte, error) {
	switch version {
	case 0x00000001: // QUIC v1
		return quicV1Salt, nil
	default:
		return nil, fmt.Errorf("unsupported QUIC version: 0x%08x", version)
	}
}
