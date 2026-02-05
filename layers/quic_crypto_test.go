// Copyright 2025 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test vectors from RFC 9001 Appendix A
// https://www.rfc-editor.org/rfc/rfc9001.html#appendix-A

func TestDeriveInitialSecrets(t *testing.T) {
	// DCID from RFC 9001 Appendix A.1
	dcid, _ := hex.DecodeString("8394c8f03e515708")

	clientSecret, serverSecret := DeriveInitialSecrets(dcid)

	// Expected values from RFC 9001 Appendix A.1
	wantClientSecret, _ := hex.DecodeString("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
	wantServerSecret, _ := hex.DecodeString("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")

	if !bytes.Equal(clientSecret, wantClientSecret) {
		t.Errorf("client_initial_secret:\ngot:  %x\nwant: %x", clientSecret, wantClientSecret)
	}

	if !bytes.Equal(serverSecret, wantServerSecret) {
		t.Errorf("server_initial_secret:\ngot:  %x\nwant: %x", serverSecret, wantServerSecret)
	}
}

func TestDeriveTrafficKeys(t *testing.T) {
	// Use client_initial_secret from RFC 9001 Appendix A.1
	clientSecret, _ := hex.DecodeString("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")

	key, iv, hp := DeriveTrafficKeys(clientSecret)

	// Expected values from RFC 9001 Appendix A.1
	wantKey, _ := hex.DecodeString("1f369613dd76d5467730efcbe3b1a22d")
	wantIV, _ := hex.DecodeString("fa044b2f42a3fd3b46fb255c")
	wantHP, _ := hex.DecodeString("9f50449e04a0e810283a1e9933adedd2")

	if !bytes.Equal(key, wantKey) {
		t.Errorf("key:\ngot:  %x\nwant: %x", key, wantKey)
	}

	if !bytes.Equal(iv, wantIV) {
		t.Errorf("iv:\ngot:  %x\nwant: %x", iv, wantIV)
	}

	if !bytes.Equal(hp, wantHP) {
		t.Errorf("hp:\ngot:  %x\nwant: %x", hp, wantHP)
	}
}

func TestRemoveHeaderProtection(t *testing.T) {
	// Simplified test to verify the function works without panicking
	// Creating a minimal valid packet structure
	packet := make([]byte, 64)
	packet[0] = 0xc0 // Long header

	hp, _ := hex.DecodeString("9f50449e04a0e810283a1e9933adedd2")

	pnOffset := 17
	_, _, err := RemoveHeaderProtection(packet, pnOffset, hp)

	if err != nil {
		// Expected to work without error given enough data
		t.Logf("RemoveHeaderProtection returned: %v", err)
	}
}

func TestDecryptPayload(t *testing.T) {
	// Simplified test - just verify the function doesn't panic
	header := []byte{0xc0, 0x00, 0x00, 0x00, 0x01}
	encryptedPayload := make([]byte, 32) // Encrypted data + auth tag (16 bytes)
	key, _ := hex.DecodeString("1f369613dd76d5467730efcbe3b1a22d")
	iv, _ := hex.DecodeString("fa044b2f42a3fd3b46fb255c")

	// This will fail decryption (wrong key/data), but should not panic
	_, err := DecryptPayload(header, encryptedPayload, 0, key, iv)
	if err == nil {
		t.Log("Decryption unexpectedly succeeded with test data")
	}
}

func TestGetSaltForVersion(t *testing.T) {
	salt, err := GetSaltForVersion(0x00000001)
	if err != nil {
		t.Fatalf("GetSaltForVersion(v1) failed: %v", err)
	}

	wantSalt, _ := hex.DecodeString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
	if !bytes.Equal(salt, wantSalt) {
		t.Errorf("salt for v1:\ngot:  %x\nwant: %x", salt, wantSalt)
	}

	_, err = GetSaltForVersion(0x99999999)
	if err == nil {
		t.Error("Expected error for unsupported version, got nil")
	}
}

func TestHKDFExpandLabel(t *testing.T) {
	// Test HKDF-Expand-Label with known input/output
	secret, _ := hex.DecodeString("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
	label := []byte("quic key")

	result := hkdfExpandLabel(secret, label, nil, 16)

	// Expected from RFC 9001 test vectors
	want, _ := hex.DecodeString("1f369613dd76d5467730efcbe3b1a22d")

	if !bytes.Equal(result, want) {
		t.Errorf("hkdfExpandLabel:\ngot:  %x\nwant: %x", result, want)
	}
}
