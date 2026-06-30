// SPDX-License-Identifier: MIT

package irohmesh_test

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	irohmesh "github.com/tmc/mlx-go-iroh"
)

// mustKey returns a fresh NodeKey or fails the test.
func mustKey(t *testing.T) irohmesh.NodeKey {
	t.Helper()
	k, err := irohmesh.GenerateNodeKey()
	if err != nil {
		t.Fatalf("generate node key: %v", err)
	}
	return k
}

// binaryPayload is a payload of non-text bytes, including a NUL, a high bit, and
// the 0xff..0x00 extremes, so a round trip that re-serialized or string-mangled
// the payload would corrupt it visibly.
var binaryPayload = []byte{0x00, 0xff, 0x01, 0x80, 0x7f, 0xfe, 0x00, 0x00, 0xc3, 0x28, 0xff}

func TestSignEnvelopeRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"text", []byte("heartbeat #1")},
		{"binary", binaryPayload},
		{"nul-only", []byte{0x00}},
		{"under-bound", make([]byte, 2900)}, // wire ~4036 < MaxGossipFrame
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := mustKey(t)
			env, err := irohmesh.SignEnvelope(k, tt.payload)
			if err != nil {
				t.Fatalf("SignEnvelope: %v", err)
			}
			if err := env.Verify(); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			// NodeID is the signer's public key.
			if want := k.Public(); !ed25519.PublicKey(env.NodeID).Equal(want) {
				t.Errorf("NodeID = %x, want %x", env.NodeID, want)
			}
			// Payload survives byte-for-byte (opaque, never re-serialized).
			if string(env.Payload) != string(tt.payload) {
				t.Errorf("Payload = %x, want %x", env.Payload, tt.payload)
			}
		})
	}
}

// TestSignEnvelopeCopiesInput confirms SignEnvelope copies the caller's payload:
// mutating the input slice afterward does not change the envelope, and the
// envelope still verifies.
func TestSignEnvelopeCopiesInput(t *testing.T) {
	k := mustKey(t)
	payload := append([]byte(nil), binaryPayload...)
	env, err := irohmesh.SignEnvelope(k, payload)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	for i := range payload {
		payload[i] ^= 0xff // scribble over the caller's slice
	}
	if string(env.Payload) != string(binaryPayload) {
		t.Errorf("Payload aliased caller slice: got %x, want %x", env.Payload, binaryPayload)
	}
	if err := env.Verify(); err != nil {
		t.Errorf("Verify after caller mutation: %v", err)
	}
}

func TestVerifyTamper(t *testing.T) {
	k := mustKey(t)
	other := mustKey(t)
	base, err := irohmesh.SignEnvelope(k, binaryPayload)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}

	// clone returns an independent copy of base so each case mutates in isolation.
	clone := func() irohmesh.SignedEnvelope {
		return irohmesh.SignedEnvelope{
			NodeID:  append([]byte(nil), base.NodeID...),
			Payload: append([]byte(nil), base.Payload...),
			Sig:     append([]byte(nil), base.Sig...),
		}
	}

	tests := []struct {
		name   string
		mutate func(*irohmesh.SignedEnvelope)
	}{
		{"flip payload byte", func(e *irohmesh.SignedEnvelope) { e.Payload[0] ^= 0x01 }},
		{"flip last payload byte", func(e *irohmesh.SignedEnvelope) { e.Payload[len(e.Payload)-1] ^= 0x80 }},
		{"flip sig byte", func(e *irohmesh.SignedEnvelope) { e.Sig[0] ^= 0x01 }},
		{"wrong node id", func(e *irohmesh.SignedEnvelope) { e.NodeID = other.Public() }},
		{"truncated node id", func(e *irohmesh.SignedEnvelope) { e.NodeID = e.NodeID[:len(e.NodeID)-1] }},
		{"truncated sig", func(e *irohmesh.SignedEnvelope) { e.Sig = e.Sig[:len(e.Sig)-1] }},
		{"empty node id", func(e *irohmesh.SignedEnvelope) { e.NodeID = nil }},
		{"empty sig", func(e *irohmesh.SignedEnvelope) { e.Sig = nil }},
		{"overlong node id", func(e *irohmesh.SignedEnvelope) { e.NodeID = append(e.NodeID, 0x00) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := clone()
			tt.mutate(&e)
			if err := e.Verify(); err == nil {
				t.Errorf("Verify accepted tampered envelope, want error")
			}
		})
	}
}

// TestVerifyCrossKey confirms you cannot keep a valid signature while swapping
// in another key's public key as NodeID: the signature is bound to the signer.
func TestVerifyCrossKey(t *testing.T) {
	a := mustKey(t)
	b := mustKey(t)

	env, err := irohmesh.SignEnvelope(a, binaryPayload)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	if err := env.Verify(); err != nil {
		t.Fatalf("Verify (genuine): %v", err)
	}

	// Forge: keep a's signature and payload but claim b signed it.
	forged := irohmesh.SignedEnvelope{
		NodeID:  b.Public(),
		Payload: env.Payload,
		Sig:     env.Sig,
	}
	if err := forged.Verify(); err == nil {
		t.Error("Verify accepted forged NodeID swap, want error")
	}
}

func TestSignEnvelopeSizeBound(t *testing.T) {
	k := mustKey(t)

	// Just under the wire bound (probed: payload 2900 -> wire ~4036).
	if _, err := irohmesh.SignEnvelope(k, make([]byte, 2900)); err != nil {
		t.Errorf("SignEnvelope under bound: unexpected error %v", err)
	}

	// A 4096-byte payload base64-expands well past MaxGossipFrame on the wire.
	_, err := irohmesh.SignEnvelope(k, make([]byte, irohmesh.MaxGossipFrame))
	if err == nil {
		t.Fatal("SignEnvelope oversized: got nil error, want size error")
	}
	if !strings.Contains(err.Error(), "MaxGossipFrame") {
		t.Errorf("error %q does not mention MaxGossipFrame", err)
	}

	// The successfully signed envelope's wire form must fit MaxGossipFrame.
	env, err := irohmesh.SignEnvelope(k, make([]byte, 2900))
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	wire, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(wire) > irohmesh.MaxGossipFrame {
		t.Errorf("wire size %d exceeds MaxGossipFrame %d", len(wire), irohmesh.MaxGossipFrame)
	}
}

func ExampleSignEnvelope() {
	k, err := irohmesh.GenerateNodeKey()
	if err != nil {
		panic(err)
	}
	env, err := irohmesh.SignEnvelope(k, []byte("heartbeat"))
	if err != nil {
		panic(err)
	}
	fmt.Println(env.Verify() == nil)
	fmt.Printf("%s\n", env.Payload)
	// Output:
	// true
	// heartbeat
}
