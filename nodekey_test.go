// SPDX-License-Identifier: MIT

package irohmesh_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/tmc/go-iroh/key"
	irohmesh "github.com/tmc/mlx-go-iroh"
)

// TestNodeKeySignVerify checks the Sign/Verify round trip and that a tampered
// message, the wrong public key, or a wrong-length key or signature all fail.
func TestNodeKeySignVerify(t *testing.T) {
	k, err := irohmesh.GenerateNodeKey()
	if err != nil {
		t.Fatalf("generate node key: %v", err)
	}
	other, err := irohmesh.GenerateNodeKey()
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}

	msg := []byte("mesh heartbeat #1")
	sig := k.Sign(msg)

	tests := []struct {
		name string
		pub  ed25519.PublicKey
		msg  []byte
		sig  []byte
		want bool
	}{
		{"valid", k.Public(), msg, sig, true},
		{"tampered msg", k.Public(), []byte("mesh heartbeat #2"), sig, false},
		{"wrong pubkey", other.Public(), msg, sig, false},
		{"short pubkey", k.Public()[:16], msg, sig, false},
		{"short sig", k.Public(), msg, sig[:32], false},
		{"empty sig", k.Public(), msg, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := irohmesh.Verify(tt.pub, tt.msg, tt.sig); got != tt.want {
				t.Errorf("Verify(%s) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// TestNodeKeyFromSeed checks deterministic derivation from a seed and the
// length validation on the seed.
func TestNodeKeyFromSeed(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}

	a, err := irohmesh.NodeKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("NodeKeyFromSeed: %v", err)
	}
	b, err := irohmesh.NodeKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("NodeKeyFromSeed (second): %v", err)
	}
	if !bytes.Equal(a.Public(), b.Public()) {
		t.Errorf("same seed yielded different public keys:\n a = %x\n b = %x", a.Public(), b.Public())
	}

	badLengths := []int{0, ed25519.SeedSize - 1, ed25519.SeedSize + 1, ed25519.PrivateKeySize}
	for _, n := range badLengths {
		if _, err := irohmesh.NodeKeyFromSeed(make([]byte, n)); err == nil {
			t.Errorf("NodeKeyFromSeed(len %d) = nil error, want error", n)
		}
	}
}

// TestLoadOrCreate checks that the first call creates and persists a key, that
// a second call loads the same key, that the seed file is written 0600, and
// that missing parent directories are created.
func TestLoadOrCreate(t *testing.T) {
	// Nested under directories that do not yet exist, so this also exercises
	// MkdirAll.
	path := filepath.Join(t.TempDir(), "node", "keys", "node.seed")

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("precondition: %s already exists (err=%v)", path, err)
	}

	created, err := irohmesh.LoadOrCreate(path)
	if err != nil {
		t.Fatalf("LoadOrCreate (create): %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat persisted key: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("seed file mode = %o, want 600", got)
	}

	loaded, err := irohmesh.LoadOrCreate(path)
	if err != nil {
		t.Fatalf("LoadOrCreate (load): %v", err)
	}
	if !bytes.Equal(created.Public(), loaded.Public()) {
		t.Errorf("reload changed key:\n created = %x\n loaded  = %x", created.Public(), loaded.Public())
	}
}

// TestNodeKeyID checks that a NodeKey's endpoint id is exactly its ed25519
// public key reinterpreted as a key.EndpointID.
func TestNodeKeyID(t *testing.T) {
	k, err := irohmesh.GenerateNodeKey()
	if err != nil {
		t.Fatalf("generate node key: %v", err)
	}

	pub, err := key.PublicKeyFromEd25519(k.Public())
	if err != nil {
		t.Fatalf("PublicKeyFromEd25519: %v", err)
	}
	want := pub.EndpointID()

	if got := k.ID(); !got.Equal(want) {
		t.Errorf("ID() = %s, want %s", got, want)
	}

	// The endpoint id bytes are the ed25519 public key bytes.
	idBytes := k.ID().PublicKey().Bytes()
	if !bytes.Equal(idBytes[:], k.Public()) {
		t.Errorf("ID public bytes = %x, want %x", idBytes[:], k.Public())
	}
}

// TestNodeKeyFromEd25519 checks wrapping an existing private key and that a
// wrong-length key is rejected.
func TestNodeKeyFromEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	k, err := irohmesh.NodeKeyFromEd25519(priv)
	if err != nil {
		t.Fatalf("NodeKeyFromEd25519: %v", err)
	}
	if !bytes.Equal(k.Public(), pub) {
		t.Errorf("public mismatch:\n got  = %x\n want = %x", k.Public(), pub)
	}

	if _, err := irohmesh.NodeKeyFromEd25519(priv[:16]); err == nil {
		t.Error("NodeKeyFromEd25519(short) = nil error, want error")
	}
}

// ExampleNodeKey signs a message and verifies it against the node's public key.
func ExampleNodeKey() {
	seed := make([]byte, ed25519.SeedSize) // all-zero seed, for a deterministic example
	k, err := irohmesh.NodeKeyFromSeed(seed)
	if err != nil {
		fmt.Println(err)
		return
	}

	msg := []byte("hello mesh")
	sig := k.Sign(msg)
	fmt.Println(irohmesh.Verify(k.Public(), msg, sig))
	// Output: true
}
