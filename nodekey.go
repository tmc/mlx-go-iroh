package irohmesh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tmc/go-iroh/key"
)

// NodeKey is a node's long-lived ed25519 identity. Its public key is the node's
// id on the mesh — the same key the go-iroh endpoint binds with (so the wire
// EndpointID equals the node id) and the key a signed receipt or heartbeat
// verifies against.
//
// NodeKey exposes a generic [NodeKey.Sign] for callers that just need a
// signature, and the raw ed25519 key via [NodeKey.Ed25519]/[NodeKey.Public] for
// callers that own their payload framing (e.g. a domain-separated receipt
// signer). The zero value is unusable; construct with [GenerateNodeKey] or
// [LoadOrCreate].
type NodeKey struct {
	priv ed25519.PrivateKey
}

// GenerateNodeKey returns a fresh random NodeKey.
func GenerateNodeKey() (NodeKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return NodeKey{}, fmt.Errorf("generate node key: %w", err)
	}
	return NodeKey{priv: priv}, nil
}

// NodeKeyFromSeed returns the NodeKey deterministically derived from seed, which
// must be [ed25519.SeedSize] bytes.
func NodeKeyFromSeed(seed []byte) (NodeKey, error) {
	if len(seed) != ed25519.SeedSize {
		return NodeKey{}, fmt.Errorf("node key seed has length %d, want %d", len(seed), ed25519.SeedSize)
	}
	return NodeKey{priv: ed25519.NewKeyFromSeed(seed)}, nil
}

// NodeKeyFromEd25519 wraps an existing ed25519 private key, so a caller that
// already manages an identity key can present it on the mesh.
func NodeKeyFromEd25519(priv ed25519.PrivateKey) (NodeKey, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return NodeKey{}, fmt.Errorf("node key has length %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	return NodeKey{priv: priv}, nil
}

// LoadOrCreate loads the NodeKey whose seed is stored at path, creating and
// persisting a fresh one if the file does not exist. The seed is written as
// hex with 0600 permissions; intermediate directories are created. This is the
// stable-identity path: a node calls it once at startup with a path under its
// home directory.
func LoadOrCreate(path string) (NodeKey, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		seed, decErr := hex.DecodeString(string(trimSpace(data)))
		if decErr != nil {
			return NodeKey{}, fmt.Errorf("load node key %s: decode seed: %w", path, decErr)
		}
		k, kerr := NodeKeyFromSeed(seed)
		if kerr != nil {
			return NodeKey{}, fmt.Errorf("load node key %s: %w", path, kerr)
		}
		return k, nil
	case errors.Is(err, os.ErrNotExist):
		k, gerr := GenerateNodeKey()
		if gerr != nil {
			return NodeKey{}, err
		}
		if mkErr := os.MkdirAll(filepath.Dir(path), 0o700); mkErr != nil {
			return NodeKey{}, fmt.Errorf("create node key dir: %w", mkErr)
		}
		seed := k.priv.Seed()
		if wErr := os.WriteFile(path, []byte(hex.EncodeToString(seed)), 0o600); wErr != nil {
			return NodeKey{}, fmt.Errorf("persist node key %s: %w", path, wErr)
		}
		return k, nil
	default:
		return NodeKey{}, fmt.Errorf("load node key %s: %w", path, err)
	}
}

// ID returns the node's go-iroh endpoint id, equal to its ed25519 public key.
func (k NodeKey) ID() key.EndpointID {
	pk, err := key.PublicKeyFromEd25519(k.Public())
	if err != nil {
		// A NodeKey constructed through this package always holds a valid
		// curve point, so this cannot fail; panic would mask a corrupted key.
		return key.EndpointID{}
	}
	return pk.EndpointID()
}

// Ed25519 returns the underlying ed25519 private key, for callers that sign
// their own domain-separated payloads (e.g. a receipt signer that owns its
// framing). The returned key aliases the NodeKey's material; do not mutate it.
func (k NodeKey) Ed25519() ed25519.PrivateKey { return k.priv }

// Public returns the node's ed25519 public key.
func (k NodeKey) Public() ed25519.PublicKey {
	return k.priv.Public().(ed25519.PublicKey)
}

// Sign returns the ed25519 signature of msg under the node key. It is the
// generic signer; callers that need domain separation should prefix msg
// themselves or sign through [NodeKey.Ed25519].
func (k NodeKey) Sign(msg []byte) []byte {
	return ed25519.Sign(k.priv, msg)
}

// Verify reports whether sig is a valid signature of msg under pub. It mirrors
// the SignX/VerifyX pairing used across the ecosystem's signed records.
func Verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// trimSpace strips trailing ASCII whitespace (newline, space, tab, CR) a key
// file may carry, without pulling in strings for one call.
func trimSpace(b []byte) []byte {
	for len(b) > 0 {
		switch b[len(b)-1] {
		case '\n', '\r', ' ', '\t':
			b = b[:len(b)-1]
		default:
			return b
		}
	}
	return b
}
