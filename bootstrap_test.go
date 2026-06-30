// SPDX-License-Identifier: MIT

package irohmesh_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/tmc/go-iroh/key"
	irohmesh "github.com/tmc/mlx-go-iroh"
)

// genPub returns a fresh ed25519 public key and its base64-std encoding, the
// roster row form RosterBootstrap consumes.
func genPub(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, base64.StdEncoding.EncodeToString(pub)
}

// endpointID builds the key.EndpointID for a public key, as RosterBootstrap's
// self argument and as the identity in a bootstrap string.
func endpointID(t *testing.T, pub ed25519.PublicKey) key.EndpointID {
	t.Helper()
	id, err := key.EndpointIDFromSlice(pub)
	if err != nil {
		t.Fatalf("EndpointIDFromSlice: %v", err)
	}
	return id
}

// TestRosterBootstrap checks that valid rows map to addr-less EndpointAddrs,
// that self is omitted, that a malformed row is skipped fail-soft, and that an
// all-malformed roster reports ErrInvalid.
func TestRosterBootstrap(t *testing.T) {
	pubA, b64A := genPub(t)
	_, b64B := genPub(t)
	pubSelf, b64Self := genPub(t)
	self := endpointID(t, pubSelf)

	t.Run("maps valid rows and omits self", func(t *testing.T) {
		roster := []string{b64A, b64Self, b64B, "not-base64!!", "c2hvcnQ="} // last two are skipped
		addrs, err := irohmesh.RosterBootstrap(roster, self)
		if err != nil {
			t.Fatalf("RosterBootstrap: %v", err)
		}
		if len(addrs) != 2 {
			t.Fatalf("got %d addrs, want 2 (self and the two malformed rows dropped)", len(addrs))
		}
		// self must not appear.
		for _, a := range addrs {
			if a.ID.Equal(self) {
				t.Errorf("self %s present in bootstrap set", self)
			}
		}
		// Addresses are intentionally empty under the unified-key model, and
		// the kept ids are exactly the non-self valid rows (A and B).
		kept := make(map[string]bool, len(addrs))
		for _, a := range addrs {
			if len(a.Addrs()) != 0 {
				t.Errorf("addr %s carries %d transport addrs, want 0", a.ID, len(a.Addrs()))
			}
			kept[a.ID.String()] = true
		}
		if !kept[endpointID(t, pubA).String()] {
			t.Errorf("roster member A %s missing from bootstrap set", endpointID(t, pubA))
		}
	})

	t.Run("all malformed is ErrInvalid", func(t *testing.T) {
		_, err := irohmesh.RosterBootstrap([]string{"@@@", "c2hvcnQ=", ""}, self)
		if !errors.Is(err, irohmesh.ErrInvalid) {
			t.Fatalf("err = %v, want errors.Is ErrInvalid", err)
		}
	})

	t.Run("empty roster is ErrInvalid", func(t *testing.T) {
		if _, err := irohmesh.RosterBootstrap(nil, self); !errors.Is(err, irohmesh.ErrInvalid) {
			t.Fatalf("err = %v, want errors.Is ErrInvalid", err)
		}
	})

	t.Run("roster of only self is ErrInvalid", func(t *testing.T) {
		if _, err := irohmesh.RosterBootstrap([]string{b64Self}, self); !errors.Is(err, irohmesh.ErrInvalid) {
			t.Fatalf("err = %v, want errors.Is ErrInvalid", err)
		}
	})
}

// validBootstrap returns a well-formed endpointID@transportAddr string and the
// endpoint id it encodes.
func validBootstrap(t *testing.T) (string, key.EndpointID) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	pk, err := key.PublicKeyFromEd25519(pub)
	if err != nil {
		t.Fatalf("PublicKeyFromEd25519: %v", err)
	}
	id := pk.EndpointID()
	return id.String() + "@ip:1.2.3.4:5678", id
}

// TestParseBootstrap checks one valid string parses to the expected id and a
// dialable address, and that each malformed shape errors.
func TestParseBootstrap(t *testing.T) {
	good, wantID := validBootstrap(t)

	t.Run("valid", func(t *testing.T) {
		addr, err := irohmesh.ParseBootstrap(good)
		if err != nil {
			t.Fatalf("ParseBootstrap(%q): %v", good, err)
		}
		if !addr.ID.Equal(wantID) {
			t.Errorf("id = %s, want %s", addr.ID, wantID)
		}
		if len(addr.Addrs()) != 1 {
			t.Fatalf("got %d transport addrs, want 1", len(addr.Addrs()))
		}
		if got := addr.Addrs()[0].String(); got != "ip:1.2.3.4:5678" {
			t.Errorf("transport addr = %q, want %q", got, "ip:1.2.3.4:5678")
		}
	})

	id := wantID.String()
	tests := []struct {
		name string
		in   string
	}{
		{"no at sign", id + "ip:1.2.3.4:5678"},
		{"bad endpoint id", "not-an-id@ip:1.2.3.4:5678"},
		{"bad transport addr unknown kind", id + "@1.2.3.4:5678"},
		{"empty transport addr", id + "@"},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := irohmesh.ParseBootstrap(tt.in); err == nil {
				t.Errorf("ParseBootstrap(%q) = nil error, want error", tt.in)
			}
		})
	}
}

// TestParseBootstraps checks a clean list parses fully and a list with one bad
// entry fails the whole list rather than returning partial results.
func TestParseBootstraps(t *testing.T) {
	a, _ := validBootstrap(t)
	b, _ := validBootstrap(t)

	t.Run("all valid", func(t *testing.T) {
		addrs, err := irohmesh.ParseBootstraps([]string{a, b})
		if err != nil {
			t.Fatalf("ParseBootstraps: %v", err)
		}
		if len(addrs) != 2 {
			t.Fatalf("got %d addrs, want 2", len(addrs))
		}
	})

	t.Run("one bad fails all", func(t *testing.T) {
		addrs, err := irohmesh.ParseBootstraps([]string{a, "garbage", b})
		if err == nil {
			t.Fatalf("ParseBootstraps with bad entry = nil error, want error")
		}
		if addrs != nil {
			t.Errorf("got partial result %v, want nil", addrs)
		}
	})
}

// ExampleParseBootstrap parses an endpointID@transportAddr seed string.
func ExampleParseBootstrap() {
	// A fixed endpoint id (lowercase hex of an ed25519 public key) and a direct
	// IP transport address.
	const seed = "632c9edea77a6d157bcff57d92adf6bb7ac99a543a3709eb4f27c2b884f93a72@ip:1.2.3.4:5678"
	addr, err := irohmesh.ParseBootstrap(seed)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(addr.Addrs()[0])
	// Output: ip:1.2.3.4:5678
}
