package blob

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"nil", nil},
		{"text", []byte("the quick brown fox")},
		{"binary", []byte{0x00, 0xff, 0x01, 0x80, 0x7f, 0xfe, 0x00}},
		{"one-byte", []byte{0x42}},
		{"large", bytes.Repeat([]byte{0xab}, 64*1024+7)}, // spans BAO blocks
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, enc, err := Encode(tt.data)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if got := HashBytes(tt.data); got != h {
				t.Errorf("HashBytes = %s, Encode hash = %s; want equal", got, h)
			}
			got, err := Decode(h, enc)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if !bytes.Equal(got, tt.data) {
				t.Errorf("Decode = %x, want %x", got, tt.data)
			}
		})
	}
}

func TestDecodeRejectsCorruption(t *testing.T) {
	data := []byte("verify me against the hash")
	h, enc, err := Encode(data)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	t.Run("tampered bytes", func(t *testing.T) {
		bad := append([]byte(nil), enc...)
		bad[len(bad)-1] ^= 0xff // flip a payload byte
		if _, err := Decode(h, bad); err == nil {
			t.Error("Decode accepted tampered bytes, want error")
		}
	})

	t.Run("wrong expected hash", func(t *testing.T) {
		wrong := HashBytes([]byte("a different blob"))
		if wrong == h {
			t.Fatal("test setup: hashes unexpectedly equal")
		}
		if _, err := Decode(wrong, enc); err == nil {
			t.Error("Decode accepted wrong expected hash, want error")
		}
	})
}

func TestMemoryStore(t *testing.T) {
	s := NewMemoryStore()
	if got := s.Len(); got != 0 {
		t.Fatalf("fresh store Len = %d, want 0", got)
	}

	data := []byte{0x00, 0xff, 0x10, 0x20}
	h := s.Put(data)
	if want := HashBytes(data); h != want {
		t.Errorf("Put hash = %s, want %s", h, want)
	}

	got, ok := s.GetBlob(h)
	if !ok {
		t.Fatal("GetBlob after Put: ok = false, want true")
	}
	if !bytes.Equal(got, data) {
		t.Errorf("GetBlob = %x, want %x", got, data)
	}
	if s.Len() != 1 {
		t.Errorf("Len after one Put = %d, want 1", s.Len())
	}

	// Idempotent: re-Putting the same data does not grow the store.
	if h2 := s.Put(data); h2 != h {
		t.Errorf("re-Put hash = %s, want %s", h2, h)
	}
	if s.Len() != 1 {
		t.Errorf("Len after idempotent Put = %d, want 1", s.Len())
	}

	// Distinct data adds a distinct blob.
	other := []byte("second blob")
	s.Put(other)
	if s.Len() != 2 {
		t.Errorf("Len after distinct Put = %d, want 2", s.Len())
	}

	// Unknown hash misses.
	if _, ok := s.GetBlob(HashBytes([]byte("never stored"))); ok {
		t.Error("GetBlob(unknown) ok = true, want false")
	}
}

// TestMemoryStoreReturnsCopies confirms Put copies the caller's slice and
// GetBlob returns copies, so neither the caller's input nor a returned slice
// aliases the stored bytes.
func TestMemoryStoreReturnsCopies(t *testing.T) {
	s := NewMemoryStore()
	data := []byte{0x01, 0x02, 0x03, 0x04}
	h := s.Put(data)

	// Mutating the input after Put must not change the store.
	data[0] = 0xff
	got, ok := s.GetBlob(h)
	if !ok {
		t.Fatal("GetBlob: ok = false, want true")
	}
	if got[0] != 0x01 {
		t.Errorf("store aliased caller input: got[0] = %#x, want 0x01", got[0])
	}

	// Mutating a returned slice must not change the store.
	got[0] = 0xee
	again, ok := s.GetBlob(h)
	if !ok {
		t.Fatal("GetBlob (second): ok = false, want true")
	}
	if again[0] != 0x01 {
		t.Errorf("returned slice aliased store: again[0] = %#x, want 0x01", again[0])
	}
}

// endpointAddr derives a netaddr.EndpointAddr from an ed25519 public key, the
// way a ticket names a peer by its node identity.
func endpointAddr(t *testing.T, pub ed25519.PublicKey) netaddr.EndpointAddr {
	t.Helper()
	pk, err := key.PublicKeyFromEd25519(pub)
	if err != nil {
		t.Fatalf("public key from ed25519: %v", err)
	}
	return netaddr.NewEndpointAddr(pk.EndpointID())
}

func TestTicketRoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	addr := endpointAddr(t, pub)
	h := HashBytes([]byte("checkpoint shard 0"))

	ticket := Ticket(addr, h)
	if ticket == "" {
		t.Fatal("Ticket returned empty string")
	}

	gotAddr, gotHash, err := ParseTicket(ticket)
	if err != nil {
		t.Fatalf("ParseTicket: %v", err)
	}
	if gotHash != h {
		t.Errorf("hash = %s, want %s", gotHash, h)
	}
	if !gotAddr.ID.Equal(addr.ID) {
		t.Errorf("addr id = %s, want %s", gotAddr.ID, addr.ID)
	}
}

func TestParseTicketRejectsGarbage(t *testing.T) {
	for _, s := range []string{"", "not-a-ticket", "blob:zzzz"} {
		if _, _, err := ParseTicket(s); err == nil {
			t.Errorf("ParseTicket(%q) = nil error, want error", s)
		}
	}
}
