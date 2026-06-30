package manifest

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// fakePeers serves blob bytes by name, optionally failing chosen names.
type fakePeers struct {
	data map[string][]byte
	fail map[string]bool
}

func (p fakePeers) Fetch(_ context.Context, _ netaddr.EndpointAddr, b Blob) ([]byte, error) {
	if p.fail[b.Name] {
		return nil, fmt.Errorf("peer fetch %q: forced failure", b.Name)
	}
	data, ok := p.data[b.Name]
	if !ok {
		return nil, fmt.Errorf("peer fetch %q: not found", b.Name)
	}
	return data, nil
}

// fakeHub serves blob bytes by name and counts calls.
type fakeHub struct {
	data  map[string][]byte
	calls int
}

func (h *fakeHub) Fetch(_ context.Context, b Blob) ([]byte, error) {
	h.calls++
	data, ok := h.data[b.Name]
	if !ok {
		return nil, fmt.Errorf("hub fetch %q: not found", b.Name)
	}
	return data, nil
}

// dummyAddr returns a deterministic but well-formed peer address. The state
// machine only needs a non-empty peer list; the fakes ignore the address. The
// seed must yield a valid Ed25519 curve point, so derive the key from a seeded
// generator rather than constructing raw bytes.
func dummyAddr(t *testing.T, seed byte) netaddr.EndpointAddr {
	t.Helper()
	pubKey, _, err := ed25519.GenerateKey(constReader(seed))
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	pk, err := key.PublicKeyFromEd25519(pubKey)
	if err != nil {
		t.Fatalf("public key from ed25519: %v", err)
	}
	return netaddr.NewEndpointAddr(pk.EndpointID())
}

// constReader yields an endless stream of one byte, a deterministic seed for
// ed25519.GenerateKey.
type constReader byte

func (c constReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(c)
	}
	return len(p), nil
}

// blobData holds the byte payloads keyed by blob name, the canonical source for
// building fakes that verify against the manifest.
type blobData struct {
	names []string
	bytes map[string][]byte
}

// buildManifest constructs a manifest whose blobs verify, with one dummy peer
// per entry. It returns the manifest plus the raw bytes for fake transports.
func buildManifest(t *testing.T, version uint64, blobs map[string][]byte) (Manifest, blobData) {
	t.Helper()
	d := blobData{bytes: map[string][]byte{}}
	var entries []Entry
	var i byte
	for name, data := range blobs {
		b, err := NewBlob(name, version, data)
		if err != nil {
			t.Fatalf("new blob %q: %v", name, err)
		}
		entries = append(entries, Entry{Blob: b, Peers: []netaddr.EndpointAddr{dummyAddr(t, i+1)}})
		d.names = append(d.names, name)
		d.bytes[name] = data
		i++
	}
	return Manifest{Version: version, Entries: entries}, d
}

func TestPullAllFromPeers(t *testing.T) {
	want := map[string][]byte{
		"weights": []byte("the model weights"),
		"config":  []byte("{config json}"),
		"tokens":  []byte("vocab data here"),
	}
	mf, d := buildManifest(t, 7, want)

	s, err := NewSync(mf)
	if err != nil {
		t.Fatalf("new sync: %v", err)
	}
	peers := fakePeers{data: d.bytes}
	hub := &fakeHub{data: map[string][]byte{}}

	if err := s.Pull(context.Background(), mf, peers, hub); err != nil {
		t.Fatalf("pull: %v", err)
	}
	if !s.AllLoaded() {
		t.Error("AllLoaded() = false, want true")
	}
	if !s.WarmupComplete() {
		t.Error("WarmupComplete() = false, want true")
	}
	if s.UsedHub() {
		t.Error("UsedHub() = true, want false")
	}
	if hub.calls != 0 {
		t.Errorf("hub.calls = %d, want 0", hub.calls)
	}
	for name, wantBytes := range want {
		got, ok := s.Blob(name)
		if !ok {
			t.Errorf("Blob(%q): not loaded", name)
			continue
		}
		if string(got) != string(wantBytes) {
			t.Errorf("Blob(%q) = %q, want %q", name, got, wantBytes)
		}
	}
}

func TestPullHubFailover(t *testing.T) {
	want := map[string][]byte{
		"alpha": []byte("alpha bytes"),
		"beta":  []byte("beta bytes"),
		"gamma": []byte("gamma bytes"),
	}
	mf, d := buildManifest(t, 3, want)

	tests := []struct {
		name  string
		peers fakePeers
	}{
		{
			name:  "peer fails one blob",
			peers: fakePeers{data: d.bytes, fail: map[string]bool{"beta": true}},
		},
		{
			name:  "peer cannot serve one blob",
			peers: fakePeers{data: map[string][]byte{"alpha": want["alpha"], "gamma": want["gamma"]}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewSync(mf)
			if err != nil {
				t.Fatalf("new sync: %v", err)
			}
			hub := &fakeHub{data: d.bytes}

			if err := s.Pull(context.Background(), mf, tt.peers, hub); err != nil {
				t.Fatalf("pull: %v", err)
			}
			if !s.UsedHub() {
				t.Error("UsedHub() = false, want true")
			}
			if !s.AllLoaded() {
				t.Error("AllLoaded() = false, want true")
			}
			if hub.calls == 0 {
				t.Error("hub.calls = 0, want > 0 (hub never invoked)")
			}
			// Failover resets and pulls the whole manifest from the hub: all
			// blobs must come from the hub, even ones a peer could serve.
			if hub.calls != len(want) {
				t.Errorf("hub.calls = %d, want %d (whole manifest from hub)", hub.calls, len(want))
			}
			for name, wantBytes := range want {
				got, ok := s.Blob(name)
				if !ok {
					t.Errorf("Blob(%q): not loaded", name)
					continue
				}
				if string(got) != string(wantBytes) {
					t.Errorf("Blob(%q) = %q, want %q", name, got, wantBytes)
				}
			}
		})
	}
}

func TestPullNoPeersNilHub(t *testing.T) {
	want := map[string][]byte{"solo": []byte("solo payload")}
	mf, _ := buildManifest(t, 1, want)

	s, err := NewSync(mf)
	if err != nil {
		t.Fatalf("new sync: %v", err)
	}
	// Peers serve nothing and hub is nil: the peer failure is fatal.
	peers := fakePeers{data: map[string][]byte{}}

	if err := s.Pull(context.Background(), mf, peers, nil); err == nil {
		t.Fatal("pull: got nil error, want failure")
	}
	if s.AllLoaded() {
		t.Error("AllLoaded() = true, want false")
	}
	if s.UsedHub() {
		t.Error("UsedHub() = true, want false")
	}
}

func TestPullHashMismatchDefense(t *testing.T) {
	want := map[string][]byte{
		"good": []byte("good payload"),
		"bad":  []byte("intended bytes for bad"),
	}
	mf, d := buildManifest(t, 2, want)

	// Peer returns wrong bytes for "bad": the wrong length and content fail
	// verifyBytes, so the peer is rejected.
	corrupt := map[string][]byte{
		"good": d.bytes["good"],
		"bad":  []byte("tampered"),
	}

	t.Run("hub recovers", func(t *testing.T) {
		s, err := NewSync(mf)
		if err != nil {
			t.Fatalf("new sync: %v", err)
		}
		peers := fakePeers{data: corrupt}
		hub := &fakeHub{data: d.bytes}

		if err := s.Pull(context.Background(), mf, peers, hub); err != nil {
			t.Fatalf("pull: %v", err)
		}
		if !s.UsedHub() {
			t.Error("UsedHub() = false, want true")
		}
		if !s.AllLoaded() {
			t.Error("AllLoaded() = false, want true")
		}
		got, ok := s.Blob("bad")
		if !ok || string(got) != string(want["bad"]) {
			t.Errorf("Blob(\"bad\") = %q, %v, want %q from hub", got, ok, want["bad"])
		}
	})

	t.Run("no hub fails", func(t *testing.T) {
		s, err := NewSync(mf)
		if err != nil {
			t.Fatalf("new sync: %v", err)
		}
		peers := fakePeers{data: corrupt}

		if err := s.Pull(context.Background(), mf, peers, nil); err == nil {
			t.Fatal("pull: got nil error, want hash-mismatch failure")
		}
		if s.AllLoaded() {
			t.Error("AllLoaded() = true, want false")
		}
	})
}

func TestNewSyncValidation(t *testing.T) {
	goodA, err := NewBlob("a", 1, []byte("aaa"))
	if err != nil {
		t.Fatalf("new blob a: %v", err)
	}
	goodB, err := NewBlob("b", 1, []byte("bbb"))
	if err != nil {
		t.Fatalf("new blob b: %v", err)
	}
	nonZeroHash := goodA.Hash

	tests := []struct {
		name    string
		mf      Manifest
		wantErr bool
	}{
		{
			name: "valid",
			mf:   Manifest{Version: 1, Entries: []Entry{{Blob: goodA}, {Blob: goodB}}},
		},
		{
			name:    "duplicate name",
			mf:      Manifest{Version: 1, Entries: []Entry{{Blob: goodA}, {Blob: goodA}}},
			wantErr: true,
		},
		{
			name:    "empty name",
			mf:      Manifest{Version: 1, Entries: []Entry{{Blob: Blob{Name: "", Version: 1, Hash: nonZeroHash, Size: 3}}}},
			wantErr: true,
		},
		{
			name:    "zero hash",
			mf:      Manifest{Version: 1, Entries: []Entry{{Blob: Blob{Name: "z", Version: 1, Size: 3}}}},
			wantErr: true,
		},
		{
			// Version defaults to the manifest version, so a per-blob zero
			// version only errors when the manifest version is also zero.
			name:    "zero version no manifest fallback",
			mf:      Manifest{Version: 0, Entries: []Entry{{Blob: Blob{Name: "z", Version: 0, Hash: nonZeroHash, Size: 3}}}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewSync(tt.mf)
			if tt.wantErr {
				if err == nil {
					t.Fatal("NewSync: got nil error, want failure")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewSync: %v", err)
			}
			if s == nil {
				t.Fatal("NewSync: nil sync without error")
			}
		})
	}
}

func TestNewBlob(t *testing.T) {
	data := []byte("hash me")
	b, err := NewBlob("x", 4, data)
	if err != nil {
		t.Fatalf("new blob: %v", err)
	}
	if b.Name != "x" {
		t.Errorf("Name = %q, want %q", b.Name, "x")
	}
	if b.Version != 4 {
		t.Errorf("Version = %d, want 4", b.Version)
	}
	if b.Size != uint64(len(data)) {
		t.Errorf("Size = %d, want %d", b.Size, len(data))
	}
	wantHash := blobs.NewHash(data).Bytes()
	if b.Hash != wantHash {
		t.Errorf("Hash = %x, want %x", b.Hash, wantHash)
	}

	if _, err := NewBlob("", 1, data); err == nil {
		t.Error("NewBlob with empty name: got nil error, want failure")
	}
}

func TestNilReceiverSafety(t *testing.T) {
	var s *Sync
	if s.AllLoaded() {
		t.Error("nil.AllLoaded() = true, want false")
	}
	if s.WarmupComplete() {
		t.Error("nil.WarmupComplete() = true, want false")
	}
	if s.UsedHub() {
		t.Error("nil.UsedHub() = true, want false")
	}
	if data, ok := s.Blob("x"); ok || data != nil {
		t.Errorf("nil.Blob(\"x\") = %v, %v, want nil, false", data, ok)
	}
	if err := s.Pull(context.Background(), Manifest{}, fakePeers{}, nil); err == nil {
		t.Error("nil.Pull: got nil error, want failure")
	}
}

func ExampleSync() {
	data := []byte("model weights")
	b, _ := NewBlob("weights", 1, data)
	mf := Manifest{Version: 1, Entries: []Entry{{Blob: b}}}

	s, _ := NewSync(mf)
	// No peers are reachable, so the pull falls back to the hub.
	hub := &fakeHub{data: map[string][]byte{"weights": data}}
	_ = s.Pull(context.Background(), mf, fakePeers{}, hub)

	got, _ := s.Blob("weights")
	fmt.Println(string(got), s.AllLoaded(), s.UsedHub())
	// Output: model weights true true
}
