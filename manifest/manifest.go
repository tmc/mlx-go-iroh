// SPDX-License-Identifier: MIT

// Package manifest pulls a content-addressed set of blobs from peers over
// go-iroh blobs, falling back to a central hub when no peer can serve one. It is
// the generalized announce-then-pull path: a late joiner is handed a [Manifest]
// of what it needs and from whom, pulls each blob BAO-verified, and a hub
// (HTTP, S3, or any [HubRepo]) backstops a peer that drops mid-pull.
//
// Nothing here is mlx- or model-specific: a [Blob] is one named, versioned,
// content-hashed unit of bytes — a model parameter, a checkpoint file, a dataset
// shard. A typed codec wraps these byte primitives.
package manifest

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

// Blob describes one content-addressed unit in a manifest: a stable name, a
// monotonic version, its BLAKE3 hash, and its size. Name and Version identify it
// across versions; Hash and Size verify the bytes on pull.
type Blob struct {
	Name    string `json:"name"`
	Version uint64 `json:"version"`
	Hash    [32]byte
	Size    uint64 `json:"size"`
}

// Entry pairs a [Blob] with the peers known to serve it.
type Entry struct {
	Blob  Blob                   `json:"blob"`
	Peers []netaddr.EndpointAddr `json:"peers,omitempty"`
}

// Manifest lists every blob a node needs for one version, with per-blob peer
// hints.
type Manifest struct {
	Version uint64  `json:"version"`
	Entries []Entry `json:"entries"`
}

// HubRepo fetches a blob from a central source — the fallback when no peer can
// serve it. An HTTP or S3 backend implements this.
type HubRepo interface {
	Fetch(context.Context, Blob) ([]byte, error)
}

// PeerFetcher fetches a blob from one peer. [Fetcher] implements it over go-iroh
// blobs; a test or alternate transport can substitute its own.
type PeerFetcher interface {
	Fetch(context.Context, netaddr.EndpointAddr, Blob) ([]byte, error)
}

// Fetcher fetches blobs from peers over go-iroh blobs, BAO-verifying each.
type Fetcher struct {
	Endpoint *iroh.Endpoint
}

// Fetch dials peer over the blobs ALPN, pulls b, and verifies it against b's
// hash and size.
func (f Fetcher) Fetch(ctx context.Context, peer netaddr.EndpointAddr, b Blob) ([]byte, error) {
	if f.Endpoint == nil {
		return nil, fmt.Errorf("fetch blob: nil endpoint")
	}
	if err := validateBlob(b); err != nil {
		return nil, fmt.Errorf("fetch blob: %w", err)
	}
	conn, err := f.Endpoint.Connect(ctx, peer, blobs.ALPN)
	if err != nil {
		return nil, fmt.Errorf("fetch blob %q: connect peer: %w", b.Name, err)
	}
	defer conn.CloseWithError(0, "")
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch blob %q: open stream: %w", b.Name, err)
	}
	got, err := blobs.GetBlobBytes(ctx, s, blobs.HashFromBytes(b.Hash))
	if err != nil {
		return nil, fmt.Errorf("fetch blob %q: get blob: %w", b.Name, err)
	}
	if err := verifyBytes(b, got); err != nil {
		return nil, fmt.Errorf("fetch blob %q: %w", b.Name, err)
	}
	return got, nil
}

// Sync tracks which manifest blobs have been loaded, gating "ready" on all of
// them. The zero value is not usable; construct with [NewSync].
type Sync struct {
	mu       sync.Mutex
	want     map[string]Blob
	loaded   map[string][]byte
	failover bool
}

// NewSync returns a Sync for manifest, validating each entry.
func NewSync(manifest Manifest) (*Sync, error) {
	want := make(map[string]Blob, len(manifest.Entries))
	for i, entry := range manifest.Entries {
		b := entry.Blob
		if b.Version == 0 {
			b.Version = manifest.Version
		}
		if err := validateBlob(b); err != nil {
			return nil, fmt.Errorf("new sync: blob %d: %w", i, err)
		}
		if _, ok := want[b.Name]; ok {
			return nil, fmt.Errorf("new sync: duplicate blob %q", b.Name)
		}
		want[b.Name] = b
	}
	return &Sync{want: want, loaded: make(map[string][]byte)}, nil
}

// Pull loads every manifest blob, trying each blob's peers in turn and falling
// back to hub if a blob has no working peer. On the first hub fallback it resets
// and pulls the whole manifest from the hub, so a partial peer pull never mixes
// with a hub pull. hub may be nil, in which case a peer failure is fatal.
func (s *Sync) Pull(ctx context.Context, manifest Manifest, fetcher PeerFetcher, hub HubRepo) error {
	if s == nil {
		return fmt.Errorf("sync pull: nil sync")
	}
	if fetcher == nil {
		return fmt.Errorf("sync pull: nil peer fetcher")
	}
	for _, entry := range sortedEntries(manifest) {
		b := entry.Blob
		if b.Version == 0 {
			b.Version = manifest.Version
		}
		if s.has(b.Name) {
			continue
		}
		data, err := pullFromPeers(ctx, fetcher, entry.Peers, b)
		if err == nil {
			s.put(b, data)
			continue
		}
		if hub == nil {
			return err
		}
		s.reset()
		s.setFailover()
		return s.pullHub(ctx, manifest, hub)
	}
	return nil
}

// AllLoaded reports whether every manifest blob is loaded — the readiness
// barrier a caller waits on before proceeding.
func (s *Sync) AllLoaded() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.want) > 0 && len(s.loaded) == len(s.want)
}

// WarmupComplete is an alias for [Sync.AllLoaded], the coordinator-facing name
// for the same warmup barrier.
func (s *Sync) WarmupComplete() bool { return s.AllLoaded() }

// UsedHub reports whether the pull fell back to the hub.
func (s *Sync) UsedHub() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failover
}

// Blob returns a loaded blob's bytes by name.
func (s *Sync) Blob(name string) ([]byte, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.loaded[name]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), data...), true
}

func (s *Sync) pullHub(ctx context.Context, manifest Manifest, hub HubRepo) error {
	for _, entry := range sortedEntries(manifest) {
		b := entry.Blob
		if b.Version == 0 {
			b.Version = manifest.Version
		}
		data, err := hub.Fetch(ctx, b)
		if err != nil {
			return fmt.Errorf("sync pull: hub fetch %q: %w", b.Name, err)
		}
		if err := verifyBytes(b, data); err != nil {
			return fmt.Errorf("sync pull: hub fetch %q: %w", b.Name, err)
		}
		s.put(b, data)
	}
	return nil
}

func (s *Sync) has(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.loaded[name]
	return ok
}

func (s *Sync) put(b Blob, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loaded[b.Name] = append([]byte(nil), data...)
}

func (s *Sync) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loaded = make(map[string][]byte)
}

func (s *Sync) setFailover() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failover = true
}

func pullFromPeers(ctx context.Context, fetcher PeerFetcher, peers []netaddr.EndpointAddr, b Blob) ([]byte, error) {
	var last error
	for _, peer := range peers {
		data, err := fetcher.Fetch(ctx, peer, b)
		if err != nil {
			last = err
			continue
		}
		if err := verifyBytes(b, data); err != nil {
			last = err
			continue
		}
		return data, nil
	}
	if last != nil {
		return nil, fmt.Errorf("sync pull: peer fetch %q: %w", b.Name, last)
	}
	return nil, fmt.Errorf("sync pull: no peers for %q", b.Name)
}

func sortedEntries(manifest Manifest) []Entry {
	out := append([]Entry(nil), manifest.Entries...)
	sort.Slice(out, func(i, j int) bool {
		return out[i].Blob.Name < out[j].Blob.Name
	})
	return out
}

// NewBlob returns the metadata describing data under name and version, computing
// its content hash so a caller never sets Hash by hand. The hash is the same
// BLAKE3 hash [verifyBytes] checks on pull, so a blob built here always verifies.
func NewBlob(name string, version uint64, data []byte) (Blob, error) {
	b := Blob{Name: name, Version: version, Hash: blobs.NewHash(data).Bytes(), Size: uint64(len(data))}
	if err := validateBlob(b); err != nil {
		return Blob{}, err
	}
	return b, nil
}

func validateBlob(b Blob) error {
	if b.Name == "" {
		return fmt.Errorf("empty name")
	}
	if b.Version == 0 {
		return fmt.Errorf("zero version")
	}
	if b.Hash == ([32]byte{}) {
		return fmt.Errorf("empty hash")
	}
	return nil
}

func verifyBytes(b Blob, data []byte) error {
	if uint64(len(data)) != b.Size {
		return fmt.Errorf("size %d does not match manifest %d", len(data), b.Size)
	}
	if got := blobs.NewHash(data).Bytes(); !bytes.Equal(got[:], b.Hash[:]) {
		return fmt.Errorf("hash mismatch")
	}
	return nil
}
