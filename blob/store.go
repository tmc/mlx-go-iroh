package blob

import (
	"sync"

	"github.com/tmc/go-iroh/blobs"
)

// MemoryStore is a concurrency-safe in-memory [Store]. It is the zero-config
// store for tests and small caches; a node that must survive a restart backs
// its blobs with a go-iroh FSStore instead.
//
// The zero value is not usable; construct with [NewMemoryStore].
type MemoryStore struct {
	mu    sync.RWMutex
	blobs map[Hash][]byte
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{blobs: make(map[Hash][]byte)}
}

// Put stores data under its content hash and returns the hash, so the caller can
// name it in a manifest or ticket.
func (s *MemoryStore) Put(data []byte) Hash {
	h := blobs.NewHash(data)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blobs[h] = append([]byte(nil), data...)
	return h
}

// GetBlob returns the bytes stored under hash, satisfying [Store].
func (s *MemoryStore) GetBlob(hash Hash) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.blobs[hash]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), data...), true
}

// Len reports the number of stored blobs.
func (s *MemoryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.blobs)
}
