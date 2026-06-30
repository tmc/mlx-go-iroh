// SPDX-License-Identifier: MIT

// Package blob is a content-addressed byte store over go-iroh blobs: hash some
// bytes to get a [Hash], serve them to peers, and pull them back BAO-verified so
// a corrupt or hostile peer cannot substitute different bytes. It carries no
// domain types — a model-parameter or checkpoint codec wraps these byte
// primitives rather than the reverse.
package blob

import (
	"context"
	"fmt"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

// ALPN is the go-iroh blobs protocol identifier, the ALPN a peer dials to fetch
// a blob and the one a [Store] serves under.
const ALPN = blobs.ALPN

// Hash is the BLAKE3 content hash of a blob, the capability that names it: a
// puller that knows the hash can verify any served bytes against it, so the hash
// itself is the access token.
type Hash = blobs.Hash

// HashBytes returns the content hash of data without encoding it, for naming a
// blob in a manifest before it is served.
func HashBytes(data []byte) Hash { return blobs.NewHash(data) }

// Encode returns data's content hash and its BAO-encoded form. The encoded form
// carries the BLAKE3 verification tree so a puller streams and verifies it
// incrementally; [Decode] checks it against the hash.
func Encode(data []byte) (Hash, []byte, error) {
	h, enc, err := blobs.EncodeBlob(data)
	if err != nil {
		return Hash{}, nil, fmt.Errorf("encode blob: %w", err)
	}
	return h, enc, nil
}

// Decode verifies encoded against want and returns the original bytes. It fails
// if the encoded bytes do not hash to want, so a puller never accepts
// unverified data.
func Decode(want Hash, encoded []byte) ([]byte, error) {
	data, err := blobs.DecodeBlob(want, encoded)
	if err != nil {
		return nil, fmt.Errorf("decode blob: %w", err)
	}
	return data, nil
}

// Ticket combines a peer's address with a blob hash into one shareable token, so
// a single string names both who has a blob and which blob it is.
func Ticket(addr netaddr.EndpointAddr, h Hash) string {
	return blobs.NewTicket(addr, h, blobs.Raw).String()
}

// ParseTicket parses a ticket string into its address and hash.
func ParseTicket(s string) (netaddr.EndpointAddr, Hash, error) {
	t, err := blobs.ParseTicket(s)
	if err != nil {
		return netaddr.EndpointAddr{}, Hash{}, fmt.Errorf("parse ticket: %w", err)
	}
	return t.Addr(), t.Hash(), nil
}

// Store serves raw blobs by hash. [MemoryStore] and a go-iroh FSStore both
// satisfy it; pass one to [Serve].
type Store = blobs.Store

// Serve streams the blob the peer requests over s, reading it from store. It is
// the provider half: register it under [ALPN] on a router so peers can pull.
func Serve(ctx context.Context, s blobs.BidiStream, store Store) error {
	return blobs.ServeBlob(ctx, s, store)
}

// Fetch pulls the blob named by h from a connected peer stream and BAO-verifies
// it against h. s is a stream opened on a connection dialed with [ALPN].
func Fetch(ctx context.Context, s blobs.BidiStream, h Hash) ([]byte, error) {
	data, err := blobs.GetBlobBytes(ctx, s, h)
	if err != nil {
		return nil, fmt.Errorf("fetch blob: %w", err)
	}
	return data, nil
}

// FetchFromPeer dials peer over [ALPN] using ep, pulls the blob named by h, and
// BAO-verifies it. It is the convenience path for a one-shot pull when the
// caller has only an endpoint and a ticket's parts.
func FetchFromPeer(ctx context.Context, ep *iroh.Endpoint, peer netaddr.EndpointAddr, h Hash) ([]byte, error) {
	conn, err := ep.Connect(ctx, peer, ALPN)
	if err != nil {
		return nil, fmt.Errorf("fetch from peer: connect: %w", err)
	}
	defer conn.CloseWithError(0, "")
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch from peer: open stream: %w", err)
	}
	return Fetch(ctx, s, h)
}
