package irohmesh

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"iter"

	"github.com/tmc/go-iroh/gossip"
)

// MaxGossipFrame is the maximum size of a single gossip message payload. The
// go-iroh gossip layer caps frames here, which is what forces control messages
// to stay small (heartbeats, commands) and pushes anything large (checkpoints)
// onto the blob path. [SignEnvelope] asserts the signed payload fits.
const MaxGossipFrame = 4096

// envelopeDomain separates envelope signatures from any other signature a node
// key produces, so a signed envelope can never be replayed as a different
// signed record (or vice versa).
const envelopeDomain = "mlx-go-iroh/gossip-envelope/v1\x00"

// SignedEnvelope is a gossip message carrying an application payload signed by
// the sending node. The shared layer owns only the envelope (identity +
// signature + size bound); Payload is OPAQUE bytes the application serializes
// however it likes — JSON for new payloads, or a domain-tagged binary form for a
// payload whose signature must be reproducible across implementations. The
// envelope never inspects or re-serializes Payload, so no domain type leaks into
// this module and a binary signed payload survives byte-for-byte.
//
// The wire form is the JSON encoding of this struct; NodeID, Payload, and Sig
// are base64 by encoding/json's []byte handling. (The JSON is the outer
// transport framing only — it does not touch the bytes the signature covers.)
type SignedEnvelope struct {
	NodeID  []byte `json:"node_id"` // ed25519 public key of the signer
	Payload []byte `json:"payload"` // opaque application bytes
	Sig     []byte `json:"sig"`     // signature over envelopeDomain||Payload
}

// SignEnvelope wraps payload in an envelope signed by k. payload is treated as
// opaque bytes: it is signed and carried verbatim, never re-serialized. It
// returns an error if the resulting wire message would exceed [MaxGossipFrame],
// so an oversized control message fails at the sender rather than being silently
// dropped by the gossip layer.
func SignEnvelope(k NodeKey, payload []byte) (SignedEnvelope, error) {
	pub := k.Public()
	env := SignedEnvelope{
		NodeID:  append([]byte(nil), pub...),
		Payload: append([]byte(nil), payload...),
		Sig:     k.Sign(envelopePayload(payload)),
	}
	wire, err := json.Marshal(env)
	if err != nil {
		return SignedEnvelope{}, fmt.Errorf("sign envelope: marshal: %w", err)
	}
	if len(wire) > MaxGossipFrame {
		return SignedEnvelope{}, fmt.Errorf("sign envelope: wire size %d exceeds MaxGossipFrame %d", len(wire), MaxGossipFrame)
	}
	return env, nil
}

// Verify reports whether the envelope is well formed and its signature is valid
// for NodeID over the payload. A verified envelope means the bytes in Payload
// were signed by the holder of NodeID's key; it says nothing about the contents.
func (e SignedEnvelope) Verify() error {
	if len(e.NodeID) != ed25519.PublicKeySize {
		return fmt.Errorf("envelope node id has length %d", len(e.NodeID))
	}
	if len(e.Sig) != ed25519.SignatureSize {
		return fmt.Errorf("envelope signature has length %d", len(e.Sig))
	}
	if !ed25519.Verify(e.NodeID, envelopePayload(e.Payload), e.Sig) {
		return errors.New("invalid envelope signature")
	}
	return nil
}

func envelopePayload(payload []byte) []byte {
	out := make([]byte, 0, len(envelopeDomain)+len(payload))
	out = append(out, envelopeDomain...)
	out = append(out, payload...)
	return out
}

// PublishSigned signs payload with k and broadcasts it to the topic. It is the
// send half of the signed-gossip pattern: the application serializes its own
// message (JSON or binary), this wraps and broadcasts it under the size bound.
func PublishSigned(ctx context.Context, topic *gossip.Topic, k NodeKey, payload []byte) error {
	if topic == nil {
		return fmt.Errorf("publish signed: nil topic")
	}
	env, err := SignEnvelope(k, payload)
	if err != nil {
		return err
	}
	wire, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("publish signed: marshal: %w", err)
	}
	if err := topic.Broadcast(ctx, wire); err != nil {
		return fmt.Errorf("publish signed: broadcast: %w", err)
	}
	return nil
}

// VerifiedEnvelopes iterates the topic's received messages, decoding and
// verifying each as a [SignedEnvelope] and yielding only those that pass. A
// message that does not decode, fails verification, or is not a received-content
// event is skipped, so the iterator yields exactly the authenticated payloads.
// It ends when the topic's event stream ends or ctx is cancelled; a transport
// error from the underlying stream is yielded with a zero envelope.
func VerifiedEnvelopes(topic *gossip.Topic) iter.Seq2[SignedEnvelope, error] {
	return func(yield func(SignedEnvelope, error) bool) {
		for ev, err := range topic.Events() {
			if err != nil {
				if !yield(SignedEnvelope{}, err) {
					return
				}
				continue
			}
			if len(ev.Content) == 0 {
				continue // neighbor up/down, peer data — not a payload
			}
			var env SignedEnvelope
			if json.Unmarshal(ev.Content, &env) != nil {
				continue
			}
			if env.Verify() != nil {
				continue
			}
			if !yield(env, nil) {
				return
			}
		}
	}
}
