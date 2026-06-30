# mlx-go-iroh

A shared transport substrate over [go-iroh](https://github.com/tmc/go-iroh): the
endpoint bring-up, connection, discovery, and bootstrap ritual that every go-iroh
mesh consumer otherwise hand-rolls, plus two primitives layered on top —
ed25519 node identity and signed-JSON gossip — and content-addressed blob and
manifest helpers.

It depends only on go-iroh, `golang.org/x`, and the standard library. The
`mlx-go` in the name marks the ecosystem family, not a dependency: there is no
mlx-go import. A consumer pins go-iroh once, through this module.

## Packages

| Package | What it provides |
| --- | --- |
| `irohmesh` | Endpoint bring-up (`Bind`/`Serve`/`Connect`/`ConnectID`), fenced `Conn` (net.Conn streams), backend-agnostic `Discovery` + `NewGossipDiscovery`, `RosterBootstrap`/`ParseBootstrap`, `NodeKey` ed25519 identity, and `SignedEnvelope` signed gossip. |
| `irohmesh/blob` | `[]byte` ⇄ BAO-verified blob content-addressed store: `Encode`/`Decode`, `Ticket`, `Serve`/`Fetch`, and a `MemoryStore`. |
| `irohmesh/manifest` | Pull a content-addressed set of blobs from peers, falling back to a hub when no peer can serve one: `Sync.Pull` with `PeerFetcher`/`HubRepo`. |

The substrate fences go-iroh: callers see `net.Conn` streams and a
`Discovery` interface, never the underlying `iroh.Conn` or gossip types.

## Example

```go
ep, err := irohmesh.Bind(ctx, irohmesh.Config{Identity: myKey.Ed25519()})
if err != nil {
	return err
}
defer ep.Close()

// Serve an application protocol; discovery is optional.
err = ep.Serve("myapp/v1", func(ctx context.Context, conn *irohmesh.Conn) error {
	s, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	// ... run a protocol over the net.Conn ...
	return nil
}, nil)

// Dial a peer you have a ticket for.
conn, err := ep.Connect(ctx, ticket, "myapp/v1")
```

## Status

Substrate, identity, gossip, blob, and manifest layers are implemented and
tested. The blob and manifest layers carry bytes only; a typed codec (for
example mlx arrays) wraps them in the consuming module.
