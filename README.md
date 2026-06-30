# mlx-go-iroh

A shared transport substrate over [go-iroh](https://github.com/tmc/go-iroh): the
endpoint bring-up, connection, discovery, and bootstrap ritual that every go-iroh
mesh consumer otherwise hand-rolls, plus two primitives layered on top —
ed25519 node identity and signed-JSON gossip — and content-addressed blob and
manifest helpers. An endpoint is gossip/LAN by default and goes global —
reachable by bare EndpointID across the internet via a pkarr relay — with two
`Config` flags.

It depends only on go-iroh, `golang.org/x`, and the standard library. The
`mlx-go` in the name marks the ecosystem family, not a dependency: there is no
mlx-go import. A consumer pins go-iroh once, through this module.

The root package is named `irohmesh`, not `mlx_go_iroh` — import the module
path and refer to the package by its name:

```go
import "github.com/tmc/mlx-go-iroh"          // package irohmesh
import "github.com/tmc/mlx-go-iroh/blob"     // package blob
import "github.com/tmc/mlx-go-iroh/manifest" // package manifest
```

## Packages

| Package | What it provides |
| --- | --- |
| `irohmesh` | Endpoint bring-up (`Bind`/`Serve`/`Connect`/`ConnectID`), fenced `Conn` (net.Conn streams), backend-agnostic `Discovery` + `NewGossipDiscovery`, `RosterBootstrap`/`ParseBootstrap`, `NodeKey` ed25519 identity, `SignedEnvelope` signed gossip, and a global `Config.Pkarr`/`Config.Relay` tier (`WaitOnline`) for bare-id reachability across the internet. |
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

## Global discovery

By default an endpoint is reachable on the LAN and through the gossip swarm. To
make it reachable by bare `EndpointID` from anywhere, bind with `Pkarr` and
`Relay`: `Bind` registers a pkarr publisher and resolver on the endpoint's
lookup services and republishes the node's address as it changes, so the same
`ResolveAddr`/`ConnectID` that do gossip dials now resolve globally. There is no
new dial API.

```go
// A globally reachable seeder.
ep, err := irohmesh.Bind(ctx, irohmesh.Config{
	Identity: myKey.Ed25519(),
	Relay:    true, // relay-assisted connectivity for NAT'd peers
	Pkarr:    true, // publish + resolve EndpointID→address via a pkarr relay
})
if err != nil {
	return err
}
defer ep.Close() // tears down the publisher and publish loop too

// Wait for a relay before advertising the id, so the published address is reachable.
if err := ep.WaitOnline(ctx); err != nil {
	return err
}
advertise(ep.ID())

// A peer anywhere dials by id alone; pkarr supplies the address.
conn, err := ep.ConnectID(ctx, peerID, "myapp/v1")
```

`PkarrRelayURL` overrides the relay (default: the number0 production relay), and
`PublishAllAddrs` publishes direct IPs in addition to relay addresses (default:
relay-only, leaking fewer addresses). The flags default off, so a Config that
sets neither binds exactly the gossip/LAN endpoint as before.

## Status

Substrate, identity, gossip, global pkarr/relay discovery, blob, and manifest
layers are implemented and tested. The blob and manifest layers carry bytes
only; a typed codec (for example mlx arrays) wraps them in the consuming module.
