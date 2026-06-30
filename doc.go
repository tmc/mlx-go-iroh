// Package irohmesh is a transport substrate over [go-iroh]: the endpoint
// bring-up, connection, discovery, and bootstrap ritual that every go-iroh mesh
// consumer otherwise hand-rolls, plus the two primitives layered on top of it —
// ed25519 node identity and signed-JSON gossip.
//
// The substrate fences go-iroh: callers see [net.Conn] streams and a
// backend-agnostic [Discovery], never the underlying iroh.Conn or gossip types.
// Bind a [NodeKey] as the endpoint identity, Serve an application ALPN, dial a
// peer by ticket, and run a protocol over a plain [net.Conn].
//
// The blob content-addressed store lives in [github.com/tmc/mlx-go-iroh/blob]
// and the manifest pull-with-hub-fallback in
// [github.com/tmc/mlx-go-iroh/manifest]. Both depend only on go-iroh.
//
// irohmesh has no mlx-go dependency: its name marks the ecosystem family, not a
// dependency. The only imports are go-iroh, golang.org/x, and the standard
// library, so a consumer pins go-iroh once through this module.
//
// [go-iroh]: https://github.com/tmc/go-iroh
package irohmesh
