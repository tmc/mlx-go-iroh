package irohmesh

import (
	"context"
	"iter"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// DefaultDiscoveryTopic is the gossip topic endpoints publish and resolve
// addressing on by default. It reuses go-iroh's default discovery topic; a
// namespaced topic is a one-line change at [NewGossipDiscovery] call sites.
var DefaultDiscoveryTopic = gossip.DefaultDiscoveryTopic

// Discovery is the backend-agnostic endpoint-discovery seam. Its method set
// mirrors go-iroh's gossip discovery so the backend is a private implementation
// detail: Publish advertises this node's addressing, and Resolve is a
// subscription that re-emits a peer's addressing as it changes.
//
// Resolve returning iter.Seq2[iroh.Item, error] leaks the iroh.Item type, the
// one deliberate seam leak; discovery is intrinsically about go-iroh addressing.
type Discovery interface {
	// Start joins the discovery topic and begins publishing/resolving. It blocks
	// until ctx is cancelled, like the underlying gossip backend.
	Start(ctx context.Context) error
	// Publish advertises this node's endpoint addressing to the swarm.
	Publish(data dns.EndpointData)
	// Resolve subscribes to a peer's addressing, yielding its iroh.Item each
	// time the swarm learns a fresher address for it.
	Resolve(ctx context.Context, id key.EndpointID) iter.Seq2[iroh.Item, error]
}

// gossipDiscovery adapts go-iroh's gossip discovery to the [Discovery] seam. It
// carries the gossip protocol instance so [Endpoint.Serve] can register its
// handler on the shared router under gossip.ALPN.
type gossipDiscovery struct {
	d *gossip.Discovery
	g *gossip.Gossip
}

// NewGossipDiscovery builds a gossip-backed [Discovery] over a bound endpoint
// for the given topic. The returned Discovery carries the gossip protocol
// handler internally; [Endpoint.Serve] registers it under gossip.ALPN on the
// shared router, so the same endpoint serves both the application ALPN and
// gossip.ALPN. bootstrap is the swarm's reachable seed peers (see
// [RosterBootstrap] and [ParseBootstraps]).
//
// The gossip discovery is registered as a resolver on the endpoint's lookup
// services, so [Endpoint.ResolveAddr] and [Endpoint.ConnectID] can dial a peer
// known only by id once the swarm has learned its address.
func NewGossipDiscovery(ep *Endpoint, topic gossip.TopicID, bootstrap []netaddr.EndpointAddr) Discovery {
	g := ep.gossipProto()
	d := gossip.New(ep.ep.ID(), gossip.WithGossip(g, topic, bootstrap))
	ep.lookup.AddResolver(d)
	return &gossipDiscovery{d: d, g: g}
}

func (g *gossipDiscovery) Start(ctx context.Context) error { return g.d.Start(ctx) }

func (g *gossipDiscovery) Publish(data dns.EndpointData) { g.d.Publish(data) }

func (g *gossipDiscovery) Resolve(ctx context.Context, id key.EndpointID) iter.Seq2[iroh.Item, error] {
	return g.d.Resolve(ctx, id)
}
