package irohmesh

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/tmc/go-iroh/endpointticket"
	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// ErrInvalid reports invalid endpoint input or state.
var ErrInvalid = errors.New("irohmesh: invalid")

// Config is the validated set of go-iroh endpoint inputs [Bind] needs.
//
// Identity, when set, is the node's ed25519 key used directly as the go-iroh
// endpoint key, so the wire EndpointID is the same key a roster records and a
// ledger signs with. It takes precedence over SecretKey, which remains for a
// string-encoded key (e.g. an operator environment variable). When neither is
// set, Bind generates an ephemeral key.
//
// BindAddr is an "ip:port" address; an empty value uses the go-iroh default
// (an ephemeral port on all interfaces).
//
// The zero Config is usable: it binds an ephemeral endpoint with a generated
// identity.
type Config struct {
	BindAddr  string
	SecretKey string
	Identity  ed25519.PrivateKey
}

// Endpoint is a bound go-iroh endpoint. After [Endpoint.Serve] it also owns the
// iroh.Router that runs the accept loop for the application and gossip ALPNs.
// Construct with [Bind]; the zero value is unusable.
type Endpoint struct {
	ep     *iroh.Endpoint
	router *iroh.Router                // nil until Serve; owns the accept loop and endpoint close
	lookup *iroh.AddressLookupServices // address resolvers (gossip, pkarr, dns)

	gossipOnce sync.Once
	gossip     *gossip.Gossip // lazily created; shared by Serve, discovery, Subscribe
}

// Bind validates cfg and binds a go-iroh endpoint WITHOUT registering ALPNs:
// the router started by [Endpoint.Serve] owns the accept loop, so the endpoint
// must not already be listening. [Endpoint.Connect] (the dial path) works on a
// bound endpoint with no Serve. The caller owns [Endpoint.Close].
func Bind(ctx context.Context, cfg Config) (*Endpoint, error) {
	var opts []iroh.Option
	switch {
	case len(cfg.Identity) == ed25519.PrivateKeySize:
		sk, err := key.SecretKeyFromEd25519(cfg.Identity)
		if err != nil {
			return nil, fmt.Errorf("%w: identity key: %v", ErrInvalid, err)
		}
		opts = append(opts, iroh.WithSecretKey(sk))
	case cfg.SecretKey != "":
		sk, err := key.ParseSecretKey(cfg.SecretKey)
		if err != nil {
			return nil, fmt.Errorf("%w: secret key: %v", ErrInvalid, err)
		}
		opts = append(opts, iroh.WithSecretKey(sk))
	}
	if cfg.BindAddr != "" {
		addr, err := netip.ParseAddrPort(cfg.BindAddr)
		if err != nil {
			return nil, fmt.Errorf("%w: bind addr: %v", ErrInvalid, err)
		}
		opts = append(opts, iroh.WithBindAddr(addr))
	}
	// Own the address-lookup registry so the endpoint can resolve a bare
	// EndpointID after bind (see Endpoint.ResolveAddr/ConnectID). A
	// gossip-backed Discovery registers itself here as a resolver, and pkarr or
	// DNS services can be added by the caller.
	lookup := new(iroh.AddressLookupServices)
	opts = append(opts, iroh.WithAddressLookup(lookup))
	ep, err := iroh.Bind(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("bind irohmesh endpoint: %w", err)
	}
	return &Endpoint{ep: ep, lookup: lookup}, nil
}

// ID returns the bound endpoint's identity key.
func (e *Endpoint) ID() key.EndpointID { return e.ep.ID() }

// Addr returns the endpoint's advertised address (identity plus any known
// transport addresses), the form a peer dials.
func (e *Endpoint) Addr() netaddr.EndpointAddr { return e.ep.Addr() }

// LocalAddr returns the endpoint's bound UDP address. Combined with [Endpoint.ID]
// via netaddr.NewEndpointAddr(id).WithIP(localAddr), it forms a dialable seed
// address for a peer on a known host — the loopback and seed-list case.
func (e *Endpoint) LocalAddr() netip.AddrPort { return e.ep.LocalAddr() }

// DialableAddr returns this endpoint's id paired with its bound local address, a
// dialable seed a peer can bootstrap from without discovery.
func (e *Endpoint) DialableAddr() netaddr.EndpointAddr {
	return netaddr.NewEndpointAddr(e.ep.ID()).WithIP(e.ep.LocalAddr())
}

// Ticket returns an endpointticket-encoded address for this endpoint at addr,
// so a connector can dial it without discovery. Used to point one endpoint at
// another on a known address (e.g. a loopback test or a seed list).
func (e *Endpoint) Ticket(addr netip.AddrPort) string {
	return endpointticket.Encode(netaddr.NewEndpointAddr(e.ep.ID(), netaddr.IPAddr{Addr: addr}))
}

// LocalTicket returns the ticket for this endpoint at its actual bound local
// address, so a node can publish its dial address without the caller knowing
// the resolved port (the ephemeral-bind case).
func (e *Endpoint) LocalTicket() string {
	return e.Ticket(e.ep.LocalAddr())
}

// Handler runs one accepted connection to completion. The endpoint wraps the
// go-iroh connection as a *[Conn] before calling it, so a handler never sees
// go-iroh. ctx is cancelled when the endpoint shuts down. The handler owns the
// connection lifetime and must Close it; a returned error closes only that
// connection and is not fatal to the accept loop.
type Handler func(ctx context.Context, conn *Conn) error

// Serve starts the iroh.Router on this endpoint: it registers appALPN to h and,
// when disc carries a gossip handler, gossip.ALPN to it — one router serving
// both ALPNs. disc may be nil for an endpoint with no discovery. Serve returns
// once the accept loop is running in the background; it does not block. It must
// be called at most once, on an endpoint bound without ALPNs. After Serve,
// [Endpoint.Close] shuts the router (and the endpoint) down.
func (e *Endpoint) Serve(appALPN string, h Handler, disc Discovery) error {
	if e.router != nil {
		return fmt.Errorf("%w: endpoint already serving", ErrInvalid)
	}
	if appALPN == "" {
		return fmt.Errorf("%w: empty app alpn", ErrInvalid)
	}
	if h == nil {
		return fmt.Errorf("%w: nil handler", ErrInvalid)
	}
	handlers := map[string]iroh.ProtocolHandler{
		appALPN: iroh.ProtocolHandlerFunc(func(ctx context.Context, ic *iroh.Conn) error {
			return h(ctx, &Conn{conn: ic}) // wrap: go-iroh is fenced here
		}),
	}
	// Register gossip.ALPN whenever gossip is in play: a gossip Discovery, or a
	// Subscribe that created the endpoint's gossip instance before Serve. Both
	// share the one gossip handler.
	if _, ok := disc.(*gossipDiscovery); ok || e.gossip != nil {
		handlers[gossip.ALPN] = e.gossipProto().Handler()
	}
	r, err := iroh.NewRouter(e.ep, handlers, nil)
	if err != nil {
		return fmt.Errorf("serve irohmesh router: %w", err)
	}
	e.router = r
	return nil
}

// Connect dials the peer named by ticket on alpn and returns the resulting
// *[Conn]. ticket is an endpointticket-encoded peer address that already carries
// dialable transport addresses. The caller owns Close on the returned
// connection. To dial a peer known only by its id, use [Endpoint.ConnectID].
func (e *Endpoint) Connect(ctx context.Context, ticket, alpn string) (*Conn, error) {
	if alpn == "" {
		return nil, fmt.Errorf("%w: empty alpn", ErrInvalid)
	}
	addr, err := endpointticket.Decode(ticket)
	if err != nil {
		return nil, fmt.Errorf("%w: peer ticket: %v", ErrInvalid, err)
	}
	return e.ConnectAddr(ctx, addr, alpn)
}

// ConnectAddr dials addr on alpn. addr must carry at least one transport address
// (IP, relay, or custom); a bare-id addr fails, since go-iroh's Connect does not
// resolve addresses before dialing. Use [Endpoint.ConnectID] to resolve a bare
// id first.
func (e *Endpoint) ConnectAddr(ctx context.Context, addr netaddr.EndpointAddr, alpn string) (*Conn, error) {
	if alpn == "" {
		return nil, fmt.Errorf("%w: empty alpn", ErrInvalid)
	}
	conn, err := e.ep.Connect(ctx, addr, alpn)
	if err != nil {
		return nil, fmt.Errorf("connect irohmesh peer: %w", err)
	}
	return &Conn{conn: conn}, nil
}

// ResolveAddr resolves a bare endpoint id to a dialable address through the
// endpoint's address-lookup services (gossip discovery, and any pkarr or DNS
// resolver the caller added). It returns the first result whose address is
// non-empty, or an error if no service yields one. It exists because go-iroh's
// Connect consults lookup services only after a connection is established, so a
// peer known only by id cannot be dialed without resolving first.
func (e *Endpoint) ResolveAddr(ctx context.Context, id key.EndpointID) (netaddr.EndpointAddr, error) {
	for item, err := range e.lookup.Resolve(ctx, id) {
		if err != nil {
			return netaddr.EndpointAddr{}, fmt.Errorf("resolve %s: %w", id.Short(), err)
		}
		if addr := item.Addr(); !addr.IsEmpty() {
			return addr, nil
		}
	}
	return netaddr.EndpointAddr{}, fmt.Errorf("resolve %s: no address from lookup services", id.Short())
}

// ConnectID resolves a bare endpoint id through the lookup services and dials
// the resulting address on alpn. It is the global-discovery dial path: a peer is
// reached by id alone, with discovery supplying the address. When the only
// resolver is gossip, the peer must be reachable through the discovery swarm.
func (e *Endpoint) ConnectID(ctx context.Context, id key.EndpointID, alpn string) (*Conn, error) {
	addr, err := e.ResolveAddr(ctx, id)
	if err != nil {
		return nil, err
	}
	return e.ConnectAddr(ctx, addr, alpn)
}

// LookupServices returns the endpoint's address-lookup registry, so a caller can
// add a pkarr, DNS, or in-memory resolver beyond the gossip discovery that
// [NewGossipDiscovery] registers. Resolvers added here back [Endpoint.ResolveAddr]
// and [Endpoint.ConnectID].
func (e *Endpoint) LookupServices() *iroh.AddressLookupServices { return e.lookup }

// Endpoint exposes the underlying go-iroh endpoint for the blob and manifest
// layers, which need it to open blob streams. It is the one deliberate seam
// leak, scoped to this module's own sub-packages; application code stays on the
// fenced [Conn]/[Discovery] surface.
func (e *Endpoint) Endpoint() *iroh.Endpoint { return e.ep }

// gossipProto returns the endpoint's single gossip instance, created on first
// use. Discovery and [Endpoint.Subscribe] share it so one router handler under
// gossip.ALPN serves both.
func (e *Endpoint) gossipProto() *gossip.Gossip {
	e.gossipOnce.Do(func() { e.gossip = gossip.NewGossip(e.ep) })
	return e.gossip
}

// Subscribe joins the gossip topic and returns it for signed publish/receive via
// [PublishSigned] and [VerifiedEnvelopes]. bootstrap seeds the swarm. The topic
// shares the endpoint's gossip instance, so [Endpoint.Serve] must register the
// gossip ALPN (it does whenever a gossip Discovery or any Subscribe is in use).
// The caller closes the returned topic.
func (e *Endpoint) Subscribe(ctx context.Context, topic gossip.TopicID, bootstrap []netaddr.EndpointAddr) (*gossip.Topic, error) {
	t, err := e.gossipProto().Subscribe(ctx, topic, bootstrap)
	if err != nil {
		return nil, fmt.Errorf("subscribe topic: %w", err)
	}
	return t, nil
}

// Close shuts the endpoint down. After Serve it routes through router.Shutdown,
// which cancels the accept loop, runs handler Shutdown hooks, and closes the
// endpoint. Before Serve it closes the endpoint directly. Shutdown is
// idempotent, so a redundant Close is safe.
func (e *Endpoint) Close() error {
	if e.router != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return e.router.Shutdown(ctx)
	}
	return e.ep.Shutdown(context.Background())
}
