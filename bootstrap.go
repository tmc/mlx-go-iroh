// SPDX-License-Identifier: MIT

package irohmesh

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// RosterBootstrap maps a roster's ed25519 public keys (base64 std encoding) to
// the EndpointAddrs a gossip swarm seeds its join from. self is omitted so a
// node never bootstraps off itself. The addresses are intentionally empty:
// under the unified-key model a roster pubkey IS an endpoint id, so the swarm
// dials members it discovers an address for, and the allow-list is the roster
// itself. A row that does not decode to a valid ed25519 key is skipped —
// fail-soft on one malformed row rather than refusing the whole mesh.
func RosterBootstrap(rosterPubsBase64 []string, self key.EndpointID) ([]netaddr.EndpointAddr, error) {
	out := make([]netaddr.EndpointAddr, 0, len(rosterPubsBase64))
	for _, b64 := range rosterPubsBase64 {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		id, err := key.EndpointIDFromSlice(raw)
		if err != nil {
			continue
		}
		if id == self {
			continue
		}
		out = append(out, netaddr.NewEndpointAddr(id))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: roster yielded no bootstrap peers", ErrInvalid)
	}
	return out, nil
}

// ParseBootstraps parses a list of bootstrap strings (see [ParseBootstrap] for
// the accepted forms). A single malformed entry fails the whole list, since a
// seed list is operator input where a typo should surface, not be silently
// dropped.
func ParseBootstraps(values []string) ([]netaddr.EndpointAddr, error) {
	addrs := make([]netaddr.EndpointAddr, 0, len(values))
	for _, value := range values {
		addr, err := ParseBootstrap(value)
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

// ParseBootstrap parses one bootstrap string into an EndpointAddr. It accepts
// three forms:
//
//   - "endpointID@kind:value" — a transport address in go-iroh's kind-prefixed
//     form, e.g. "id@ip:127.0.0.1:9000" or a relay or custom address.
//   - "endpointID@host:port" — a bare IP socket address, shorthand for the ip:
//     form, e.g. "id@127.0.0.1:9000".
//   - "endpointID" — a bare global identity with no transport address. It is
//     resolved at dial time through the endpoint's lookup services (pkarr or
//     DNS), so it dials only from an endpoint bound with [Config].Pkarr or
//     another resolver; a gossip/LAN-only endpoint yields no address for it.
//
// The "@" forms yield a seed the swarm can dial immediately, like a roster entry
// that already carries an address; the bare form yields an addr-less
// EndpointAddr, like a [RosterBootstrap] entry, whose address discovery supplies.
func ParseBootstrap(s string) (netaddr.EndpointAddr, error) {
	idText, addrText, ok := strings.Cut(s, "@")
	if !ok {
		// Bare id: a global identity resolved through lookup services at dial time.
		id, err := key.ParseEndpointID(s)
		if err != nil {
			return netaddr.EndpointAddr{}, fmt.Errorf("bootstrap %q: want endpointID, endpointID@host:port, or endpointID@kind:value", s)
		}
		return netaddr.NewEndpointAddr(id), nil
	}
	id, err := key.ParseEndpointID(idText)
	if err != nil {
		return netaddr.EndpointAddr{}, fmt.Errorf("bootstrap %q: parse endpoint id: %w", s, err)
	}
	// Kind-prefixed transport address (ip/relay/custom). Tried first so a string
	// that was valid before this function accepted the host:port shorthand still
	// parses identically. The two forms are disjoint: ParseTransportAddr requires
	// a "kind:" prefix, which ParseAddrPort rejects.
	if addr, err := netaddr.ParseTransportAddr(addrText); err == nil {
		return netaddr.NewEndpointAddr(id, addr), nil
	}
	// Bare host:port shorthand for an ip: address.
	if ap, err := netip.ParseAddrPort(addrText); err == nil {
		return netaddr.NewEndpointAddr(id).WithIP(ap), nil
	}
	return netaddr.EndpointAddr{}, fmt.Errorf("bootstrap %q: address %q is neither kind:value nor host:port", s, addrText)
}
