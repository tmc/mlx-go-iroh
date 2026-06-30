// SPDX-License-Identifier: MIT

package irohmesh

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
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

// ParseBootstraps parses a list of endpointID@transportAddr bootstrap strings.
// A single malformed entry fails the whole list, since a seed list is operator
// input where a typo should surface, not be silently dropped.
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

// ParseBootstrap parses one endpointID@transportAddr bootstrap string into a
// dialable EndpointAddr. Unlike [RosterBootstrap]'s addr-less ids, this yields a
// seed the swarm can dial immediately.
func ParseBootstrap(s string) (netaddr.EndpointAddr, error) {
	idText, addrText, ok := strings.Cut(s, "@")
	if !ok {
		return netaddr.EndpointAddr{}, fmt.Errorf("bootstrap %q: want endpointID@transportAddr", s)
	}
	id, err := key.ParseEndpointID(idText)
	if err != nil {
		return netaddr.EndpointAddr{}, fmt.Errorf("bootstrap %q: parse endpoint id: %w", s, err)
	}
	addr, err := netaddr.ParseTransportAddr(addrText)
	if err != nil {
		return netaddr.EndpointAddr{}, fmt.Errorf("bootstrap %q: parse transport addr: %w", s, err)
	}
	return netaddr.NewEndpointAddr(id, addr), nil
}
