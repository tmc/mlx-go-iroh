// SPDX-License-Identifier: MIT

package irohmesh_test

import (
	"net/netip"
	"testing"

	"github.com/tmc/go-iroh/endpointticket"
	irohmesh "github.com/tmc/mlx-go-iroh"
)

// TestTicketFromAddrRoundTrips mints a ticket from a raw id and address and
// confirms it decodes back to the same id and IP, the operator-tool path that
// needs no bound endpoint.
func TestTicketFromAddrRoundTrips(t *testing.T) {
	k, err := irohmesh.GenerateNodeKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	id := k.ID()
	addr := netip.MustParseAddrPort("127.0.0.1:9876")

	ticket := irohmesh.TicketFromAddr(id, addr)
	got, err := endpointticket.Decode(ticket)
	if err != nil {
		t.Fatalf("decode ticket: %v", err)
	}
	if got.ID != id {
		t.Fatalf("ticket id = %v, want %v", got.ID, id)
	}
	ips := got.IPAddrs()
	if len(ips) != 1 || ips[0] != addr {
		t.Fatalf("ticket addrs = %v, want [%v]", ips, addr)
	}
}

// TestEndpointTicketMatchesTicketFromAddr confirms Endpoint.Ticket and the
// standalone TicketFromAddr agree, since Ticket delegates to it.
func TestEndpointTicketMatchesTicketFromAddr(t *testing.T) {
	ctx := t.Context()
	k, err := irohmesh.GenerateNodeKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	ep, err := irohmesh.Bind(ctx, irohmesh.Config{
		BindAddr: "127.0.0.1:0",
		Identity: k.Ed25519(),
	})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	defer ep.Close()

	addr := netip.MustParseAddrPort("127.0.0.1:4321")
	if ep.Ticket(addr) != irohmesh.TicketFromAddr(ep.ID(), addr) {
		t.Fatal("Endpoint.Ticket disagrees with TicketFromAddr")
	}
}
