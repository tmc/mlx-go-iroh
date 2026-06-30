package irohmesh_test

import (
	"context"
	"errors"
	"testing"
	"time"

	irohmesh "github.com/tmc/mlx-go-iroh"
)

// TestBindPkarrRegistersLookupAndClosesClean binds a pkarr-enabled endpoint and
// confirms the publisher and resolver are registered on its lookup services (so
// ResolveAddr/ConnectID resolve globally), then that Close tears the publisher
// and publish loop down without error. It does not reach the public relay: it
// asserts the wiring, not a live round trip.
func TestBindPkarrRegistersLookupAndClosesClean(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	k, err := irohmesh.GenerateNodeKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	ep, err := irohmesh.Bind(ctx, irohmesh.Config{
		BindAddr: "127.0.0.1:0",
		Identity: k.Ed25519(),
		Relay:    true,
		Pkarr:    true,
	})
	if err != nil {
		t.Fatalf("bind global: %v", err)
	}

	// Pkarr registers exactly one publisher and one resolver on the lookup
	// services the endpoint owns; gossip/LAN binds leave them empty.
	if got := ep.LookupServices().Len(); got != 2 {
		t.Fatalf("lookup services Len = %d, want 2 (pkarr publisher + resolver)", got)
	}

	if err := ep.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestBindWithoutPkarrHasEmptyLookup confirms the default (gossip/LAN) bind is
// unchanged: no publisher or resolver is registered until discovery adds one.
func TestBindWithoutPkarrHasEmptyLookup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ep, err := irohmesh.Bind(ctx, irohmesh.Config{BindAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	defer ep.Close()

	if !ep.LookupServices().IsEmpty() {
		t.Fatalf("lookup services not empty on a non-pkarr bind: Len = %d", ep.LookupServices().Len())
	}
}

// TestWaitOnlineRequiresPkarr confirms WaitOnline reports ErrInvalid on an
// endpoint bound without pkarr publishing: there is nothing to bring online.
func TestWaitOnlineRequiresPkarr(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ep, err := irohmesh.Bind(ctx, irohmesh.Config{BindAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	defer ep.Close()

	wctx, wcancel := context.WithTimeout(ctx, time.Second)
	defer wcancel()
	if err := ep.WaitOnline(wctx); !errors.Is(err, irohmesh.ErrInvalid) {
		t.Fatalf("WaitOnline on non-pkarr endpoint: err = %v, want ErrInvalid", err)
	}
}

// TestBindPkarrGeneratesIdentityWhenUnset confirms a pkarr bind with no Identity
// or SecretKey still binds: Bind generates a key so the publisher and endpoint
// share one identity, and the endpoint gets a usable EndpointID.
func TestBindPkarrGeneratesIdentityWhenUnset(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ep, err := irohmesh.Bind(ctx, irohmesh.Config{
		BindAddr: "127.0.0.1:0",
		Pkarr:    true,
	})
	if err != nil {
		t.Fatalf("bind global without identity: %v", err)
	}
	defer ep.Close()

	if ep.ID().IsZero() {
		t.Fatal("generated identity yielded a zero EndpointID")
	}
}
